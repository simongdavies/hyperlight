#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Hyperlight Authors.

"""Aggregate existing isolation_bench JSON files. Never launches a program.

Usage: python summarize_bench.py run1.json run2.json > summary.json

Groups retain feature, scenario, source, executable identities, machine,
filesystem, requested controls, runtime inventory, environment and cache
conditions. Warmups, first invocations and ordinary samples stay separate.
VM index is a repeated observation within a condition, not a new condition.
P95 uses the nearest-rank definition. Failed runs contribute no measurements.
Input reports and raw sample references are retained in the output.
"""

import argparse
import copy
import hashlib
import json
import math
import re
import statistics
import sys
from pathlib import Path


SCHEMA = "hyperlight-isolation-bench/v1"


def artifact_identity(program):
    if program is None:
        return None
    return {
        "executable_sha256": program["executable"]["sha256"],
        "runtime_files": sorted(
            (
                {"image_path": entry["image_path"], "sha256": entry["file"]["sha256"]}
                for entry in program["runtime_files"]
            ),
            key=lambda entry: entry["image_path"],
        ),
    }


def condition(report):
    config = report["config"]
    artifacts = report["artifacts"]
    if config.get("measurement", {}).get("kind") == "resident":
        expected = {"per_sandbox": [
            {"vm_index": row["vm_index"], "artifacts": row["artifacts"]}
            for row in report["process_reports"]
        ]}
        if artifacts != expected:
            raise ValueError("Resident artifact inventory is incomplete")
    return {
        "platform": report["platform"],
        "architecture": report["architecture"],
        "build": report["build"],
        "scenario": report["scenario"],
        "policy": report["policy"],
        "trusted_windows_caller_consent": report["trusted_windows_caller_consent"],
        "source_fingerprint_sha256": report["source_fingerprint_sha256"],
        "source_revision": config["source_revision"],
        "machine": config["machine"],
        "filesystem": config["filesystem"],
        "controller_sha256": config["controller_sha256"],
        "guest_sha256": config["guest"]["sha256"],
        "worker": artifact_identity(config["worker"]),
        "sandbox_host": artifact_identity(config["sandbox_host"]),
        "packaged_artifacts": artifacts,
        "os_dependencies": config["os_dependencies"],
        "process_memory_bytes": config["process_memory_bytes"],
        "cpu_quota_us": config["cpu_quota_us"],
        "cpu_period_us": config["cpu_period_us"],
        "linux": config["linux"],
        "samples": config["samples"],
        "warmup": config["warmup"],
        "vm_starts": config["vm_starts"],
        "payload_order": config["payload_bytes"],
        "environment": report["environment"],
        "cache_conditions": report["cache_conditions"],
        "guest_layout": report["guest_layout"],
        "execution": report["execution"],
        "effective_process_controls": effective_controls(report),
        "measurement": config.get("measurement", {"kind": "sequential"}),
        "observer_policy": observer_policy(report),
    }


def observer_policy(report):
    observations = report.get("observations", [])
    if not observations:
        return None
    policies = [{
        "platform": value["platform"], "authority": value["authority"],
        "sampling_interval_ms": value["sampling_interval_ms"],
        "observer_sha256": value["observer_sha256"],
        "windows_adapter_sha256": value.get("windows_adapter_sha256"),
    } for value in observations]
    if any(value != policies[0] for value in policies):
        raise ValueError("Observer authority or sampling policy changed")
    return policies[0]


def positive(value, name, allow_zero=False):
    if type(value) is not int or value < (0 if allow_zero else 1):
        raise ValueError(f"{name} must be a {'nonnegative' if allow_zero else 'positive'} integer")
    return value


def observed_metrics(report):
    mode = report["config"].get("measurement", {"kind": "sequential"})
    if mode["kind"] == "sequential":
        if report.get("observations"):
            raise ValueError("Sequential run has unexpected observer evidence")
        return []
    if mode["kind"] not in ("resident", "recovery"):
        raise ValueError("Unknown measurement mode")
    expected = (["reference", "warm_idle", "active_start", "active_end"]
                if mode["kind"] == "resident" else ["quiescent_fault", "recovered"])
    observations = report["observations"]
    if [item["phase"] for item in observations] != expected:
        raise ValueError("Incomplete observation boundaries")
    policy = observer_policy(report)
    if (not policy["authority"] or policy["sampling_interval_ms"] != 100
            or policy["platform"] != report["platform"]):
        raise ValueError("Missing observer authority or unexpected sampling interval")
    rows = []
    whole_memory = {}

    def add(metric, unit, value, phase, role, vm_index=None):
        if (not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(value)
                or (value < 0 and not metric.startswith("amortized_increment_"))):
            raise ValueError("Invalid observed metric")
        rows.append({"metric": metric, "unit": unit, "value": value, "phase": phase,
                     "role": role, "vm_index": vm_index})

    identity = observations[0]["controller_identity"]
    positive(identity["pid"], "controller PID")
    positive(identity["start_ticks"], "controller identity")
    if identity["pid"] != positive(report["controller_pid"], "report controller PID"):
        raise ValueError("Observer belongs to another benchmark controller")
    identities = {}
    last_window_end = 0
    warm_census = None
    for sequence, observation in enumerate(observations):
        phase = observation["phase"]
        if (observation["status"] != "ok"
                or observation["schema"] != "hyperlight-isolation-observation/v1"
                or observation["sequence"] != sequence
                or observation["controller_identity"] != identity):
            raise ValueError("Invalid observer acknowledgement")
        previous = 0
        first = None
        stable_census = None
        for sample in observation["samples"]:
            stamp = positive(sample["monotonic_ns"], "sample timestamp")
            if stamp <= previous:
                raise ValueError("Unordered memory samples")
            if previous and not 50_000_000 <= stamp - previous <= 150_000_000:
                raise ValueError("Memory sampling gap is outside50..150ms")
            if first is None and stamp <= last_window_end:
                raise ValueError("Memory observation windows overlap or repeat")
            previous = stamp
            if first is None:
                first = stamp
            pids = set()
            totals = {}
            census = {}
            for process in sample["processes"]:
                pid = positive(process["pid"], "process PID")
                positive(process["start_ticks"], "process identity")
                if pid in pids:
                    raise ValueError("Duplicate process memory accounting")
                pids.add(pid)
                key = (process["role"], process["vm_index"])
                signature = (process["start_ticks"], *key)
                if pid in identities and identities[pid] != signature:
                    raise ValueError("Original process identity or ownership changed")
                identities[pid] = signature
                census[pid] = process
                if process["role"] not in ("calling_process", "controller_scope", "sandbox_host", "function_worker"):
                    raise ValueError("Unknown observed process role")
                if process["role"] in ("sandbox_host", "function_worker"):
                    positive(process["vm_index"], "sandbox index", allow_zero=True)
                    if process["vm_index"] >= mode.get("sandboxes", 1):
                        raise ValueError("Observed sandbox index exceeds configured count")
                totals.setdefault(key, {})
                fields = (("private_resident_bytes", "rss_bytes", "pss_bytes")
                          if observation["platform"] == "linux" else
                          ("private_committed_bytes", "working_set_bytes"))
                if observation["platform"] not in ("linux", "windows"):
                    raise ValueError("Unsupported memory semantics")
                for field in fields:
                    value = positive(process[field], field, allow_zero=True)
                    totals[key][field] = totals[key].get(field, 0) + value
            if identity["pid"] not in pids:
                raise ValueError("Memory sample omits the controller")
            signature = frozenset((pid, row["start_ticks"], row["role"], row["vm_index"])
                                  for pid, row in census.items())
            if stable_census is not None and signature != stable_census:
                raise ValueError("Complete process census changed within a stable window")
            stable_census = signature
            caller = census[identity["pid"]]
            if (caller["start_ticks"] != identity["start_ticks"]
                    or caller["role"] != "calling_process" or caller["vm_index"] is not None):
                raise ValueError("Controller identity or attribution changed")
            if phase != "reference":
                process_reports = report["process_reports"]
                if mode["kind"] == "recovery":
                    process_reports = [row for row in process_reports if row["stage"] == "after_fault"]
                if len(process_reports) != mode.get("sandboxes", 1):
                    raise ValueError("Missing native topology inventory")
                expected_roles = {
                    "legacy-local": set(), "calling-vm-local-functions": set(),
                    "calling-vm-separate-functions": {"function_worker"},
                    "separate-vm-local-functions": {"sandbox_host"},
                    "separate-vm-separate-functions": {"sandbox_host", "function_worker"},
                }[report["scenario"]]
                seen_indices = set()
                for inventory in process_reports:
                    index = positive(inventory["vm_index"], "inventory index", True)
                    if index in seen_indices or index >= mode.get("sandboxes", 1):
                        raise ValueError("Duplicate or invalid topology index")
                    seen_indices.add(index)
                    if (len(inventory["processes"]) != len(expected_roles)
                            or {process["role"] for process in inventory["processes"]} != expected_roles):
                        raise ValueError("Reported topology does not match placement")
                    for process in inventory["processes"]:
                        observed = census.get(process["root_process_id"])
                        if observed is None or (observed["role"], observed["vm_index"]) != (process["role"], index):
                            raise ValueError("Memory census omits or misattributes a native root")
            for (role, index), fields in totals.items():
                for field, value in fields.items():
                    add(field, "bytes", value, phase, role, index)
            for field in fields:
                total = sum(values[field] for values in totals.values())
                add(field, "bytes", total, phase, "whole_topology")
                whole_memory.setdefault((phase, field), []).append(total)
            if observation["platform"] == "linux":
                charged = sample["whole_run"]
                if charged["domain"] != policy["authority"]["delegated_cgroup"]:
                    raise ValueError("Whole-run accounting authority changed")
                for field in ("memory_current_bytes", "memory_peak_bytes"):
                    add(field, "charged_bytes", positive(charged[field], field, True), phase, "whole_run")
                positive(charged["cpu_usage_usec"], "CPU counter", True)
                domains = set()
                for domain in sample["role_domains"]:
                    if domain["domain"] in domains:
                        raise ValueError("Duplicate role-domain accounting")
                    domains.add(domain["domain"])
                    for field in ("memory_current_bytes", "memory_peak_bytes", "cpu_usage_usec"):
                        positive(domain[field], field, True)
        if phase in ("reference", "warm_idle", "active_end", "recovered") and not observation["samples"]:
            raise ValueError("Missing required memory window")
        required_span = {"reference": 800_000_000, "warm_idle": 1_800_000_000, "active_end": 4_800_000_000}.get(phase)
        if required_span is not None and previous - first < required_span:
            raise ValueError("Memory observation window is too short")
        minimum_samples = {"reference": 9, "warm_idle": 19, "active_end": 49}.get(phase, 0)
        if len(observation["samples"]) < minimum_samples:
            raise ValueError("Memory observation coverage is incomplete")
        if first is not None:
            last_window_end = previous
        if phase == "warm_idle":
            warm_census = stable_census
        elif phase == "active_end" and stable_census != warm_census:
            raise ValueError("Resident process census changed between idle and active windows")
    if mode["kind"] == "resident":
        count = mode["sandboxes"]
        resident = report["resident"]
        if count not in (1, 2, 4, 8) or resident["sandbox_count"] != count:
            raise ValueError("Resident count mismatch")
        counters = resident["per_sandbox"]
        if len(counters) != count or sorted(row["vm_index"] for row in counters) != list(range(count)):
            raise ValueError("Incomplete per-sandbox counters")
        duration = positive(resident["window_ns"], "resident window")
        if duration < 5_000_000_000:
            raise ValueError("Resident workload window is too short")
        calls = 0
        for row in counters:
            total = positive(row["completed_calls"], "completed calls")
            positive(row["elapsed_ns"], "per-sandbox elapsed time")
            calls += total
            add("validated_throughput", "calls/second", total * 1_000_000_000 / duration,
                "active", "sandbox", row["vm_index"])
        add("validated_throughput", "calls/second", calls * 1_000_000_000 / duration, "active", "whole_topology")
        for (phase, field), values in whole_memory.items():
            if phase == "warm_idle":
                reference = statistics.median(whole_memory[("reference", field)])
                increment = (statistics.median(values) - reference) / count
                add(f"amortized_increment_{field}", "bytes/sandbox", increment, "warm_idle", "whole_topology")
    else:
        recovery = report["recovery"]
        if (recovery["faults"] != 1 or recovery["in_flight_at_fault"] is not False
                or recovery["validated_result"] != 42
                or recovery["guest_state_before_fault"] != recovery["guest_state_before_mutation"] + 7
                or recovery["guest_state_after_recovery"] != recovery["guest_state_before_fault"]):
            raise ValueError("Recovery did not preserve actual mutated guest state")
        before = observations[0]["fault"]
        after = observations[1]["fault"]
        if before["original_identity"] != after["original_identity"] or before["fault_requested_ns"] != after["fault_requested_ns"]:
            raise ValueError("Fault identity changed")
        if after["original_root_exited"] is not True:
            raise ValueError("Original worker root exit not observed")
        old = [row for row in report["process_reports"] if row["stage"] == "before_fault"]
        new = [row for row in report["process_reports"] if row["stage"] == "after_fault"]
        if len(old) != 1 or len(new) != 1:
            raise ValueError("Missing recovery topology inventories")
        old_policy = effective_controls({**report, "process_reports": old})
        new_policy = effective_controls({**report, "process_reports": new})
        if old_policy != new_policy:
            raise ValueError("Recovered program or effective controls changed")
        original = [process for process in old[0]["processes"] if process["role"] == "function_worker"]
        replacement = [process for process in new[0]["processes"] if process["role"] == "function_worker"]
        if (len(original) != 1 or len(replacement) != 1
                or original[0]["root_process_id"] != before["original_identity"]["pid"]
                or original[0]["root_process_id"] == replacement[0]["root_process_id"]):
            raise ValueError("Fault does not identify the replaced worker")
        for process in old[0]["processes"]:
            if process["role"] == "sandbox_host":
                candidates = [item for item in new[0]["processes"] if item["role"] == "sandbox_host"]
                if len(candidates) != 1 or candidates[0]["root_process_id"] != process["root_process_id"]:
                    raise ValueError("Unfaulted sandbox host changed")
        start = positive(after["fault_requested_ns"], "fault timestamp")
        end = positive(after["validated_boundary_ns"], "recovery boundary")
        if end < start or after["fault_to_validated_boundary_ns"] != end - start:
            raise ValueError("Invalid recovery/cleanup timing evidence")
        add("fault_to_validated_boundary", "ns", end - start, "recovery", "function_worker", 0)
        if observations[1]["platform"] == "linux":
            last = positive(after["last_populated_ns"], "last populated timestamp")
            empty = positive(after["first_empty_or_removed_ns"], "empty observation")
            if not start <= last <= empty <= end:
                raise ValueError("Invalid retired-domain observation bounds")
            add("retired_domain_empty_upper_bound", "ns", empty - start, "recovery", "function_worker", 0)
    return rows


def effective_controls(report):
    """Retain enforcement differences without grouping by transient process IDs."""
    definitions = {}
    for observation in report["process_reports"]:
        for process in observation["processes"]:
            controls = copy.deepcopy(process["controls"])
            if report["platform"] == "windows":
                for control in controls:
                    result = control["result"]
                    if result["status"] == "applied" and "mechanism" in result:
                        result["mechanism"] = re.sub(
                            r"\bAppContainer [^;\s]+ SID S-1-15-2-(?:\d+-){6}\d+(?=;)",
                            "AppContainer <identity> SID <identity>",
                            result["mechanism"],
                        )
            definition = {
                "role": process["role"],
                "name": process["name"],
                "program_manifest_sha256": process["program_manifest_sha256"],
                "controls": controls,
            }
            key = json.dumps(definition, sort_keys=True, separators=(",", ":"))
            definitions[key] = definition
    return [definitions[key] for key in sorted(definitions)]


def validate_sample(sample):
    if sample.get("unit") != "ns":
        raise ValueError("Only nanosecond durations are supported")
    duration = sample.get("duration")
    if type(duration) is not int or duration < 0:
        raise ValueError("duration must be a nonnegative integer")
    for name in ("vm_index", "sample_index"):
        if type(sample.get(name)) is not int or sample[name] < 0:
            raise ValueError(f"{name} must be a nonnegative integer")
    for name in ("metric", "phase"):
        if not isinstance(sample.get(name), str) or not sample[name]:
            raise ValueError(f"{name} must be a nonempty string")
    payload = sample.get("payload_bytes")
    if payload is not None and (type(payload) is not int or payload < 0):
        raise ValueError("payload_bytes must be null or a nonnegative integer")


def aggregate(paths):
    inputs = []
    groups = {}
    rejected = []
    seen = set()
    observed_groups = {}
    for supplied_path in paths:
        path = Path(supplied_path).resolve(strict=True)
        if path in seen:
            raise ValueError(f"Duplicate input path: {path}")
        seen.add(path)
        data = path.read_bytes()
        report = json.loads(data)
        if report.get("schema") != SCHEMA:
            raise ValueError(f"Unsupported schema: {path}")
        input_index = len(inputs)
        inputs.append(
            {
                "path": str(path),
                "sha256": hashlib.sha256(data).hexdigest(),
                "report": report,
            }
        )
        if report.get("status") == "error":
            rejected.append(
                {"input_index": input_index, "reason": report.get("error", "Failed run")}
            )
            continue
        if report.get("status") != "ok" or report.get("provenance_verified") is not True:
            raise ValueError(f"Run is not successful with verified provenance: {path}")
        comparable = condition(report)
        for offset, observation in enumerate(observed_metrics(report)):
            definition = {"condition": comparable, **{key: observation[key] for key in (
                "metric", "unit", "phase", "role", "vm_index"
            )}}
            key = json.dumps(definition, sort_keys=True, separators=(",", ":"))
            group = observed_groups.setdefault(key, {**definition, "raw_samples": []})
            group["raw_samples"].append({"input_index": input_index, "observation_offset": offset,
                                         "value": observation["value"]})
        for sample_index, sample in enumerate(report["samples"]):
            validate_sample(sample)
            definition = {
                "condition": comparable,
                "metric": sample["metric"],
                "phase": sample["phase"],
                "payload_bytes": sample["payload_bytes"],
                "unit": sample["unit"],
            }
            key = json.dumps(definition, sort_keys=True, separators=(",", ":"))
            group = groups.setdefault(key, {**definition, "raw_samples": []})
            group["raw_samples"].append(
                {
                    "input_index": input_index,
                    "sample_offset": sample_index,
                    "sample": sample,
                }
            )
    summaries = []
    for key in sorted(groups):
        group = groups[key]
        durations = sorted(entry["sample"]["duration"] for entry in group["raw_samples"])
        count = len(durations)
        group["statistics"] = {
            "count": count,
            "min": durations[0],
            "median": statistics.median(durations),
            "p95": durations[math.ceil(count * 0.95) - 1],
            "max": durations[-1],
        }
        summaries.append(group)
    observed_summaries = []
    for key in sorted(observed_groups):
        group = observed_groups[key]
        values = sorted(row["value"] for row in group["raw_samples"])
        group["statistics"] = {
            "count": len(values), "min": values[0], "median": statistics.median(values),
            "p95": values[math.ceil(0.95 * len(values)) - 1], "max": values[-1],
        }
        observed_summaries.append(group)
    return {
        "schema": "hyperlight-isolation-bench-summary/v1",
        "percentile_definition": "nearest rank, ceil(0.95 * count)",
        "measurement_note": "Warmup, first-use and sample phases are separate groups",
        "inputs": inputs,
        "failed_runs": rejected,
        "groups": summaries,
        "observed_groups": observed_summaries,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", help="Existing raw benchmark JSON files")
    args = parser.parse_args()
    try:
        summary = aggregate(args.files)
        json.dump(summary, sys.stdout, indent=2, allow_nan=False)
        sys.stdout.write("\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Cannot aggregate benchmark input: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
