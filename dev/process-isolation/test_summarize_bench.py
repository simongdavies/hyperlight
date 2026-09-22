#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Hyperlight Authors.

import copy
import json
import tempfile
import unittest
from pathlib import Path

from summarize_bench import SCHEMA, aggregate, condition, observed_metrics, validate_sample


def report():
    config = dict.fromkeys(
        (
            "source_revision", "machine", "filesystem", "controller_sha256",
            "worker", "sandbox_host", "os_dependencies", "process_memory_bytes",
            "cpu_quota_us", "cpu_period_us", "linux", "samples", "warmup",
            "vm_starts", "payload_bytes",
        )
    )
    config["guest"] = {"sha256": "guest"}
    result = dict.fromkeys(
        (
            "platform", "architecture", "build", "scenario", "policy",
            "trusted_windows_caller_consent", "source_fingerprint_sha256",
            "artifacts", "environment", "cache_conditions", "guest_layout",
            "execution",
        )
    )
    result.update(
        schema=SCHEMA, status="ok", provenance_verified=True, config=config,
        samples=[], process_reports=[],
    )
    return result


def sample(duration, phase="sample"):
    return {
        "metric": "guest_RoundTripHostString", "phase": phase, "payload_bytes": 32,
        "unit": "ns", "duration": duration, "vm_index": 0, "sample_index": 0,
    }


def windows_process(suffix, sid):
    baseline = (
        f"AppContainer Hyperlight.{suffix} SID {sid}; empty capability allowlist; "
        "Mesh requires exact-SID IPC authorization; no inherited environment; "
        "null stdio; scoped read/execute image ACL; Windows AppContainer OS-resource baseline"
    )
    return {
        "role": "function_worker", "name": "bench-functions",
        "program_manifest_sha256": "manifest", "root_process_id": 100,
        "controls": [
            {"requested": {"kind": "memory_limit", "bytes": 268435456}, "required": True,
             "result": {"status": "applied", "effective": {"kind": "memory_limit", "bytes": 268435456},
                        "mechanism": "JOB_OBJECT_LIMIT_JOB_MEMORY: 268435456 committed virtual-memory bytes across the job; not RSS; " + baseline}},
            {"requested": {"kind": "deny_network"}, "required": True,
             "result": {"status": "applied", "effective": {"kind": "deny_network"},
                        "mechanism": baseline + "; no network capabilities or loopback exemption"}},
            {"requested": {"kind": "deny_child_processes"}, "required": True,
             "result": {"status": "applied", "effective": {"kind": "deny_child_processes"},
                        "mechanism": baseline + "; PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY=RESTRICTED; job active-process limit=1"}},
        ],
    }


def observed_report(kind="resident", count=1, platform="linux"):
    raw = report()
    raw["platform"] = platform
    raw["controller_pid"] = 10
    raw["scenario"] = "legacy-local" if kind == "resident" else "calling-vm-separate-functions"
    raw["process_reports"] = [{"vm_index": index, "stage": "resident", "processes": [],
                              "artifacts": {"worker_manifest_sha256": None, "sandbox_manifest_sha256": None}}
                             for index in range(count)]
    raw["config"]["measurement"] = {"kind": kind, **({"sandboxes": count} if kind == "resident" else {})}
    phases = ["reference", "warm_idle", "active_start", "active_end"] if kind == "resident" else ["quiescent_fault", "recovered"]
    raw["observations"] = []
    for sequence, phase in enumerate(phases):
        process = {"pid": 10, "start_ticks": 1, "role": "calling_process", "vm_index": None,
                   "private_resident_bytes": 100, "rss_bytes": 200, "pss_bytes": 150,
                   "private_committed_bytes": 300, "working_set_bytes": 400}
        length = {"reference": 10, "warm_idle": 20, "active_start": 0,
                  "active_end": 51, "quiescent_fault": 0, "recovered": 1}[phase]
        raw["observations"].append({
            "schema": "hyperlight-isolation-observation/v1", "status": "ok",
            "phase": phase, "sequence": sequence, "platform": platform,
            "controller_identity": {"pid": 10, "start_ticks": 1},
            "authority": {"delegated_cgroup": "/run-one"} if platform == "linux" else {"windows_run": "run-one"},
            "sampling_interval_ms": 100, "observer_sha256": "observer",
            "samples": [{
                "monotonic_ns": 1 + sequence * 10_000_000_000 + index * 100_000_000,
                "processes": [copy.deepcopy(process)],
                "whole_run": {"domain": "/run-one", "memory_current_bytes": 500,
                              "memory_peak_bytes": 700, "cpu_usage_usec": 100},
                "role_domains": [],
            } for index in range(length)],
        })
    if kind == "resident":
        raw["artifacts"] = {"per_sandbox": [
            {"vm_index": row["vm_index"], "artifacts": copy.deepcopy(row["artifacts"])}
            for row in raw["process_reports"]
        ]}
        raw["resident"] = {"sandbox_count": count, "window_ns": 5_000_000_000,
                           "per_sandbox": [{"vm_index": index, "completed_calls": 100,
                                            "elapsed_ns": 5_000_000_000} for index in range(count)]}
    else:
        before_worker = windows_process("test", "S-1-15-2-1-2-3-4-5-6-7")
        before_worker["root_process_id"] = 11
        after_worker = copy.deepcopy(before_worker)
        after_worker["root_process_id"] = 12
        raw["process_reports"] = [
            {"vm_index": 0, "stage": "before_fault", "processes": [before_worker]},
            {"vm_index": 0, "stage": "after_fault", "processes": [after_worker]},
        ]
        for sample in raw["observations"][-1]["samples"]:
            worker = copy.deepcopy(sample["processes"][0])
            worker.update(pid=12, start_ticks=3, role="function_worker", vm_index=0)
            sample["processes"].append(worker)
        raw["recovery"] = {"faults": 1, "in_flight_at_fault": False, "validated_result": 42,
                           "guest_state_before_mutation": 5, "guest_state_before_fault": 12,
                           "guest_state_after_recovery": 12}
        fault = {"original_identity": {"pid": 11, "start_ticks": 2},
                 "fault_requested_ns": 1, "last_populated_ns": 2,
                 "first_empty_or_removed_ns": 3, "validated_boundary_ns": 4,
                 "fault_to_validated_boundary_ns": 3, "original_root_exited": True}
        for observation in raw["observations"]:
            observation["fault"] = copy.deepcopy(fault)
    return raw


class AggregationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.paths = []

    def write(self, value):
        path = Path(self.directory.name) / f"{len(self.paths)}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        self.paths.append(path)
        return path

    def test_resident_memory_and_throughput_are_distinct_metrics(self):
        self.write(observed_report(count=2))
        result = aggregate(self.paths)
        groups = result["observed_groups"]
        throughput = next(row for row in groups if row["metric"] == "validated_throughput" and row["role"] == "whole_topology")
        self.assertEqual(throughput["statistics"]["median"], 40)
        self.assertTrue(any(row["unit"] == "charged_bytes" for row in groups))
        self.assertTrue(any(row["metric"] == "private_resident_bytes" and row["unit"] == "bytes" for row in groups))
        self.assertEqual(result["inputs"][0]["report"], observed_report(count=2))

    def test_observer_authority_counts_and_windows_semantics_separate(self):
        self.write(observed_report())
        changed = observed_report(count=2)
        self.write(changed)
        changed = observed_report()
        for observation in changed["observations"]:
            observation["authority"]["delegated_cgroup"] = "/run-two"
            for sample in observation["samples"]:
                sample["whole_run"]["domain"] = "/run-two"
        self.write(changed)
        self.write(observed_report(platform="windows"))
        groups = aggregate(self.paths)["observed_groups"]
        throughput = [row for row in groups if row["metric"] == "validated_throughput" and row["role"] == "whole_topology"]
        self.assertEqual(len(throughput), 4)
        self.assertTrue(any(row["metric"] == "private_committed_bytes" for row in groups))
        self.assertFalse(any(row["metric"] == "private_resident_bytes" and row["condition"]["platform"] == "windows" for row in groups))

    def test_duplicate_pid_and_missing_memory_are_rejected(self):
        raw = observed_report()
        values = raw["observations"][0]["samples"][0]["processes"]
        values.append(copy.deepcopy(values[0]))
        with self.assertRaises(ValueError):
            observed_metrics(raw)
        values.pop()
        del values[0]["private_resident_bytes"]
        with self.assertRaises(KeyError):
            observed_metrics(raw)

    def test_incomplete_residency_or_observation_window_is_rejected(self):
        raw = observed_report(count=2)
        raw["resident"]["per_sandbox"].pop()
        with self.assertRaises(ValueError):
            observed_metrics(raw)
        raw = observed_report()
        raw["observations"][1]["samples"] = raw["observations"][1]["samples"][:1]
        with self.assertRaises(ValueError):
            observed_metrics(raw)

    def test_recovery_requires_mutation_readback_and_cleanup_evidence(self):
        raw = observed_report(kind="recovery")
        rows = observed_metrics(raw)
        self.assertTrue(any(row["metric"] == "fault_to_validated_boundary" and row["value"] == 3 for row in rows))
        raw["recovery"]["guest_state_after_recovery"] = 5
        with self.assertRaises(ValueError):
            observed_metrics(raw)
        raw = observed_report(kind="recovery")
        raw["observations"][1]["fault"]["first_empty_or_removed_ns"] = 10
        with self.assertRaises(ValueError):
            observed_metrics(raw)
        raw = observed_report(kind="recovery", platform="windows")
        self.assertFalse(any(row["metric"] == "retired_domain_empty_upper_bound" for row in observed_metrics(raw)))

    def test_failed_observed_run_contributes_no_metrics(self):
        raw = observed_report()
        raw["status"] = "error"
        raw["observations"] = []
        self.write(raw)
        result = aggregate(self.paths)
        self.assertEqual(result["observed_groups"], [])
        self.assertEqual(len(result["failed_runs"]), 1)

    def test_observation_rejects_identity_role_and_platform_drift(self):
        for field, value in (("start_ticks", 3), ("role", "function_worker"), ("vm_index", 0)):
            raw = observed_report()
            raw["observations"][1]["samples"][0]["processes"][0][field] = value
            with self.assertRaises(ValueError):
                observed_metrics(raw)
        raw = observed_report()
        raw["platform"] = "windows"
        with self.assertRaises(ValueError):
            observed_metrics(raw)
        raw = observed_report(kind="recovery")
        raw["observations"][-1]["samples"][0]["processes"].pop()
        with self.assertRaises(ValueError):
            observed_metrics(raw)

    def test_recovery_rejects_wrong_fault_and_changed_policy(self):
        raw = observed_report(kind="recovery")
        raw["process_reports"][1]["processes"][0]["program_manifest_sha256"] = "other"
        with self.assertRaises(ValueError):
            observed_metrics(raw)
        raw = observed_report(kind="recovery")
        for observation in raw["observations"]:
            observation["fault"]["original_identity"]["pid"] = 99
        with self.assertRaises(ValueError):
            observed_metrics(raw)

    def test_amortized_shared_memory_retains_negative_noise(self):
        raw = observed_report(count=2)
        for sample in raw["observations"][1]["samples"]:
            sample["processes"][0]["private_resident_bytes"] = 80
        rows = observed_metrics(raw)
        increment = next(row for row in rows if row["metric"] == "amortized_increment_private_resident_bytes")
        self.assertEqual(increment["value"], -10)

    def test_resident_producer_shape_requires_per_sandbox_artifacts(self):
        raw = observed_report(count=2)
        self.assertEqual(condition(raw)["packaged_artifacts"], raw["artifacts"])
        raw["artifacts"]["per_sandbox"].pop()
        with self.assertRaises(ValueError):
            condition(raw)
        del raw["artifacts"]
        with self.assertRaises(KeyError):
            condition(raw)
        for raw in (report(), observed_report(kind="recovery")):
            del raw["artifacts"]
            with self.assertRaises(KeyError):
                condition(raw)

    def test_sparse_interior_samples_and_reused_windows_are_rejected(self):
        raw = observed_report()
        for observation in raw["observations"]:
            if observation["samples"]:
                observation["samples"] = [observation["samples"][0], observation["samples"][-1]]
        with self.assertRaises(ValueError):
            observed_metrics(raw)
        raw = observed_report()
        raw["observations"][-1]["samples"].pop(20)
        with self.assertRaises(ValueError):
            observed_metrics(raw)
        raw = observed_report()
        for sample in raw["observations"][1]["samples"]:
            sample["monotonic_ns"] -= 10_000_000_000
        with self.assertRaises(ValueError):
            observed_metrics(raw)

    def test_stable_windows_require_complete_descendant_census(self):
        for remove_index in (0, 1, -1):
            raw = observed_report()
            for observation in raw["observations"]:
                for sample in observation["samples"]:
                    child = copy.deepcopy(sample["processes"][0])
                    child.update(pid=20, role="controller_scope")
                    sample["processes"].append(child)
            raw["observations"][1]["samples"][remove_index]["processes"].pop()
            with self.assertRaises(ValueError):
                observed_metrics(raw)

    def test_observer_must_match_enclosing_controller(self):
        raw = observed_report()
        raw["controller_pid"] = 200
        with self.assertRaises(ValueError):
            observed_metrics(raw)

    def test_nearest_rank_and_phases_keep_raw_references(self):
        raw = report()
        raw["samples"] = [sample(value) for value in range(1, 21)]
        raw["samples"].extend([sample(999, "warmup"), sample(888, "first_invocation")])
        self.write(raw)
        result = aggregate(self.paths)
        self.assertEqual(len(result["groups"]), 3)
        group = next(g for g in result["groups"] if g["phase"] == "sample")
        self.assertEqual(
            group["statistics"],
            {"count": 20, "min": 1, "median": 10.5, "p95": 19, "max": 20},
        )
        self.assertEqual(group["raw_samples"][19]["sample_offset"], 19)
        self.assertEqual(result["inputs"][0]["report"], raw)
        self.assertEqual(len(result["inputs"][0]["sha256"]), 64)

    def test_policy_binary_and_effective_controls_are_distinct(self):
        raw = report()
        raw["samples"] = [sample(1)]
        self.write(raw)
        for key in ("policy", "source_fingerprint_sha256"):
            changed = copy.deepcopy(raw)
            changed[key] = "different"
            self.write(changed)
        changed = copy.deepcopy(raw)
        changed["config"]["controller_sha256"] = "different"
        self.write(changed)
        changed = copy.deepcopy(raw)
        changed["process_reports"] = [{"processes": [{
            "role": "worker", "name": "functions",
            "program_manifest_sha256": "manifest",
            "controls": [{"result": {"status": "not_applied"}}],
        }]}]
        self.write(changed)
        self.assertEqual(len(aggregate(self.paths)["groups"]), 5)

    def test_process_ids_do_not_split_equivalent_conditions(self):
        raw = report()
        raw["samples"] = [sample(1)]
        raw["process_reports"] = [{"processes": [{
            "role": "worker", "name": "functions",
            "program_manifest_sha256": "manifest", "controls": [],
            "root_process_id": 100,
        }]}]
        self.write(raw)
        raw["process_reports"][0]["processes"][0]["root_process_id"] = 200
        self.write(raw)
        groups = aggregate(self.paths)["groups"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["statistics"]["count"], 2)

    def test_appcontainer_identities_do_not_split_equivalent_conditions(self):
        raw = report()
        raw.update(platform="windows", samples=[sample(1)])
        first = windows_process("one", "S-1-15-2-1-2-3-4-5-6-7")
        second = windows_process("two", "S-1-15-2-11-12-13-14-15-16-17")
        raw["process_reports"] = [{"processes": [first]}]
        original = copy.deepcopy(raw)
        self.write(raw)
        raw["process_reports"].append({"processes": [second]})
        self.write(raw)
        result = aggregate(self.paths)
        self.assertEqual(len(result["groups"]), 1)
        self.assertEqual(result["groups"][0]["statistics"]["count"], 2)
        self.assertEqual(len(result["groups"][0]["condition"]["effective_process_controls"]), 1)
        self.assertEqual(result["inputs"][0]["report"], original)
        self.assertEqual(result["inputs"][1]["report"], raw)

    def test_identity_normalization_preserves_policy_and_mechanism_differences(self):
        raw = report()
        raw.update(platform="windows", samples=[sample(1)])
        raw["process_reports"] = [{"processes": [
            windows_process("one", "S-1-15-2-1-2-3-4-5-6-7")
        ]}]
        self.write(raw)
        for change in ("required", "effective", "mechanism", "not_applied", "reason"):
            changed = copy.deepcopy(raw)
            controls = changed["process_reports"][0]["processes"][0]["controls"]
            if change == "required":
                controls[2]["required"] = False
            elif change == "effective":
                controls[0]["result"]["effective"]["bytes"] = 134217728
            elif change == "mechanism":
                controls[1]["result"]["mechanism"] += "; extra capability"
            else:
                controls[2]["result"] = {"status": "not_applied", "reason": change}
            self.write(changed)
        self.assertEqual(len(aggregate(self.paths)["groups"]), 6)

    def test_failed_run_contributes_no_samples(self):
        raw = report()
        raw.update(status="error", error="unavailable", samples=[sample(1)])
        self.write(raw)
        result = aggregate(self.paths)
        self.assertEqual(result["groups"], [])
        self.assertEqual(result["failed_runs"], [
            {"input_index": 0, "reason": "unavailable"}
        ])

    def test_duplicate_and_unverified_input_are_rejected(self):
        path = self.write(report())
        with self.assertRaisesRegex(ValueError, "Duplicate input"):
            aggregate([path, path])
        raw = report()
        raw["provenance_verified"] = False
        with self.assertRaisesRegex(ValueError, "verified provenance"):
            aggregate([self.write(raw)])

    def test_invalid_samples_are_rejected(self):
        for name, value in (
            ("duration", -1), ("duration", True), ("duration", 1.5),
            ("unit", "ms"), ("vm_index", -1), ("sample_index", None),
            ("metric", ""), ("phase", None), ("payload_bytes", -1),
        ):
            with self.subTest(name=name, value=value):
                invalid = sample(1)
                invalid[name] = value
                with self.assertRaises(ValueError):
                    validate_sample(invalid)


if __name__ == "__main__":
    unittest.main()
