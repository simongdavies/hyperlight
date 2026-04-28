/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! Guest-side sleep using the LAPIC one-shot timer.
//!
//! When `hw-interrupts` is enabled, the hypervisor provides an emulated
//! Local APIC (LAPIC). This module programs the LAPIC timer in one-shot
//! mode, halts the vCPU with `HLT`, and resumes when the timer fires.
//!
//! # Efficiency
//!
//! During `HLT` the host thread is descheduled by the kernel — zero CPU
//! consumption, zero VM exits. The LAPIC timer countdown and interrupt
//! delivery are handled entirely inside the hypervisor (KVM in-kernel
//! LAPIC / WHP LAPIC emulation).
//!
//! # Requirements
//!
//! - `hw-interrupts` feature (LAPIC emulation)
//! - `enable_guest_clock` feature (pvclock for TSC calibration)
//! - x86_64 only
//! - [`init()`] must be called once during guest init (maps the APIC
//!   MMIO page and installs the timer ISR)
//!
//! # Cancellation
//!
//! The host's `kill()` mechanism kicks the vCPU out of `HLT` via signal
//! (KVM) or `WHvCancelRunVirtualProcessor` (WHP). A cancelled sleep
//! returns `SleepError::Interrupted`.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use hyperlight_common::vmem::{BasicMapping, MappingKind, PAGE_SIZE};
use hyperlight_guest::time;

/// APIC MMIO base address (standard x86).
const APIC_BASE_ADDR: u64 = 0xFEE00000;
/// APIC register: Spurious Interrupt Vector Register.
const APIC_SVR: *mut u32 = (APIC_BASE_ADDR + 0x0F0) as *mut u32;
/// APIC register: LVT Timer.
const APIC_LVT_TIMER: *mut u32 = (APIC_BASE_ADDR + 0x320) as *mut u32;
/// APIC register: Timer Initial Count.
const APIC_TIMER_ICR: *mut u32 = (APIC_BASE_ADDR + 0x380) as *mut u32;
/// APIC register: Timer Current Count (read-only).
const APIC_TIMER_CCR: *mut u32 = (APIC_BASE_ADDR + 0x390) as *mut u32;
/// APIC register: Timer Divide Configuration.
const APIC_TIMER_DCR: *mut u32 = (APIC_BASE_ADDR + 0x3E0) as *mut u32;

/// Timer interrupt vector — matches the existing hw-interrupts convention.
const TIMER_VECTOR: u32 = 0x20;
/// APIC timer divide-by-1 configuration value.
const APIC_TIMER_DIVIDE_BY_1: u32 = 0b1011;
/// LVT Timer: one-shot mode (bits 17:18 = 00), not masked, vector 0x20.
const LVT_ONESHOT: u32 = TIMER_VECTOR;
/// LVT Timer: masked (bit 16 set) — disables timer delivery.
const LVT_MASKED: u32 = 0x0001_0000 | TIMER_VECTOR;
/// Maximum sleep duration: 60 seconds (defense-in-depth).
const MAX_SLEEP_NS: u64 = 60_000_000_000;
/// Calibration measurement period: ~1ms worth of APIC ticks.
const CALIBRATION_TICKS: u32 = 0x00FF_FFFF;

/// Flag set by the timer ISR to indicate the interrupt fired.
static TIMER_FIRED: AtomicU32 = AtomicU32::new(0);
/// Whether [`init()`] has been called.
static INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Cached APIC timer ticks per nanosecond, fixed-point 32.32.
/// Computed once during [`init()`] via runtime calibration.
/// Value = (ticks_per_ns * 2^32), so actual ticks = (ns * TICKS_PER_NS) >> 32.
static TICKS_PER_NS_FP32: AtomicU64 = AtomicU64::new(0);

// Timer ISR: sets the TIMER_FIRED flag, writes LAPIC EOI, returns.
// Uses r11 for the EOI address because 0xFEE000B0 has bit 31 set
// and a 32-bit immediate in 64-bit mode would sign-extend incorrectly.
core::arch::global_asm!(
    ".globl _hl_sleep_timer_isr",
    "_hl_sleep_timer_isr:",
    "push rax",
    "push r11",
    "lock inc dword ptr [rip + {flag}]",
    "xor eax, eax",
    "mov r11, 0xFEE000B0",
    "mov dword ptr [r11], eax",
    "pop r11",
    "pop rax",
    "iretq",
    flag = sym TIMER_FIRED,
);

unsafe extern "C" {
    fn _hl_sleep_timer_isr();
}

/// Errors from the sleep API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepError {
    /// Sleep infrastructure not initialised (call [`init()`] first).
    NotInitialized,
    /// Paravirtualized clock not available (host built without
    /// `enable_guest_clock`).
    ClockUnavailable,
    /// Could not convert duration to TSC ticks (calibration data missing
    /// or zero).
    CalibrationFailed,
    /// Sleep was interrupted by host cancellation before the deadline.
    Interrupted,
}

impl core::fmt::Display for SleepError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("sleep not initialised"),
            Self::ClockUnavailable => f.write_str("guest clock unavailable"),
            Self::CalibrationFailed => f.write_str("TSC calibration failed"),
            Self::Interrupted => f.write_str("sleep interrupted by host"),
        }
    }
}

/// IDT pointer structure for SIDT/LIDT.
#[repr(C, packed)]
struct IdtPtr {
    limit: u16,
    base: u64,
}

/// Initialise the sleep infrastructure. Call once during guest init, and
/// again after snapshot restore (the APIC MMIO mapping lives in scratch
/// pages that are not included in snapshots).
///
/// This:
/// 1. Maps the APIC MMIO page at `0xFEE00000` into the guest's page tables
///    (KVM's in-kernel LAPIC intercepts the MMIO — no real memory needed).
/// 2. Enables the LAPIC via the Spurious Vector Register.
/// 3. Installs a minimal timer ISR at IDT vector 0x20.
///
/// Fully idempotent — safe to call multiple times.
///
/// # Safety
///
/// Must not be called concurrently with other page table operations.
pub unsafe fn init() {
    // Always re-map and re-install — the APIC MMIO page table entry
    // lives in dynamically allocated scratch pages that are NOT
    // included in snapshots. After restore the mapping is gone even
    // though INITIALIZED is still true in the snapshotted BSS.

    // 1. Map the APIC MMIO page.
    unsafe {
        crate::paging::map_region(
            APIC_BASE_ADDR,
            APIC_BASE_ADDR as *mut u8,
            PAGE_SIZE as u64,
            MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        );
        crate::paging::barrier::first_valid_same_ctx();
    }

    // 2. Enable the LAPIC (SVR bit 8 = enable, vector 0xFF for spurious).
    unsafe {
        core::ptr::write_volatile(APIC_SVR, 0x1FF);
    }

    // 3. Install ISR at IDT vector 0x20.
    let handler_addr = _hl_sleep_timer_isr as *const () as u64;
    let mut idtr = IdtPtr { limit: 0, base: 0 };
    unsafe {
        core::arch::asm!(
            "sidt [{}]",
            in(reg) &mut idtr as *mut IdtPtr,
            options(nostack, preserves_flags)
        );
    }
    let entry_ptr = (idtr.base as usize + TIMER_VECTOR as usize * 16) as *mut u8;
    unsafe {
        // 16-byte IDT entry: interrupt gate, present, DPL=0, CS=0x08
        core::ptr::write_volatile(entry_ptr as *mut u16, handler_addr as u16);
        core::ptr::write_volatile(entry_ptr.add(2) as *mut u16, 0x08);
        core::ptr::write_volatile(entry_ptr.add(4), 0);
        core::ptr::write_volatile(entry_ptr.add(5), 0x8E);
        core::ptr::write_volatile(entry_ptr.add(6) as *mut u16, (handler_addr >> 16) as u16);
        core::ptr::write_volatile(entry_ptr.add(8) as *mut u32, (handler_addr >> 32) as u32);
        core::ptr::write_volatile(entry_ptr.add(12) as *mut u32, 0);
    }

    core::sync::atomic::fence(Ordering::SeqCst);

    // 4. Calibrate APIC timer tick rate against pvclock. This spins
    //    for a short period (~1ms) to measure the bus clock ratio.
    if time::is_available() {
        calibrate_apic_timer();
    }

    INITIALIZED.store(true, Ordering::Release);
}

/// Arm the LAPIC one-shot timer and halt the vCPU until the interrupt
/// fires or the host cancels execution.
///
/// Uses APIC counter mode (not TSC-Deadline) for maximum compatibility.
/// The tick count is calibrated at [`init()`] time.
#[inline]
unsafe fn arm_and_halt(ticks: u32) {
    TIMER_FIRED.store(0, Ordering::SeqCst);

    unsafe {
        // Divide-by-1.
        core::ptr::write_volatile(APIC_TIMER_DCR, APIC_TIMER_DIVIDE_BY_1);
        // One-shot mode, not masked, vector 0x20.
        core::ptr::write_volatile(APIC_LVT_TIMER, LVT_ONESHOT);
        // Write initial count — starts countdown immediately.
        core::ptr::write_volatile(APIC_TIMER_ICR, ticks);
        // sti; hlt is atomic on x86: the interrupt is guaranteed to
        // be delivered after sti but the CPU enters HLT before any
        // handler can run.
        core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack));
    }
}

/// Convert nanoseconds to APIC timer ticks using the cached calibration.
#[inline]
fn ns_to_apic_ticks(ns: u64) -> u64 {
    let fp32 = TICKS_PER_NS_FP32.load(Ordering::Relaxed);
    ((ns as u128 * fp32 as u128) >> 32) as u64
}

/// Calibrate the APIC timer by measuring how many ticks elapse per
/// nanosecond. Arms the APIC timer with a known count and measures
/// the elapsed pvclock nanoseconds. The LVT is masked during
/// calibration so no interrupt fires.
fn calibrate_apic_timer() {
    // Mask the LVT timer so the countdown doesn't fire an interrupt.
    unsafe {
        core::ptr::write_volatile(APIC_TIMER_DCR, APIC_TIMER_DIVIDE_BY_1);
        core::ptr::write_volatile(APIC_LVT_TIMER, LVT_MASKED);
    }

    let t0 = time::monotonic_time_ns().unwrap_or(0);

    // Start a countdown from CALIBRATION_TICKS.
    unsafe { core::ptr::write_volatile(APIC_TIMER_ICR, CALIBRATION_TICKS) };

    // Spin until at least half the ticks have elapsed, giving us a
    // reasonable measurement window.
    let half = CALIBRATION_TICKS / 2;
    loop {
        let current = unsafe { core::ptr::read_volatile(APIC_TIMER_CCR) };
        if current <= half {
            break;
        }
        core::hint::spin_loop();
    }

    let remaining = unsafe { core::ptr::read_volatile(APIC_TIMER_CCR) };
    let t1 = time::monotonic_time_ns().unwrap_or(0);

    // Stop the timer.
    unsafe { core::ptr::write_volatile(APIC_TIMER_ICR, 0) };

    let elapsed_ticks = (CALIBRATION_TICKS - remaining) as u64;
    let elapsed_ns = t1.saturating_sub(t0);

    if elapsed_ns > 0 && elapsed_ticks > 0 {
        // Fixed-point 32.32: ticks_per_ns * 2^32
        let fp32 = ((elapsed_ticks as u128) << 32) / elapsed_ns as u128;
        TICKS_PER_NS_FP32.store(fp32 as u64, Ordering::Release);
    }
}

/// Sleep for `duration_ns` nanoseconds.
///
/// The vCPU halts during the sleep — zero CPU consumption, host thread
/// descheduled. Uses the LAPIC one-shot timer with TSC calibration from
/// the paravirtualized clock page.
///
/// Handles spurious wakeups by re-checking the deadline and re-arming
/// if time remains.
///
/// # Errors
///
/// - [`SleepError::NotInitialized`] if [`init()`] wasn't called.
/// - [`SleepError::ClockUnavailable`] if pvclock isn't configured.
/// - [`SleepError::CalibrationFailed`] if TSC frequency can't be derived.
/// - [`SleepError::Interrupted`] if the host cancelled execution.
/// Ensure the sleep infrastructure is initialised. Called lazily on the
/// first `sleep_ns()` invocation rather than at sandbox startup, so
/// guests that never sleep pay zero cost.
///
/// Idempotent — safe to call after snapshot restore (re-maps the APIC
/// page and re-calibrates, since scratch pages are not snapshotted).
fn ensure_init() {
    if INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    // Safety: single-threaded guest, no concurrent page table ops
    // during a sleep call.
    unsafe { init() };
}

pub fn sleep_ns(duration_ns: u64) -> Result<(), SleepError> {
    if !time::is_available() {
        return Err(SleepError::ClockUnavailable);
    }

    ensure_init();

    if TICKS_PER_NS_FP32.load(Ordering::Relaxed) == 0 {
        return Err(SleepError::CalibrationFailed);
    }

    // Clamp to max sleep duration.
    let duration_ns = duration_ns.min(MAX_SLEEP_NS);
    if duration_ns == 0 {
        return Ok(());
    }

    let start = time::monotonic_time_ns().ok_or(SleepError::ClockUnavailable)?;
    let deadline = start.wrapping_add(duration_ns);

    loop {
        let now = time::monotonic_time_ns().ok_or(SleepError::ClockUnavailable)?;
        if now >= deadline {
            return Ok(());
        }

        let remaining_ns = deadline.saturating_sub(now);
        let ticks = ns_to_apic_ticks(remaining_ns);

        if ticks == 0 {
            return Ok(());
        }

        // APIC initial count is u32; for very long sleeps we may need
        // to sleep in chunks. Clamp to u32::MAX and loop.
        let ticks = ticks.min(u32::MAX as u64) as u32;

        unsafe { arm_and_halt(ticks) };

        // Check if we were woken by the timer or by a cancellation.
        if TIMER_FIRED.load(Ordering::SeqCst) == 0 {
            // Woken without timer firing — likely host cancellation.
            // Check if deadline passed anyway (race with timer).
            let now = time::monotonic_time_ns().ok_or(SleepError::ClockUnavailable)?;
            if now >= deadline {
                return Ok(());
            }
            return Err(SleepError::Interrupted);
        }
        // Timer fired but we might have been woken early if ticks was
        // clamped. Loop back to check deadline.
    }
}

/// Sleep for `duration_us` microseconds.
pub fn sleep_us(duration_us: u64) -> Result<(), SleepError> {
    sleep_ns(duration_us.saturating_mul(1_000))
}

/// Sleep for `duration_ms` milliseconds.
pub fn sleep_ms(duration_ms: u64) -> Result<(), SleepError> {
    sleep_ns(duration_ms.saturating_mul(1_000_000))
}
