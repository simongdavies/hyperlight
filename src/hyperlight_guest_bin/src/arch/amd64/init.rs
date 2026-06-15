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

use core::arch::asm;
use core::mem;

use super::exception::entry::init_idt;
use super::machine::{GDT, GdtEntry, GdtPointer, ProcCtrl, TSS};

/// See AMD64 Architecture Programmer's Manual, Volume 2: System Programming
///     Section 4: Segmented Virtual Memory
///         §4.6: Descriptor Tables
/// for the functions of the GDT.
///
/// Hyperlight's GDT consists of:
/// - A null first entry, which is architecturally required
/// - A single code segment descriptor, used for all code accesses
/// - A single data segment descriptor, used for all data accesses
/// - A TSS System descriptor that outlines the location of the TSS
///   (see [`init_tss`], below)
#[repr(C)]
struct HyperlightGDT {
    null: GdtEntry,
    kernel_code: GdtEntry,
    kernel_data: GdtEntry,
    tss: [GdtEntry; 2],
    /// User-mode 32-bit code descriptor. Only loaded by a compatibility-mode
    /// `sysret`, which we never issue, but it occupies the `sysret` selector
    /// base (0x28) so that the user data and 64-bit user code descriptors land
    /// at base+8 and base+16 as required by `sysretq`.
    #[cfg(feature = "userspace")]
    user_code32: GdtEntry,
    /// User-mode data descriptor (ring 3 SS/DS). Selector 0x30 | RPL 3 = 0x33.
    #[cfg(feature = "userspace")]
    user_data: GdtEntry,
    /// User-mode 64-bit code descriptor (ring 3 CS). Selector 0x38 | RPL 3 = 0x3b.
    #[cfg(feature = "userspace")]
    user_code: GdtEntry,
}
const _: () = assert!(mem::size_of::<HyperlightGDT>() == mem::size_of::<GDT>());
const _: () = assert!(mem::offset_of!(HyperlightGDT, null) == 0x00);
const _: () = assert!(mem::offset_of!(HyperlightGDT, kernel_code) == 0x08);
const _: () = assert!(mem::offset_of!(HyperlightGDT, kernel_data) == 0x10);
const _: () = assert!(mem::offset_of!(HyperlightGDT, tss) == 0x18);
#[cfg(feature = "userspace")]
const _: () = assert!(mem::offset_of!(HyperlightGDT, user_code32) == 0x28);
#[cfg(feature = "userspace")]
const _: () = assert!(mem::offset_of!(HyperlightGDT, user_data) == 0x30);
#[cfg(feature = "userspace")]
const _: () = assert!(mem::offset_of!(HyperlightGDT, user_code) == 0x38);

unsafe fn init_gdt(pc: *mut ProcCtrl) {
    unsafe {
        let gdt_ptr = &raw mut (*pc).gdt as *mut HyperlightGDT;
        (&raw mut (*gdt_ptr).null).write_volatile(GdtEntry::new(0, 0, 0, 0));
        (&raw mut (*gdt_ptr).kernel_code).write_volatile(GdtEntry::new(0, 0, 0x9A, 0xA));
        (&raw mut (*gdt_ptr).kernel_data).write_volatile(GdtEntry::new(0, 0, 0x92, 0xC));
        (&raw mut (*gdt_ptr).tss).write_volatile(GdtEntry::tss(
            &raw mut (*pc).tss as u64,
            mem::size_of::<TSS>() as u32,
        ));
        // User-mode segment descriptors for syscall/sysret. Access bytes are
        // P|DPL3|S|type: 0xFA = executable/readable code, 0xF2 = writable data.
        // Flags: 0xA = G,L (64-bit), 0xC = G,D/B (32-bit). Limits are ignored
        // for these segments in long mode (and user_code32 is never actually
        // loaded), matching the limit-0 convention of the kernel descriptors.
        #[cfg(feature = "userspace")]
        {
            (&raw mut (*gdt_ptr).user_code32).write_volatile(GdtEntry::new(0, 0, 0xFA, 0xC));
            (&raw mut (*gdt_ptr).user_data).write_volatile(GdtEntry::new(0, 0, 0xF2, 0xC));
            (&raw mut (*gdt_ptr).user_code).write_volatile(GdtEntry::new(0, 0, 0xFA, 0xA));
        }
        let gdtr = GdtPointer {
            limit: (core::mem::size_of::<GDT>() - 1) as u16,
            base: gdt_ptr as u64,
        };
        asm!(
            "lgdt [{0}]",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            "push rcx",
            "lea rax, [2f + rip]",
            "push rax",
            "retfq",
            "2:",
            in(reg) &gdtr,
            in("ax") mem::offset_of!(HyperlightGDT, kernel_data),
            in("rcx") mem::offset_of!(HyperlightGDT, kernel_code),
            lateout("rax") _,
            options(nostack, preserves_flags)
        );
    }
}

/// Hyperlight's TSS contains only a single IST entry, which is used
/// to set up the stack switch to the exception stack whenever we take
/// an exception (including page faults, which are important, since
/// the fault might be due to needing to grow the stack!)
///
/// This function sets up the TSS and then points the processor at the
/// system segment descriptor, initialized in [`init_gdt`] above,
/// which describes the location of the TSS.
unsafe fn init_tss(pc: *mut ProcCtrl) {
    unsafe {
        let tss_ptr = &raw mut (*pc).tss;
        // copy byte by byte to avoid alignment issues
        let ist1_ptr = &raw mut (*tss_ptr).ist1 as *mut [u8; 8];
        let exn_stack = hyperlight_common::layout::MAX_GVA as u64
            - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
            + 1;
        ist1_ptr.write_volatile(exn_stack.to_ne_bytes());
        asm!(
            "ltr ax",
            in("ax") core::mem::offset_of!(HyperlightGDT, tss),
            options(nostack, preserves_flags)
        );
    }
}

/// To initialise the main stack, we just pre-emptively map the first
/// page of it.
unsafe fn init_stack() -> u64 {
    use hyperlight_guest::layout::MAIN_STACK_TOP_GVA;
    let stack_top_page_base = (MAIN_STACK_TOP_GVA - 1) & !0xfff;
    unsafe {
        use hyperlight_common::vmem::{BasicMapping, MappingKind, PAGE_SIZE};
        crate::paging::map_region(
            hyperlight_guest::prim_alloc::alloc_phys_pages(1),
            stack_top_page_base as *mut u8,
            PAGE_SIZE as u64,
            MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        );
        crate::paging::barrier::first_valid_same_ctx();
    }
    MAIN_STACK_TOP_GVA
}

/// Machine-specific initialisation; calls [`crate::generic_init`]
/// once stack, CoW, etc have been set up.
#[unsafe(no_mangle)]
pub extern "C" fn entrypoint(peb_address: u64, seed: u64, ops: u64, max_log_level: u64) {
    unsafe {
        // Allocate a VA for processor control structures which must
        // survive snapshotting at the same VA.
        let pc = ProcCtrl::init();

        init_gdt(pc);
        init_tss(pc);
        init_idt(pc);
        let stack_top = init_stack();

        // Set up the ring 0 / ring 3 transition machinery (user stack and
        // syscall MSRs) before any user code can run.
        #[cfg(feature = "userspace")]
        super::ring3::init();

        // Architecture early init is complete! We pivot now to
        // executing on the main stack, and jump into generic
        // initialisation code in lib.rs
        pivot_stack(peb_address, seed, ops, max_log_level, stack_top);
    }
}

unsafe extern "C" {
    unsafe fn pivot_stack(
        peb_address: u64,
        seed: u64,
        ops: u64,
        max_log_level: u64,
        stack_top: u64,
    ) -> !;
}

// Mark this as the bottom-most frame for debuggers:
//  - .cfi_undefined rip: tells DWARF unwinders there is no return
//    address to recover (i.e. no caller frame).
//  - xor ebp, ebp: sets the frame pointer to zero so frame-pointer-
//    based unwinders recognise this as the end of the chain.
// See System V AMD64 ABI: https://gitlab.com/x86-psABIs/x86-64-ABI
//      §3.4.1 (Initial Stack and Register State)
//      §6.3 Unwinding Through Assembler Code
core::arch::global_asm!("
    .global pivot_stack\n
    pivot_stack:\n
    .cfi_startproc\n
    .cfi_undefined rip\n
    mov rsp, r8\n
    xor ebp, ebp\n
    call {generic_init}\n
    mov dx, {halt_port}\n
    out dx, eax\n
    cli\n
    hlt\n
    .cfi_endproc\n
",
    generic_init = sym crate::generic_init,
    halt_port = const hyperlight_common::outb::VmAction::Halt as u16,
);
