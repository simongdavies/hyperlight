#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonSpecialRegisters {
    pub(crate) ttbr0_el1: u64,
    // todo: handle ttbr1 as well
    pub(crate) tcr_el1: u64,
    pub(crate) mair_el1: u64,
    pub(crate) sctlr_el1: u64,
    pub(crate) cpacr_el1: u64,
    pub(crate) vbar_el1: u64,
    pub(crate) sp_el1: u64,
}

pub(crate) const TCR_EL1_PS_48: u64 = 0b101u64 << 32;
pub(crate) const TCR_EL1_TG0_4K: u64 = 0b00u64 << 14;
pub(crate) const TCR_EL1_TG1_4K: u64 = 0b00u64 << 30;
#[allow(clippy::identity_op)]
pub(crate) const TCR_EL1_T0SZ_48: u64 = 16u64 << 0;
pub(crate) const TCR_EL1_T1SZ_48: u64 = 16u64 << 16;

/// Normal memory, Outer + Inner Write-Back, non-transient, Read+Write allocate.
/// This matches the x86 guest, which maps all Normal RAM Write-Back
/// (`PAGE_WRITE_BACK`). A Write-Through policy (the previous value,
/// `0b1011_1011`) forces every store to be written straight through to memory
/// instead of coalescing in the L1 D-cache, which makes store-heavy guest code
/// run orders of magnitude slower under a hypervisor. Each nibble `0b1111`
/// decodes as Write-Back non-transient with Read and Write allocation.
pub(crate) const MAIR_NORMAL_OWB_NT_AA: u64 = 0b11111111;
pub(crate) const MAIR_ITEM_WIDTH: u8 = 8;

pub(crate) const SCTLR_EL1_RES1: u64 = 0b11u64 << 28 | 0b11u64 << 22 | 0b1u64 << 20 | 0b1u64 << 11;
pub(crate) const SCTLR_EL1_M: u64 = 0b1u64 << 0;
pub(crate) const SCTLR_EL1_C: u64 = 0b1u64 << 2;
/// Instruction cache enable. Without this bit set, instruction fetches to
/// Normal memory are treated as Non-cacheable, forcing every instruction fetch
/// to bypass the L1 I-cache (and, under a hypervisor, drag a stage-2 walk on
/// the I-side). That makes all in-guest execution run orders of magnitude
/// slower, so the I-cache must be enabled alongside the MMU and D-cache.
pub(crate) const SCTLR_EL1_I: u64 = 0b1u64 << 12;

pub(crate) const CPACR_EL1_FPEN_NO_TRAP: u64 = 0b11 << 20;

impl CommonSpecialRegisters {
    pub(crate) fn defaults(root_pt_addr: u64) -> Self {
        CommonSpecialRegisters {
            ttbr0_el1: root_pt_addr & !0xfff,
            tcr_el1: TCR_EL1_PS_48
                | TCR_EL1_TG0_4K
                | TCR_EL1_TG1_4K
                | TCR_EL1_T0SZ_48
                | TCR_EL1_T1SZ_48,
            mair_el1: MAIR_NORMAL_OWB_NT_AA
                << (MAIR_ITEM_WIDTH * hyperlight_common::vmem::ATTR_INDEX_NORMAL),
            sctlr_el1: SCTLR_EL1_RES1 | SCTLR_EL1_M | SCTLR_EL1_C | SCTLR_EL1_I,
            cpacr_el1: CPACR_EL1_FPEN_NO_TRAP,
            vbar_el1: 0,
            sp_el1: 0,
        }
    }
}
