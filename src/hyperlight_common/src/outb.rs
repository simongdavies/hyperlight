/// Supported actions when issuing an OUTB actions by Hyperlight.
/// - Log: for logging,
/// - CallFunction: makes a call to a host function,
/// - Abort: aborts the execution of the guest,
/// - DebugPrint: prints a message to the host
pub enum OutBAction {
    Log = 99,
    CallFunction = 101,
    Abort = 102,
    DebugPrint = 103,
}

impl TryFrom<u16> for OutBAction {
    type Error = anyhow::Error;
    fn try_from(val: u16) -> anyhow::Result<Self> {
        match val {
            99 => Ok(OutBAction::Log),
            101 => Ok(OutBAction::CallFunction),
            102 => Ok(OutBAction::Abort),
            103 => Ok(OutBAction::DebugPrint),
            _ => Err(anyhow::anyhow!("Invalid OutBAction value: {}", val)),
        }
    }
}
