pub enum OutBAction {
    Log = 99,
    CallFunction = 101,
    Abort = 102,
}

impl TryFrom<u16> for OutBAction {
    type Error = anyhow::Error;
    fn try_from(val: u16) -> anyhow::Result<Self> {
        match val {
            99 => Ok(OutBAction::Log),
            101 => Ok(OutBAction::CallFunction),
            102 => Ok(OutBAction::Abort),
            _ => Err(anyhow::anyhow!("Invalid OutBAction value: {}", val)),
        }
    }
}
