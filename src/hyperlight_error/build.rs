use anyhow::Result;

fn main() -> Result<()> {
    cfg_aliases::cfg_aliases! {
        kvm: { all(feature = "kvm", target_os = "linux") },
        mshv: { all(any(feature = "mshv2", feature = "mshv3"), target_os = "linux") },

        // the following features are mutually exclusive but rather than enforcing that here we are enabling mshv3 to override mshv2 when both are enabled
        // because mshv2 is in the default feature set we want to allow users to enable mshv3 without having to set --no-default-features and the re-enable
        // the other features they want.
        mshv2: { all(feature = "mshv2", not(feature="mshv3"), target_os = "linux") },
        mshv3: { all(feature = "mshv3", target_os = "linux") },
    }
    Ok(())
}
