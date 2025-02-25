use std::io::Write;

use hyperlight_error::new_error;
use tempfile::NamedTempFile;

use super::Hypervisor;
use crate::Result;

/// Dump registers + memory regions + raw memory to a tempfile
#[cfg(crashdump)]
pub(crate) fn crashdump_to_tempfile(hv: &dyn Hypervisor) -> Result<()> {
    let mut temp_file = NamedTempFile::with_prefix("mem")?;
    let hv_details = format!("{:#x?}", hv);

    // write hypervisor details such as registers, info about mapped memory regions, etc.
    temp_file.write_all(hv_details.as_bytes())?;
    temp_file.write_all(b"================ MEMORY DUMP =================\n")?;

    // write the raw memory dump for each memory region
    for region in hv.get_memory_regions() {
        if region.host_region.start == 0 || region.host_region.is_empty() {
            continue;
        }
        // SAFETY: we got this memory region from the hypervisor so should never be invalid
        let region_slice = unsafe {
            std::slice::from_raw_parts(
                region.host_region.start as *const u8,
                region.host_region.len(),
            )
        };
        temp_file.write_all(region_slice)?;
    }
    temp_file.flush()?;

    // persist the tempfile to disk
    let persist_path = temp_file.path().with_extension("dmp");
    temp_file
        .persist(&persist_path)
        .map_err(|e| new_error!("Failed to persist crashdump file: {:?}", e))?;

    println!("Memory dumped to file: {:?}", persist_path);
    log::error!("Memory dumped to file: {:?}", persist_path);

    Ok(())
}
