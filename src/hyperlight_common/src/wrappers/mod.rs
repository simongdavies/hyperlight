/// Wrappers around flatbuffer types
#[allow(missing_docs)]
pub mod flatbuffer_wrappers;
/// Safe wrappers around windows types like `PSTR`
#[cfg(all(target_os = "windows", feature = "std"))]
pub mod windows_wrappers;
