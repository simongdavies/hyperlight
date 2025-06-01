use core::ffi::c_char;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_guest_bin::guest_err::setError;

#[unsafe(no_mangle)]
pub extern "C" fn hl_set_error(err: ErrorCode, message: *const c_char) {
    unsafe {
        setError(err.into(), message);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_abort_with_code(err: i32) {
    hyperlight_guest::exit::abort_with_code(&[err as u8]);
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_abort_with_code_and_message(err: i32, message: *const c_char) {
    unsafe { hyperlight_guest::exit::abort_with_code_and_message(&[err as u8], message) };
}
