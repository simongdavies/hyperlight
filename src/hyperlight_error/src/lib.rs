/// Dealing with errors, including errors across VM boundaries
#[deny(dead_code, missing_docs, unused_mut)]
pub mod error;

/// The re-export for the `HyperlightError` type
pub use error::HyperlightError;

// Logs an error then returns with it , more or less equivalent to the bail! macro in anyhow
// but for HyperlightError instead of anyhow::Error
#[macro_export]
macro_rules! log_then_return {
    ($msg:literal $(,)?) => {{
        let __args = std::format_args!($msg);
        let __err_msg = match __args.as_str() {
            Some(msg) => String::from(msg),
            None => std::format!($msg),
        };
        let __err = $crate::HyperlightError::Error(__err_msg);
        log::error!("{}", __err);
        return Err(__err);
    }};
    ($err:expr $(,)?) => {
        log::error!("{}", $err);
        return Err($err);
    };
    ($err:stmt $(,)?) => {
        log::error!("{}", $err);
        return Err($err);
    };
    ($fmtstr:expr, $($arg:tt)*) => {
           let __err_msg = std::format!($fmtstr, $($arg)*);
           let __err = $crate::error::HyperlightError::Error(__err_msg);
           log::error!("{}", __err);
           return Err(__err);
    };
}
