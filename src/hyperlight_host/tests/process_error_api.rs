// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use hyperlight_host::HyperlightError;

// This external exhaustive match checks both feature-disabled and enabled enum shapes.
fn retains_cleanup(error: &HyperlightError) -> bool {
    use HyperlightError::*;
    match error {
        #[cfg(feature = "process-isolation")]
        ProcessCleanup(_) => true,
        AnyhowError(_)
        | CheckedAddOverflow(_, _)
        | CStringConversionError(_)
        | Error(_)
        | ExecutionAccessViolation(_)
        | ExecutionCanceledByHost()
        | FailedToGetValueFromParameter()
        | FieldIsMissingInGuestLogData(_)
        | GuestAborted(_, _)
        | GuestError(_, _)
        | GuestExecutionHungOnHostFunctionCall()
        | GuestFunctionCallAlreadyInProgress()
        | GuestInterfaceUnsupportedType(_)
        | GuestBinVersionMismatch { .. }
        | HostFunctionNotFound(_)
        | HyperlightVmError(_)
        | IOError(_)
        | IntConversionFailure(_)
        | InvalidFlatBuffer(_)
        | JsonConversionFailure(_)
        | LockAttemptFailed(_)
        | MemoryAccessViolation(_, _, _)
        | MemoryRequestTooBig(_, _)
        | MemoryRequestTooSmall(_, _)
        | MetricNotFound(_)
        | NoHypervisorFound()
        | NoMemorySnapshot
        | ParameterValueConversionFailure(_, _)
        | PEFileProcessingFailure(_)
        | PoisonedSandbox
        | UnrecoverableSandbox
        | RawPointerLessThanBaseAddress(_, _)
        | RefCellBorrowFailed(_)
        | RefCellMutBorrowFailed(_)
        | ReturnValueConversionFailure(_, _)
        | SharedMemory(_)
        | SnapshotHostFunctionMismatch { .. }
        | SystemTimeError(_)
        | TryFromSliceError(_)
        | UnexpectedNoOfArguments(_, _)
        | UnexpectedParameterValueType(_, _)
        | UnexpectedReturnValueType(_, _)
        | UTF8StringConversionFailure(_)
        | VectorCapacityIncorrect(_, _, _) => false,
        #[cfg(target_os = "windows")]
        CrossBeamReceiveError(_) | CrossBeamSendError(_) | WindowsAPIError(_) => false,
        #[cfg(target_os = "linux")]
        VmmSysError(_) => false,
    }
}

#[test]
fn public_error_shape_is_exhaustively_matchable() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<HyperlightError>();
    assert!(!retains_cleanup(&HyperlightError::UnrecoverableSandbox));
    #[cfg(feature = "process-isolation")]
    {
        assert_send_sync::<hyperlight_host::process::ProcessCleanupError>();
        let _constructor: fn(
            Box<hyperlight_host::process::ProcessCleanupError>,
        ) -> HyperlightError = HyperlightError::ProcessCleanup;
    }
}
