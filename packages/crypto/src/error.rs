#[cfg(feature = "backtraces")]
use std::backtrace::Backtrace;
use std::fmt::Debug;
use thiserror::Error;

pub type CryptoResult<T> = core::result::Result<T, CryptoError>;

#[derive(Error, Debug, PartialEq)]
pub enum CryptoError {
    #[error("Crypto error: {msg}")]
    GenericErr {
        msg: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Invalid point on curve")]
    InvalidPointOnCurve {
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Invalid hash format")]
    InvalidHashFormat {
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Invalid public key format")]
    InvalidPubkeyFormat {
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
    #[error("Invalid proof format")]
    InvalidProofFormat {
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
}

impl CryptoError {
    pub fn generic_err(msg: impl Into<String>) -> Self {
        CryptoError::GenericErr {
            msg: msg.into(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn invalid_point_on_curve() -> Self {
        CryptoError::InvalidPointOnCurve {
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn invalid_hash_format() -> Self {
        CryptoError::InvalidHashFormat {
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn invalid_pubkey_format() -> Self {
        CryptoError::InvalidPubkeyFormat {
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    pub fn invalid_proof_format() -> Self {
        CryptoError::InvalidProofFormat {
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    /// Numeric error code that can easily be passed over the
    /// contract VM boundary.
    pub fn code(&self) -> u32 {
        match self {
            CryptoError::InvalidPointOnCurve { .. } => 2,
            CryptoError::InvalidHashFormat { .. } => 3,
            CryptoError::InvalidProofFormat { .. } => 4,
            CryptoError::InvalidPubkeyFormat { .. } => 5,
            CryptoError::GenericErr { .. } => 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_err_works() {
        let error = CryptoError::generic_err("something went wrong in a general way");
        match error {
            CryptoError::GenericErr { msg, .. } => {
                assert_eq!(msg, "something went wrong in a general way")
            }
            _ => panic!("wrong error type!"),
        }
    }

    #[test]
    fn invalid_point_on_curve_works() {
        let error = CryptoError::invalid_point_on_curve();
        match error {
            CryptoError::InvalidPointOnCurve { .. } => {}
            _ => panic!("wrong error type!"),
        }
    }

    #[test]
    fn invalid_hash_format_works() {
        let error = CryptoError::invalid_hash_format();
        match error {
            CryptoError::InvalidHashFormat { .. } => {}
            _ => panic!("wrong error type!"),
        }
    }

    #[test]
    fn invalid_proof_format_works() {
        let error = CryptoError::invalid_proof_format();
        match error {
            CryptoError::InvalidProofFormat { .. } => {}
            _ => panic!("wrong error type!"),
        }
    }

    #[test]
    fn invalid_pubkey_format_works() {
        let error = CryptoError::invalid_pubkey_format();
        match error {
            CryptoError::InvalidPubkeyFormat { .. } => {}
            _ => panic!("wrong error type!"),
        }
    }

    #[test]
    fn code_works() {
        assert_eq!(CryptoError::invalid_point_on_curve().code(), 2);
        assert_eq!(CryptoError::invalid_hash_format().code(), 3);
        assert_eq!(CryptoError::invalid_proof_format().code(), 4);
        assert_eq!(CryptoError::invalid_pubkey_format().code(), 5);
        assert_eq!(CryptoError::generic_err("test").code(), 10);
    }
}
