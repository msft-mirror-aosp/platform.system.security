// Copyright 2023, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Errors and relating functions thrown in this library.

use open_dice_cbor_bindgen::DiceResult;
use std::{fmt, result};

#[cfg(feature = "std")]
use std::error::Error;

/// Error type used by DICE.
#[derive(Debug)]
pub enum DiceError {
    /// Provided input was invalid.
    InvalidInput,
    /// Provided buffer was too small.
    BufferTooSmall,
    /// Platform error.
    PlatformError,
    /// Input string has an interior nul byte.
    /// TODO(b/267575445): Remove this error once we change the param of
    /// `format_config_descriptor to take &CStr.
    #[cfg(feature = "std")]
    CStrNulError,
    /// The allocation of a ZVec failed.
    #[cfg(feature = "std")]
    ZVecError(keystore2_crypto::zvec::Error),
}

#[cfg(feature = "std")]
impl From<keystore2_crypto::zvec::Error> for DiceError {
    fn from(e: keystore2_crypto::zvec::Error) -> Self {
        Self::ZVecError(e)
    }
}

/// This makes `DiceError` accepted by anyhow.
#[cfg(feature = "std")]
impl Error for DiceError {}

impl fmt::Display for DiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidInput => write!(f, "invalid input"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::PlatformError => write!(f, "platform error"),
            #[cfg(feature = "std")]
            Self::CStrNulError => write!(f, "input string has an interior nul byte"),
            #[cfg(feature = "std")]
            Self::ZVecError(e) => write!(f, "ZVec allocation failed {e}"),
        }
    }
}

/// DICE result type.
pub type Result<T> = result::Result<T, DiceError>;

/// Checks the given `DiceResult`. Returns an error if it's not OK.
pub fn check_result(result: DiceResult) -> Result<()> {
    match result {
        DiceResult::kDiceResultOk => Ok(()),
        DiceResult::kDiceResultInvalidInput => Err(DiceError::InvalidInput),
        DiceResult::kDiceResultBufferTooSmall => Err(DiceError::BufferTooSmall),
        DiceResult::kDiceResultPlatformError => Err(DiceError::PlatformError),
    }
}
