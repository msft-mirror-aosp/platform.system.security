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

//! This module implements a retry version for multiple DICE functions that
//! require preallocated output buffer. As the retry functions require
//! memory allocation on heap, currently we only expose these functions in
//! std environment.

use crate::bcc::{bcc_format_config_descriptor, bcc_main_flow};
use crate::dice::{dice_main_flow, Cdi, CdiValues, InputValues};
use crate::error::{DiceError, Result};
use std::ffi::CStr;

/// Artifacts stores a set of dice artifacts comprising CDI_ATTEST, CDI_SEAL,
/// and the BCC formatted attestation certificate chain.
/// As we align with the DICE standards today, this is the certificate chain
/// is also called DICE certificate chain.
pub struct OwnedDiceArtifacts {
    /// CDI Values.
    pub cdi_values: CdiValues,
    /// Boot Certificate Chain.
    pub bcc: Vec<u8>,
}

/// Retries the given function with bigger output buffer size.
fn retry_with_bigger_buffer<F>(mut f: F) -> Result<Vec<u8>>
where
    F: FnMut(&mut Vec<u8>) -> Result<usize>,
{
    const INITIAL_BUFFER_SIZE: usize = 256;
    const MAX_BUFFER_SIZE: usize = 64 * 1024 * 1024;

    let mut buffer = vec![0u8; INITIAL_BUFFER_SIZE];
    while buffer.len() <= MAX_BUFFER_SIZE {
        match f(&mut buffer) {
            Err(DiceError::BufferTooSmall) => {
                let new_size = buffer.len() * 2;
                buffer.resize(new_size, 0);
            }
            Err(e) => return Err(e),
            Ok(actual_size) => {
                if actual_size > buffer.len() {
                    panic!(
                        "actual_size larger than buffer size: open-dice function
                         may have written past the end of the buffer."
                    );
                }
                buffer.truncate(actual_size);
                return Ok(buffer);
            }
        }
    }
    Err(DiceError::PlatformError)
}

/// Formats a configuration descriptor following the BCC's specification.
pub fn retry_bcc_format_config_descriptor(
    name: Option<&CStr>,
    version: Option<u64>,
    resettable: bool,
) -> Result<Vec<u8>> {
    retry_with_bigger_buffer(|buffer| {
        bcc_format_config_descriptor(name, version, resettable, buffer)
    })
}

/// Executes the main BCC flow.
///
/// Given a full set of input values along with the current BCC and CDI values,
/// computes the next CDI values and matching updated BCC.
pub fn retry_bcc_main_flow(
    current_cdi_attest: &Cdi,
    current_cdi_seal: &Cdi,
    bcc: &[u8],
    input_values: &InputValues,
) -> Result<OwnedDiceArtifacts> {
    let mut next_cdi_values = CdiValues::default();
    let next_bcc = retry_with_bigger_buffer(|next_bcc| {
        bcc_main_flow(
            current_cdi_attest,
            current_cdi_seal,
            bcc,
            input_values,
            &mut next_cdi_values,
            next_bcc,
        )
    })?;
    Ok(OwnedDiceArtifacts { cdi_values: next_cdi_values, bcc: next_bcc })
}

/// Executes the main DICE flow.
///
/// Given a full set of input values and the current CDI values, computes the
/// next CDI values and a matching certificate.
pub fn retry_dice_main_flow(
    current_cdi_attest: &Cdi,
    current_cdi_seal: &Cdi,
    input_values: &InputValues,
) -> Result<(CdiValues, Vec<u8>)> {
    let mut next_cdi_values = CdiValues::default();
    let next_cdi_certificate = retry_with_bigger_buffer(|next_cdi_certificate| {
        dice_main_flow(
            current_cdi_attest,
            current_cdi_seal,
            input_values,
            next_cdi_certificate,
            &mut next_cdi_values,
        )
    })?;
    Ok((next_cdi_values, next_cdi_certificate))
}
