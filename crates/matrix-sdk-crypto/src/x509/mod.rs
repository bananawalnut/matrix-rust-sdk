// Copyright 2026 The Matrix.org Foundation C.I.C.
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

#![cfg(feature = "experimental-x509-identity-verification")]

//! Types and traits for verification of users and devices using X.509 keys and
//! certificates.

mod errors;
mod raw_x509_signature;
mod x509_signer;
mod x509_verify;

pub use raw_x509_signature::RawX509Signature;
pub use x509_signer::{RawX509Signer, X509Signer};
pub use x509_verify::{RawX509Verifier, X509Verifier};

#[cfg(any(test, feature = "rust-x509-verifier-impl"))]
mod rust_raw_x509_signer;
#[cfg(any(test, feature = "rust-x509-verifier-impl"))]
mod rust_raw_x509_verifier;
#[cfg(any(test, feature = "rust-x509-verifier-impl"))]
pub use rust_raw_x509_signer::RustRawX509Signer;
#[cfg(any(test, feature = "rust-x509-verifier-impl"))]
pub use rust_raw_x509_verifier::RustRawX509Verifier;
