// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::{collections::BTreeMap, ops::Deref};

use matrix_sdk_base::crypto::{
    Device as BaseDevice, DeviceData, LocalTrust, UserDevices as BaseUserDevices,
    store::CryptoStoreError,
};
use ruma::{
    DeviceId, OwnedDeviceId, OwnedUserId,
    api::client::keys::upload_signatures::v3::Response as UploadSignaturesResponse,
    encryption::DeviceKeys as RumaDeviceKeys, events::key::verification::VerificationMethod,
    serde::Raw,
};

use super::ManualVerifyError;
use crate::{
    Client,
    encryption::verification::{SasVerification, VerificationRequest},
    error::Result,
};

fn ensure_signature_upload_succeeded(has_failures: bool) -> Result<(), ManualVerifyError> {
    if has_failures { Err(ManualVerifyError::ServerFailures) } else { Ok(()) }
}

/// Updates about [`Device`]s which got received over the `/keys/query`
/// endpoint.
#[derive(Clone, Debug, Default)]
pub struct DeviceUpdates {
    /// The list of newly discovered devices.
    ///
    /// A device being in this list does not necessarily mean that the device
    /// was just created, it just means that it's the first time we're
    /// seeing this device.
    pub new: BTreeMap<OwnedUserId, BTreeMap<OwnedDeviceId, Device>>,
    /// The list of changed devices.
    pub changed: BTreeMap<OwnedUserId, BTreeMap<OwnedDeviceId, Device>>,
}

impl DeviceUpdates {
    pub(crate) fn new(
        client: Client,
        updates: matrix_sdk_base::crypto::store::types::DeviceUpdates,
    ) -> Self {
        let map_devices = |(user_id, devices)| {
            // For some reason we need to tell Rust the type of `devices`.
            let devices: BTreeMap<_, _> = devices;

            (
                user_id,
                devices
                    .into_iter()
                    .map(|(device_id, device)| {
                        (device_id, Device { inner: device, client: client.to_owned() })
                    })
                    .collect(),
            )
        };

        let new = updates.new.into_iter().map(map_devices).collect();
        let changed = updates.changed.into_iter().map(map_devices).collect();

        DeviceUpdates { new, changed }
    }
}

/// A device represents a E2EE capable client or device of an user.
///
/// A `Device` is backed by [device keys] that are uploaded to the server.
///
/// The [device keys] for our own device will be automatically uploaded by the
/// SDK and the private parts of our device keys never leave this device.
///
/// Device keys consist of an Ed25519 keypair and a Curve25519 keypair. Only the
/// public parts of those keypairs will be uploaded to the server.
///
/// ```text
///                 ┌──────────────────────────────────┐
///                 │              Device              │
///                 ├──────────────────────────────────┤
///                 │            Device Keys           │
///                 ├────────────────┬─────────────────┤
///                 │   Ed25519 Key  │  Curve25519 Key │
///                 └────────────────┴─────────────────┘
/// ```
///
/// The Ed25519 key will be used to uniquely identify the `Device` while the
/// Curve25519 key is used to establish 1-to-1 encrypted communication channels
/// between two devices.
///
/// [device keys]: https://spec.matrix.org/unstable/client-server-api/#device-keys
#[derive(Clone, Debug)]
pub struct Device {
    pub(crate) inner: BaseDevice,
    pub(crate) client: Client,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Whether the signature upload request reached and was accepted by the server.
pub enum SignatureUploadTransport {
    /// The homeserver returned a successful HTTP response.
    Accepted,
    /// The request failed before a successful HTTP response was received.
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// The per-key result reported inside a successful signature upload response.
pub enum SignatureUploadProcessing {
    /// The response contained no per-key failures.
    Accepted,
    /// The homeserver rejected the signature because the key did not match.
    KeyMismatch,
    /// The homeserver rejected an invalid signature.
    InvalidSignature,
    /// The response contained another per-key failure.
    OtherFailure,
}

/// Non-secret diagnostics for one own-device signature upload attempt.
#[derive(Debug)]
pub struct DeviceSignatureDiagnostic {
    /// Whether the local private self-signing key matches the public identity.
    pub private_key_matches_public_identity: bool,
    /// Whether locally cached device keys match the queried server device.
    pub local_device_keys_match_server_device: bool,
    /// Whether the object signed locally matches the queried server device.
    pub signed_object_matches_server_device: bool,
    /// Whether the generated signature verifies against the public identity.
    pub generated_signature_valid: bool,
    /// Whether the upload transport itself succeeded.
    pub upload_transport: SignatureUploadTransport,
    /// How the homeserver processed the uploaded signature.
    pub upload_processing: SignatureUploadProcessing,
}

fn classify_signature_upload(response: &UploadSignaturesResponse) -> SignatureUploadProcessing {
    if response.failures.is_empty() {
        return SignatureUploadProcessing::Accepted;
    }
    let mut result = SignatureUploadProcessing::OtherFailure;
    for failure in response.failures.values().flat_map(|failures| failures.values()) {
        let Ok(failure) = serde_json::to_value(failure) else { continue };
        match classify_signature_upload_failure(&failure) {
            SignatureUploadProcessing::KeyMismatch => {
                return SignatureUploadProcessing::KeyMismatch;
            }
            SignatureUploadProcessing::InvalidSignature => {
                result = SignatureUploadProcessing::InvalidSignature;
            }
            _ => {}
        }
    }
    result
}

fn classify_signature_upload_failure(failure: &serde_json::Value) -> SignatureUploadProcessing {
    if failure.get("error").and_then(|error| error.as_str()) == Some("Key does not match") {
        SignatureUploadProcessing::KeyMismatch
    } else if failure.get("errcode").and_then(|code| code.as_str()) == Some("M_INVALID_SIGNATURE") {
        SignatureUploadProcessing::InvalidSignature
    } else {
        SignatureUploadProcessing::OtherFailure
    }
}

impl Deref for Device {
    type Target = DeviceData;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Device {
    /// Request an interactive verification with this `Device`.
    ///
    /// Returns a [`VerificationRequest`] object that can be used to control the
    /// verification flow.
    ///
    /// The default methods that are supported are `m.sas.v1` and
    /// `m.qr_code.show.v1`, if this isn't desirable the
    /// [`request_verification_with_methods()`] method can be used to override
    /// this. `m.qr_code.show.v1` is only available if the `qrcode` feature is
    /// enabled, which it is by default.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matrix_sdk::{Client, ruma::{device_id, user_id}};
    /// # use url::Url;
    /// # async {
    /// # let alice = user_id!("@alice:example.org");
    /// # let homeserver = Url::parse("http://example.com")?;
    /// # let client = Client::new(homeserver).await?;
    /// let device =
    ///     client.encryption().get_device(alice, device_id!("DEVICEID")).await?;
    ///
    /// if let Some(device) = device {
    ///     let verification = device.request_verification().await?;
    /// }
    /// # anyhow::Ok(()) };
    /// ```
    ///
    /// [`request_verification_with_methods()`]:
    /// #method.request_verification_with_methods
    pub async fn request_verification(&self) -> Result<VerificationRequest> {
        let (verification, request) = self.inner.request_verification();
        self.client.send_verification_request(request).await?;

        Ok(VerificationRequest { inner: verification, client: self.client.clone() })
    }

    /// Request an interactive verification with this `Device`.
    ///
    /// Returns a [`VerificationRequest`] object that can be used to control the
    /// verification flow.
    ///
    /// # Arguments
    ///
    /// * `methods` - The verification methods that we want to support. Must be
    ///   non-empty.
    ///
    /// # Panics
    ///
    /// This method will panic if `methods` is empty.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matrix_sdk::{
    /// #    Client,
    /// #    ruma::{
    /// #        device_id, user_id,
    /// #        events::key::verification::VerificationMethod,
    /// #    }
    /// # };
    /// # use url::Url;
    /// # async {
    /// # let alice = user_id!("@alice:example.org");
    /// # let homeserver = Url::parse("http://example.com")?;
    /// # let client = Client::new(homeserver).await?;
    /// let device =
    ///     client.encryption().get_device(alice, device_id!("DEVICEID")).await?;
    ///
    /// // We don't want to support showing a QR code, we only support SAS
    /// // verification
    /// let methods = vec![VerificationMethod::SasV1];
    ///
    /// if let Some(device) = device {
    ///     let verification =
    ///         device.request_verification_with_methods(methods).await?;
    /// }
    /// # anyhow::Ok(()) };
    /// ```
    pub async fn request_verification_with_methods(
        &self,
        methods: Vec<VerificationMethod>,
    ) -> Result<VerificationRequest> {
        assert!(!methods.is_empty(), "The list of verification methods can't be non-empty");

        let (verification, request) = self.inner.request_verification_with_methods(methods);
        self.client.send_verification_request(request).await?;

        Ok(VerificationRequest { inner: verification, client: self.client.clone() })
    }

    /// Start an interactive verification with this [`Device`]
    ///
    /// Returns a [`SasVerification`] object that represents the interactive
    /// verification flow.
    ///
    /// This method has been deprecated in the spec and the
    /// [`request_verification()`] method should be used instead.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matrix_sdk::{Client, ruma::{device_id, user_id}};
    /// # use url::Url;
    /// # async {
    /// # let alice = user_id!("@alice:example.org");
    /// # let homeserver = Url::parse("http://example.com")?;
    /// # let client = Client::new(homeserver).await?;
    /// let device =
    ///     client.encryption().get_device(alice, device_id!("DEVICEID")).await?;
    ///
    /// if let Some(device) = device {
    ///     let verification = device.start_verification().await?;
    /// }
    /// # anyhow::Ok(()) };
    /// ```
    ///
    /// [`request_verification()`]: #method.request_verification
    #[deprecated(
        since = "0.4.0",
        note = "directly starting a verification is deprecated in the spec. \
                Users should instead use request_verification()"
    )]
    pub async fn start_verification(&self) -> Result<SasVerification> {
        let (sas, request) = self.inner.start_verification().await?;
        self.client.send_to_device(&request).await?;

        Ok(SasVerification { inner: Box::new(sas), client: self.client.clone() })
    }

    /// Manually verify this device.
    ///
    /// This method will attempt to sign the device using our private cross
    /// signing key.
    ///
    /// This method will always fail if the device belongs to someone else, we
    /// can only sign our own devices.
    ///
    /// It can also fail if we don't have the private part of our self-signing
    /// key.
    ///
    /// The state of our private cross signing keys can be inspected using the
    /// [`Encryption::cross_signing_status()`] method.
    ///
    /// [`Encryption::cross_signing_status()`]: crate::encryption::Encryption::cross_signing_status
    ///
    /// ### Problems of manual verification
    ///
    /// Manual verification may be more convenient to use, i.e. both devices
    /// need to be online and available to interactively verify each other.
    /// Despite the convenience, interactive verifications should be
    /// generally preferred. Manually verifying a device won't notify the
    /// other device, the one being verified, that they should also verify
    /// us. This means that device `A` will consider device `B` to be
    /// verified, but not the other way around.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matrix_sdk::{
    /// #    Client,
    /// #    ruma::{
    /// #        device_id, user_id,
    /// #        events::key::verification::VerificationMethod,
    /// #    }
    /// # };
    /// # use url::Url;
    /// # async {
    /// # let alice = user_id!("@alice:example.org");
    /// # let homeserver = Url::parse("http://example.com")?;
    /// # let client = Client::new(homeserver).await?;
    /// let device =
    ///     client.encryption().get_device(alice, device_id!("DEVICEID")).await?;
    ///
    /// if let Some(device) = device {
    ///     device.verify().await?;
    /// }
    /// # anyhow::Ok(()) };
    /// ```
    pub async fn verify(&self) -> Result<(), ManualVerifyError> {
        let request = self.inner.verify().await?;
        let response = self.client.send(request).await?;
        ensure_signature_upload_succeeded(!response.failures.is_empty())?;

        Ok(())
    }

    /// Sign the locally cached own device, upload the signature, and return
    /// non-secret diagnostics for the attempt.
    pub async fn verify_with_diagnostics(
        &self,
    ) -> Result<DeviceSignatureDiagnostic, ManualVerifyError> {
        let prepared = self.inner.prepare_signature_with_diagnostics().await?;
        self.send_prepared_diagnostic(prepared).await
    }

    /// Sign the exact own-device JSON queried from the server, upload the
    /// signature, and return non-secret diagnostics for the attempt.
    pub async fn verify_raw_with_diagnostics(
        &self,
        raw: Raw<RumaDeviceKeys>,
    ) -> Result<DeviceSignatureDiagnostic, ManualVerifyError> {
        let prepared = self.inner.prepare_raw_signature_with_diagnostics(raw).await?;
        self.send_prepared_diagnostic(prepared).await
    }

    async fn send_prepared_diagnostic(
        &self,
        prepared: matrix_sdk_base::crypto::DeviceSignaturePreparation,
    ) -> Result<DeviceSignatureDiagnostic, ManualVerifyError> {
        let (upload_transport, upload_processing) = match self.client.send(prepared.request).await {
            Ok(response) => {
                (SignatureUploadTransport::Accepted, classify_signature_upload(&response))
            }
            Err(_) => (SignatureUploadTransport::Failed, SignatureUploadProcessing::OtherFailure),
        };

        Ok(DeviceSignatureDiagnostic {
            private_key_matches_public_identity: prepared.private_key_matches_public_identity,
            local_device_keys_match_server_device: prepared.local_device_keys_match_server_device,
            signed_object_matches_server_device: prepared.signed_object_matches_server_device,
            generated_signature_valid: prepared.generated_signature_valid,
            upload_transport,
            upload_processing,
        })
    }

    /// Is the device considered to be verified.
    ///
    /// A device is considered to be verified, either if it's locally marked as
    /// such, or if it's signed by the appropriate cross signing key. Our own
    /// device, is always implicitly verified.
    ///
    /// ## Local trust
    ///
    /// Local trust can be established using the [`Device::set_local_trust()`]
    /// method or it will be established if we interactively verify the device
    /// using [`Device::request_verification()`].
    ///
    /// **Note**: The concept of local trust is largely deprecated because it
    /// can't be shared with other devices. Every device needs to verify all the
    /// other devices it communicates to. Because this becomes quickly
    /// unsustainable verification has migrated to cross signing verification.
    ///
    /// ## Cross signing verification
    ///
    /// Cross signing verification uses signatures over devices and user
    /// identities to check if a device is considered to be verified. The
    /// signatures can be uploaded to the homeserver, this allows us to
    /// share the verification state with other devices. Devices only need to
    /// verify a user identity, if the user identity has verified and signed
    /// the device we can consider the device to be verified as well.
    ///
    /// Devices are usually cross signing verified using interactive
    /// verification, which can be started using the
    /// [`Device::request_verification()`] method.
    ///
    /// A [`Device`] can also be manually signed using the [`Device::verify()`]
    /// method, this works only for devices belonging to our own user.
    ///
    /// Do note that the device that is being manually signed will not trust our
    /// own user identity like it would if we interactively verify the device.
    /// Such a device can mark our own user as verified using the
    /// [`UserIdentity::verify()`] method.
    ///
    /// ### Verification of devices belonging to our own user.
    ///
    /// If the device belongs to our own user, the device will be considered to
    /// be verified if:
    ///
    /// * The device has been signed by our self-signing key
    /// * Our own user identity is considered to be [verified]
    ///
    /// In other words we need to find a valid signature chain from our user
    /// identity to the device:
    ///
    ///```text
    ///         ┌─────────────────────────────────────┐    ┌─────────────┐
    ///         │           Own User Identity         │    │   Device    │
    ///         ├──────────────────┬──────────────────┤───►├─────────────┤
    ///         │    Master Key    │ Self-signing Key │    │ Device Keys │
    ///         └──────────────────┴──────────────────┘    └─────────────┘
    /// ```
    ///
    /// ### Verification of devices belonging to other users.
    ///
    /// If the device belongs to some other user it will be considered to be
    /// verified if:
    ///
    /// * The device has been signed by the user's self-signing key
    /// * The user's master-signing key has been signed by our own user-signing
    ///   key, i.e. our own identity trusts the other users identity.
    /// * Our own user identity is considered to be [verified]
    ///
    /// ```text
    ///             ┌─────────────────────────────────────┐
    ///             │           Own User Identity         │
    ///             ├──────────────────┬──────────────────┤─────┐
    ///             │    Master Key    │ User-signing Key │     │
    ///             └──────────────────┴──────────────────┘     │
    ///     ┌───────────────────────────────────────────────────┘
    ///     │
    ///     │       ┌─────────────────────────────────────┐    ┌─────────────┐
    ///     │       │             User Identity           │    │   Device    │
    ///     └──────►├──────────────────┬──────────────────┤───►│─────────────│
    ///             │    Master Key    │ Self-signing Key │    │ Device Keys │
    ///             └──────────────────┴──────────────────┘    └─────────────┘
    /// ```
    ///
    /// # Examples
    ///
    /// Let's check if a device is verified:
    ///
    /// ```no_run
    /// # use matrix_sdk::{
    /// #    Client,
    /// #    ruma::{
    /// #        device_id, user_id,
    /// #        events::key::verification::VerificationMethod,
    /// #    }
    /// # };
    /// # use url::Url;
    /// # async {
    /// # let alice = user_id!("@alice:example.org");
    /// # let homeserver = Url::parse("http://example.com")?;
    /// # let client = Client::new(homeserver).await?;
    /// let device =
    ///     client.encryption().get_device(alice, device_id!("DEVICEID")).await?;
    ///
    /// if let Some(device) = device {
    ///     if device.is_verified() {
    ///         println!(
    ///             "Device {} of user {} is verified",
    ///             device.device_id(),
    ///             device.user_id(),
    ///         );
    ///     } else {
    ///         println!(
    ///             "Device {} of user {} is not verified",
    ///             device.device_id(),
    ///             device.user_id(),
    ///         );
    ///     }
    /// }
    /// # anyhow::Ok(()) };
    /// ```
    ///
    /// [`UserIdentity::verify()`]:
    /// crate::encryption::identities::UserIdentity::verify
    /// [verified]: crate::encryption::identities::UserIdentity::is_verified
    pub fn is_verified(&self) -> bool {
        self.inner.is_verified()
    }

    /// Is the device considered to be verified with cross-signing.
    ///
    /// A device is considered to be verified if it's signed by the appropriate
    /// cross-signing key.
    ///
    /// ## Cross-signing verification
    ///
    /// Cross-signing verification uses signatures over devices and user
    /// identities to check if a device is considered to be verified. The
    /// signatures can be uploaded to the homeserver, this allows us to
    /// share the verification state with other devices. Devices only need to
    /// verify a user identity, if the user identity has verified and signed
    /// the device we can consider the device to be verified as well.
    ///
    /// Devices are usually cross-signing verified using interactive
    /// verification, which can be started using the
    /// [`Device::request_verification()`] method.
    ///
    /// A [`Device`] can also be manually signed using the [`Device::verify()`]
    /// method, this works only for devices belonging to our own user.
    ///
    /// Do note that the device that is being manually signed will not trust our
    /// own user identity like it would if we interactively verify the device.
    /// Such a device can mark our own user as verified using the
    /// [`UserIdentity::verify()`] method.
    ///
    /// ### Verification of devices belonging to our own user.
    ///
    /// If the device belongs to our own user, the device will be considered to
    /// be verified if:
    ///
    /// * The device has been signed by our self-signing key
    /// * Our own user identity is considered to be [verified]
    ///
    /// In other words we need to find a valid signature chain from our user
    /// identity to the device:
    ///
    ///```text
    ///         ┌─────────────────────────────────────┐    ┌─────────────┐
    ///         │           Own User Identity         │    │   Device    │
    ///         ├──────────────────┬──────────────────┤───►├─────────────┤
    ///         │    Master Key    │ Self-signing Key │    │ Device Keys │
    ///         └──────────────────┴──────────────────┘    └─────────────┘
    /// ```
    ///
    /// ### Verification of devices belonging to other users.
    ///
    /// If the device belongs to some other user it will be considered to be
    /// verified if:
    ///
    /// * The device has been signed by the user's self-signing key
    /// * The user's master-signing key has been signed by our own user-signing
    ///   key, i.e. our own identity trusts the other users identity.
    /// * Our own user identity is considered to be [verified]
    ///
    /// ```text
    ///             ┌─────────────────────────────────────┐
    ///             │           Own User Identity         │
    ///             ├──────────────────┬──────────────────┤─────┐
    ///             │    Master Key    │ User-signing Key │     │
    ///             └──────────────────┴──────────────────┘     │
    ///     ┌───────────────────────────────────────────────────┘
    ///     │
    ///     │       ┌─────────────────────────────────────┐    ┌─────────────┐
    ///     │       │             User Identity           │    │   Device    │
    ///     └──────►├──────────────────┬──────────────────┤───►│─────────────│
    ///             │    Master Key    │ Self-signing Key │    │ Device Keys │
    ///             └──────────────────┴──────────────────┘    └─────────────┘
    /// ```
    ///
    /// # Examples
    ///
    /// Let's check if a device is verified:
    ///
    /// ```no_run
    /// # use matrix_sdk::{
    /// #    Client,
    /// #    ruma::{
    /// #        device_id, user_id,
    /// #        events::key::verification::VerificationMethod,
    /// #    }
    /// # };
    /// # use url::Url;
    /// # async {
    /// # let alice = user_id!("@alice:example.org");
    /// # let homeserver = Url::parse("http://example.com")?;
    /// # let client = Client::new(homeserver).await?;
    /// let device =
    ///     client.encryption().get_device(alice, device_id!("DEVICEID")).await?;
    ///
    /// if let Some(device) = device {
    ///     if device.is_verified_with_cross_signing() {
    ///         println!(
    ///             "Device {} of user {} is verified with cross-signing",
    ///             device.device_id(),
    ///             device.user_id()
    ///         );
    ///     } else {
    ///         println!(
    ///             "Device {} of user {} is not verified with cross-signing",
    ///             device.device_id(),
    ///             device.user_id()
    ///         );
    ///     }
    /// }
    /// # anyhow::Ok(()) };
    /// ```
    ///
    /// [`UserIdentity::verify()`]:
    /// crate::encryption::identities::UserIdentity::verify
    /// [verified]: crate::encryption::identities::UserIdentity::is_verified
    pub fn is_verified_with_cross_signing(&self) -> bool {
        self.inner.is_cross_signing_trusted()
    }

    /// Set the local trust state of the device to the given state.
    ///
    /// This won't affect any cross signing verification state, this only sets
    /// a flag marking to have the given trust state.
    ///
    /// # Arguments
    ///
    /// * `trust_state` - The new trust state that should be set for the device.
    pub async fn set_local_trust(&self, trust_state: LocalTrust) -> Result<(), CryptoStoreError> {
        self.inner.set_local_trust(trust_state).await
    }

    /// Is the device cross-signed by its own user.
    pub fn is_cross_signed_by_owner(&self) -> bool {
        self.inner.is_cross_signed_by_owner()
    }
}

/// The collection of all the [`Device`]s a user has.
#[derive(Debug)]
pub struct UserDevices {
    pub(crate) inner: BaseUserDevices,
    pub(crate) client: Client,
}

impl UserDevices {
    /// Get the specific device with the given device ID.
    pub fn get(&self, device_id: &DeviceId) -> Option<Device> {
        self.inner.get(device_id).map(|d| Device { inner: d, client: self.client.clone() })
    }

    /// Iterator over all the device ids of the user devices.
    pub fn keys(&self) -> impl Iterator<Item = &DeviceId> {
        self.inner.keys()
    }

    /// Iterator over all the devices of the user devices.
    pub fn devices(&self) -> impl Iterator<Item = Device> + '_ {
        let client = self.client.clone();

        self.inner.devices().map(move |d| Device { inner: d, client: client.clone() })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn signature_upload_key_mismatch_is_classified() {
        let failure = serde_json::json!({
            "errcode": "M_UNKNOWN",
            "error": "Key does not match"
        });

        assert_eq!(
            super::classify_signature_upload_failure(&failure),
            super::SignatureUploadProcessing::KeyMismatch
        );
    }

    #[test]
    fn signature_upload_response_failures_are_not_treated_as_success() {
        assert!(super::ensure_signature_upload_succeeded(true).is_err());
        assert!(super::ensure_signature_upload_succeeded(false).is_ok());
    }
}
