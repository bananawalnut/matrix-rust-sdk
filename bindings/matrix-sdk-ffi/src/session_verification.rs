// Copyright 2025 The Matrix.org Foundation C.I.C.
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
// See the License for that specific language governing permissions and
// limitations under the License.

use std::sync::{
    Arc, Mutex, RwLock, Weak,
    atomic::{AtomicBool, Ordering},
};

use futures_util::StreamExt;
use matrix_sdk::{
    Account,
    encryption::{
        Encryption,
        identities::UserIdentity,
        verification::{
            QrVerification, QrVerificationData, QrVerificationState, SasState, SasVerification,
            VerificationRequest, VerificationRequestState,
        },
    },
    ruma::events::key::verification::VerificationMethod,
};
use matrix_sdk_common::{SendOutsideWasm, SyncOutsideWasm, executor::AbortHandle};
use ruma::UserId;
use tracing::{error, warn};

use crate::{
    client::UserProfile, error::ClientError, runtime::get_runtime_handle, utils::Timestamp,
};

#[derive(uniffi::Object)]
pub struct SessionVerificationEmoji {
    symbol: String,
    description: String,
}

#[matrix_sdk_ffi_macros::export]
impl SessionVerificationEmoji {
    pub fn symbol(&self) -> String {
        self.symbol.clone()
    }

    pub fn description(&self) -> String {
        self.description.clone()
    }
}

#[derive(uniffi::Enum)]
pub enum SessionVerificationData {
    Emojis { emojis: Vec<Arc<SessionVerificationEmoji>>, indices: Vec<u8> },
    Decimals { values: Vec<u16> },
}

#[derive(uniffi::Enum)]
pub enum SessionVerificationQrState {
    Scanned,
    Reciprocated,
    Confirmed,
}

/// Details about the incoming verification request
#[derive(uniffi::Record)]
pub struct SessionVerificationRequestDetails {
    sender_profile: UserProfile,
    flow_id: String,
    device_id: String,
    device_display_name: Option<String>,
    /// First time this device was seen in milliseconds since epoch.
    first_seen_timestamp: Timestamp,
}

#[matrix_sdk_ffi_macros::export(callback_interface)]
pub trait SessionVerificationControllerDelegate: SyncOutsideWasm + SendOutsideWasm {
    fn did_receive_verification_request(&self, details: SessionVerificationRequestDetails);
    fn did_accept_verification_request(&self);
    fn did_start_sas_verification(&self);
    fn did_receive_verification_data(&self, data: SessionVerificationData);
    fn did_update_qr_verification(&self, state: SessionVerificationQrState);
    fn did_fail(&self);
    fn did_cancel(&self);
    fn did_finish(&self);
}

pub type Delegate = Arc<RwLock<Option<Arc<dyn SessionVerificationControllerDelegate>>>>;

#[derive(Default)]
struct ListenerTasks {
    request: Mutex<Option<AbortHandle>>,
    concrete: Mutex<Option<AbortHandle>>,
}

impl ListenerTasks {
    fn replace_request_listener(&self, handle: AbortHandle) {
        if let Some(previous) = self.request.lock().unwrap().replace(handle) {
            previous.abort();
        }
    }

    fn replace_concrete_listener(&self, handle: AbortHandle, abort_request: bool) {
        if let Some(previous) = self.concrete.lock().unwrap().replace(handle) {
            previous.abort();
        }
        if abort_request {
            self.abort_request_listener();
        }
    }

    fn abort_request_listener(&self) {
        if let Some(handle) = self.request.lock().unwrap().take() {
            handle.abort();
        }
    }

    fn abort_concrete_listener(&self) {
        if let Some(handle) = self.concrete.lock().unwrap().take() {
            handle.abort();
        }
    }

    fn abort_all(&self) {
        self.abort_request_listener();
        self.abort_concrete_listener();
    }
}

impl Drop for ListenerTasks {
    fn drop(&mut self) {
        self.abort_all();
    }
}

#[derive(Clone, uniffi::Object)]
pub struct SessionVerificationController {
    encryption: Encryption,
    user_identity: UserIdentity,
    account: Account,
    delegate: Delegate,
    verification_request: Arc<RwLock<Option<VerificationRequest>>>,
    sas_verification: Arc<RwLock<Option<SasVerification>>>,
    qr_verification: Arc<RwLock<Option<QrVerification>>>,
    listener_tasks: Arc<ListenerTasks>,
    locally_starting_sas: Arc<AtomicBool>,
}

#[matrix_sdk_ffi_macros::export]
impl SessionVerificationController {
    pub fn set_delegate(&self, delegate: Option<Box<dyn SessionVerificationControllerDelegate>>) {
        *self.delegate.write().unwrap() = delegate.map(Arc::from);
    }

    /// Set this particular request as the currently active one and register for
    /// events pertaining it.
    /// * `sender_id` - The user requesting verification.
    /// * `flow_id` - - The ID that uniquely identifies the verification flow.
    pub async fn acknowledge_verification_request(
        &self,
        sender_id: String,
        flow_id: String,
    ) -> Result<(), ClientError> {
        let sender_id = UserId::parse(sender_id.clone())?;

        let verification_request = self
            .encryption
            .get_verification_request(&sender_id, flow_id)
            .await
            .ok_or(ClientError::from_str("Unknown session verification request", None))?;

        self.set_ongoing_verification_request(verification_request)
    }

    /// Accept the previously acknowledged verification request
    pub async fn accept_verification_request(&self) -> Result<(), ClientError> {
        let verification_request = self.verification_request.read().unwrap().clone();

        if let Some(verification_request) = verification_request {
            verification_request
                .accept_with_methods(Self::supported_verification_methods())
                .await?;
        }

        Ok(())
    }

    /// Request verification for the current device
    pub async fn request_device_verification(&self) -> Result<(), ClientError> {
        let verification_request = self
            .user_identity
            .request_verification_with_methods(Self::supported_verification_methods())
            .await?;

        self.set_ongoing_verification_request(verification_request)
    }

    /// Request verification for the given user
    pub async fn request_user_verification(&self, user_id: String) -> Result<(), ClientError> {
        let user_id = UserId::parse(user_id)?;

        let user_identity = self
            .encryption
            .get_user_identity(&user_id)
            .await?
            .ok_or(ClientError::from_str("Unknown user identity", None))?;

        if user_identity.is_verified() {
            return Err(ClientError::from_str("User is already verified", None));
        }

        let verification_request = user_identity
            .request_verification_with_methods(Self::supported_verification_methods())
            .await?;

        self.set_ongoing_verification_request(verification_request)
    }

    /// Transition the current verification request into a SAS verification
    /// flow.
    pub async fn start_sas_verification(&self) -> Result<(), ClientError> {
        let verification_request = self.verification_request.read().unwrap().clone();

        let Some(verification_request) = verification_request else {
            return Err(ClientError::from_str("Verification request missing.", None));
        };

        self.locally_starting_sas.store(true, Ordering::Release);
        match verification_request.start_sas().await {
            Ok(Some(_)) => {}
            _ => {
                self.locally_starting_sas.store(false, Ordering::Release);
                if let Some(delegate) = Self::current_delegate(&self.delegate) {
                    delegate.did_fail()
                }
            }
        }

        Ok(())
    }

    /// Generate raw Matrix QR verification bytes for another signed-in device
    /// to scan. These bytes must be encoded directly into a QR image.
    pub async fn generate_qr_verification_code(&self) -> Result<Vec<u8>, ClientError> {
        let verification_request = self.verification_request.read().unwrap().clone();
        let Some(verification_request) = verification_request else {
            return Err(ClientError::from_str("Verification request missing.", None));
        };

        let qr = verification_request
            .generate_qr_code()
            .await?
            .ok_or(ClientError::from_str("QR verification is unavailable.", None))?;
        *self.qr_verification.write().unwrap() = Some(qr.clone());
        let task = get_runtime_handle()
            .spawn(Self::listen_to_qr_verification_changes(qr.clone(), self.delegate.clone()));
        self.listener_tasks.replace_concrete_listener(task.abort_handle(), true);
        let bytes = qr.to_bytes().map_err(|error| {
            ClientError::from_str(format!("Failed encoding QR verification: {error}"), None)
        })?;
        Ok(bytes)
    }

    /// Scan raw Matrix QR verification bytes from another signed-in device.
    pub async fn scan_qr_verification_code(&self, data: Vec<u8>) -> Result<(), ClientError> {
        let verification_request = self.verification_request.read().unwrap().clone();
        let Some(verification_request) = verification_request else {
            return Err(ClientError::from_str("Verification request missing.", None));
        };
        let data = QrVerificationData::from_bytes(data).map_err(|error| {
            ClientError::from_str(format!("Invalid QR verification data: {error}"), None)
        })?;
        *self.qr_verification.write().unwrap() = None;
        self.listener_tasks.abort_concrete_listener();
        self.install_request_listener(verification_request.clone());
        let qr = verification_request
            .scan_qr_code(data)
            .await?
            .ok_or(ClientError::from_str("QR verification is unavailable.", None))?;
        *self.qr_verification.write().unwrap() = Some(qr.clone());
        let task = get_runtime_handle()
            .spawn(Self::listen_to_qr_verification_changes(qr, self.delegate.clone()));
        self.listener_tasks.replace_concrete_listener(task.abort_handle(), true);
        Ok(())
    }

    /// Confirm that the other signed-in device scanned the displayed QR code.
    pub async fn confirm_qr_verification(&self) -> Result<(), ClientError> {
        let qr_verification = self.qr_verification.read().unwrap().clone();
        let Some(qr_verification) = qr_verification else {
            return Err(ClientError::from_str("QR verification missing", None));
        };
        Ok(qr_verification.confirm().await?)
    }

    /// Confirm that the short auth strings match on both sides.
    pub async fn approve_verification(&self) -> Result<(), ClientError> {
        let sas_verification = self.sas_verification.read().unwrap().clone();

        let Some(sas_verification) = sas_verification else {
            return Err(ClientError::from_str("SAS verification missing", None));
        };

        Ok(sas_verification.confirm().await?)
    }

    /// Reject the short auth string
    pub async fn decline_verification(&self) -> Result<(), ClientError> {
        let sas_verification = self.sas_verification.read().unwrap().clone();

        let Some(sas_verification) = sas_verification else {
            return Err(ClientError::from_str("SAS verification missing", None));
        };

        Ok(sas_verification.mismatch().await?)
    }

    /// Cancel the current verification request
    pub async fn cancel_verification(&self) -> Result<(), ClientError> {
        let qr_verification = self.qr_verification.read().unwrap().clone();
        if let Some(qr_verification) = qr_verification {
            return Ok(qr_verification.cancel().await?);
        }
        let verification_request = self.verification_request.read().unwrap().clone();

        let Some(verification_request) = verification_request else {
            return Err(ClientError::from_str("Verification request missing.", None));
        };

        Ok(verification_request.cancel().await?)
    }
}

impl SessionVerificationController {
    fn supported_verification_methods() -> Vec<VerificationMethod> {
        vec![
            VerificationMethod::SasV1,
            VerificationMethod::QrCodeScanV1,
            VerificationMethod::QrCodeShowV1,
            VerificationMethod::ReciprocateV1,
        ]
    }

    pub(crate) fn new(
        encryption: Encryption,
        user_identity: UserIdentity,
        account: Account,
    ) -> Self {
        SessionVerificationController {
            encryption,
            user_identity,
            account,
            delegate: Arc::new(RwLock::new(None)),
            verification_request: Arc::new(RwLock::new(None)),
            sas_verification: Arc::new(RwLock::new(None)),
            qr_verification: Arc::new(RwLock::new(None)),
            listener_tasks: Arc::new(ListenerTasks::default()),
            locally_starting_sas: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Ask the controller to process an incoming request based on the sender
    /// and flow identifier. It will fetch the request, verify that it's in the
    /// correct state and then and notify the delegate.
    pub(crate) async fn process_incoming_verification_request(
        &self,
        sender: &UserId,
        flow_id: impl AsRef<str>,
    ) {
        if sender != self.user_identity.user_id()
            && let Some(status) = self.encryption.cross_signing_status().await
            && !status.is_complete()
        {
            warn!(
                "Cannot verify other users until our own device's cross-signing status \
                 is complete: {status:?}"
            );
            return;
        }

        let Some(request) = self.encryption.get_verification_request(sender, flow_id).await else {
            error!("Failed retrieving verification request");
            return;
        };

        let VerificationRequestState::Requested { other_device_data, .. } = request.state() else {
            error!("Received verification request event but the request is in the wrong state.");
            return;
        };

        let Ok(sender_profile) = UserProfile::fetch(&self.account, sender).await else {
            error!("Failed fetching user profile for verification request");
            return;
        };

        if let Some(delegate) = Self::current_delegate(&self.delegate) {
            delegate.did_receive_verification_request(SessionVerificationRequestDetails {
                sender_profile,
                flow_id: request.flow_id().into(),
                device_id: other_device_data.device_id().into(),
                device_display_name: other_device_data.display_name().map(str::to_owned),
                first_seen_timestamp: other_device_data.first_time_seen_ts().into(),
            });
        }
    }

    fn set_ongoing_verification_request(
        &self,
        verification_request: VerificationRequest,
    ) -> Result<(), ClientError> {
        if let Some(ongoing_verification_request) =
            self.verification_request.read().unwrap().clone()
            && !ongoing_verification_request.is_done()
            && !ongoing_verification_request.is_cancelled()
        {
            return Err(ClientError::from_str("There is another verification flow ongoing.", None));
        }

        *self.verification_request.write().unwrap() = Some(verification_request.clone());
        *self.sas_verification.write().unwrap() = None;
        *self.qr_verification.write().unwrap() = None;
        self.locally_starting_sas.store(false, Ordering::Release);
        self.listener_tasks.abort_all();

        self.install_request_listener(verification_request);

        Ok(())
    }

    fn install_request_listener(&self, verification_request: VerificationRequest) {
        let task = get_runtime_handle().spawn(Self::listen_to_verification_request_changes(
            verification_request,
            self.sas_verification.clone(),
            self.delegate.clone(),
            Arc::downgrade(&self.listener_tasks),
            self.locally_starting_sas.clone(),
        ));
        self.listener_tasks.replace_request_listener(task.abort_handle());
    }

    /// Clone the current delegate out of the lock, releasing the read guard
    /// before it is returned. Callbacks must never be invoked while the guard
    /// is held: a delegate that detaches itself via `set_delegate` (which takes
    /// the write guard) would otherwise deadlock. See issue #6669.
    fn current_delegate(
        delegate: &Delegate,
    ) -> Option<Arc<dyn SessionVerificationControllerDelegate>> {
        delegate.read().unwrap().clone()
    }

    async fn listen_to_verification_request_changes(
        verification_request: VerificationRequest,
        sas_verification: Arc<RwLock<Option<SasVerification>>>,
        delegate: Delegate,
        listener_tasks: Weak<ListenerTasks>,
        locally_starting_sas: Arc<AtomicBool>,
    ) {
        let mut stream = verification_request.changes();

        while let Some(state) = stream.next().await {
            match state {
                VerificationRequestState::Transitioned { verification } => {
                    if verification.clone().qr().is_some() {
                        // QR generate/scan installs a concrete listener after its
                        // fallible continuation succeeds. Until then this request
                        // listener remains the terminal-event fallback.
                        continue;
                    }

                    let Some(verification) = verification.sas() else { continue };
                    *sas_verification.write().unwrap() = Some(verification.clone());

                    let Some(listener_tasks) = listener_tasks.upgrade() else { break };
                    let task =
                        get_runtime_handle().spawn(Self::listen_to_sas_verification_changes(
                            verification.clone(),
                            delegate.clone(),
                        ));
                    listener_tasks.replace_concrete_listener(task.abort_handle(), false);

                    let locally_started = locally_starting_sas.swap(false, Ordering::AcqRel);
                    if !locally_started && verification.accept().await.is_err() {
                        if let Some(current_delegate) = Self::current_delegate(&delegate) {
                            current_delegate.did_fail()
                        }
                        break;
                    }
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_start_sas_verification()
                    }

                    // The concrete SAS listener was installed before the only
                    // fallible handoff, so it now owns terminal events.
                    break;
                }
                VerificationRequestState::Ready { .. } => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_accept_verification_request()
                    }
                }
                VerificationRequestState::Done => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_finish();
                    }
                    break;
                }
                VerificationRequestState::Cancelled(..) => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_cancel();
                    }
                    break;
                }
                _ => {}
            }
        }
    }

    async fn listen_to_sas_verification_changes(sas: SasVerification, delegate: Delegate) {
        let mut stream = sas.changes();

        while let Some(state) = stream.next().await {
            match state {
                SasState::KeysExchanged { emojis, decimals } => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        if let Some(emojis) = emojis {
                            current_delegate.did_receive_verification_data(
                                SessionVerificationData::Emojis {
                                    emojis: emojis
                                        .emojis
                                        .into_iter()
                                        .map(|emoji| {
                                            Arc::new(SessionVerificationEmoji {
                                                symbol: emoji.symbol.to_owned(),
                                                description: emoji.description.to_owned(),
                                            })
                                        })
                                        .collect(),
                                    indices: emojis.indices.to_vec(),
                                },
                            );
                        } else {
                            current_delegate.did_receive_verification_data(
                                SessionVerificationData::Decimals {
                                    values: vec![decimals.0, decimals.1, decimals.2],
                                },
                            )
                        }
                    }
                }
                SasState::Done { .. } => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_finish()
                    }
                    break;
                }
                SasState::Cancelled(_cancel_info) => {
                    // TODO: The cancel_info is usable, we should tell the user why we were
                    // cancelled.
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_cancel()
                    }
                    break;
                }
                SasState::Created { .. }
                | SasState::Started { .. }
                | SasState::Accepted { .. }
                | SasState::Confirmed => (),
            }
        }
    }

    async fn listen_to_qr_verification_changes(qr: QrVerification, delegate: Delegate) {
        let mut stream = qr.changes();
        while let Some(state) = stream.next().await {
            let update = match state {
                QrVerificationState::Scanned => Some(SessionVerificationQrState::Scanned),
                QrVerificationState::Reciprocated => Some(SessionVerificationQrState::Reciprocated),
                QrVerificationState::Confirmed => Some(SessionVerificationQrState::Confirmed),
                QrVerificationState::Done { .. } => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_finish();
                    }
                    break;
                }
                QrVerificationState::Cancelled(_) => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_cancel();
                    }
                    break;
                }
                QrVerificationState::Started => None,
            };
            if let Some(update) = update
                && let Some(current_delegate) = Self::current_delegate(&delegate)
            {
                current_delegate.did_update_qr_verification(update);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use matrix_sdk::ruma::events::key::verification::VerificationMethod;

    use super::{
        Delegate, ListenerTasks, SessionVerificationController,
        SessionVerificationControllerDelegate, SessionVerificationData, SessionVerificationQrState,
        SessionVerificationRequestDetails,
    };

    #[test]
    fn advertises_post_login_qr_and_sas_methods() {
        assert_eq!(
            SessionVerificationController::supported_verification_methods(),
            vec![
                VerificationMethod::SasV1,
                VerificationMethod::QrCodeScanV1,
                VerificationMethod::QrCodeShowV1,
                VerificationMethod::ReciprocateV1,
            ]
        );
    }

    /// A delegate that detaches itself from within a callback. The only
    /// documented way to detach is `set_delegate(None)`, which takes the
    /// delegate write guard. Mirrors the deadlock repro from issue #6669.
    struct ReentrantDelegate {
        slot: Delegate,
    }

    impl SessionVerificationControllerDelegate for ReentrantDelegate {
        fn did_cancel(&self) {
            *self.slot.write().unwrap() = None;
        }
        fn did_receive_verification_request(&self, _: SessionVerificationRequestDetails) {}
        fn did_accept_verification_request(&self) {}
        fn did_start_sas_verification(&self) {}
        fn did_receive_verification_data(&self, _: SessionVerificationData) {}
        fn did_update_qr_verification(&self, _: SessionVerificationQrState) {}
        fn did_fail(&self) {}
        fn did_finish(&self) {}
    }

    #[test]
    fn invoking_a_callback_does_not_hold_the_delegate_read_guard() {
        let slot: Delegate = Arc::new(RwLock::new(None));
        *slot.write().unwrap() = Some(Arc::new(ReentrantDelegate { slot: slot.clone() }));

        // `current_delegate` must release the read guard before the callback
        // runs. If it held the guard, the re-entrant `set_delegate` (write
        // guard) inside `did_cancel` would deadlock here.
        if let Some(delegate) = SessionVerificationController::current_delegate(&slot) {
            delegate.did_cancel();
        }

        assert!(slot.read().unwrap().is_none(), "delegate should have detached itself");
    }

    fn source_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let start = source.find(start).expect("start marker must exist");
        let remainder = &source[start..];
        let end = remainder.find(end).expect("end marker must exist after start");
        &remainder[..end]
    }

    #[test]
    fn request_listener_transfers_terminal_ownership_when_sas_transitions() {
        let source = include_str!("session_verification.rs");
        let transitioned = source_section(
            source,
            "VerificationRequestState::Transitioned { verification } =>",
            "VerificationRequestState::Ready { .. } =>",
        );

        assert!(transitioned.contains("replace_concrete_listener"));
        assert!(transitioned.contains("break;"), "SAS transition must stop the request listener");
    }

    #[test]
    fn request_listener_stops_after_direct_terminal_events() {
        let source = include_str!("session_verification.rs");
        let done = source_section(
            source,
            "VerificationRequestState::Done =>",
            "VerificationRequestState::Cancelled(..) =>",
        );
        let cancelled =
            source_section(source, "VerificationRequestState::Cancelled(..) =>", "_ => {}");

        assert!(done.contains("did_finish()"));
        assert!(done.contains("break;"));
        assert!(cancelled.contains("did_cancel()"));
        assert!(cancelled.contains("break;"));
    }

    #[test]
    fn locally_started_sas_has_only_the_request_listener_as_owner() {
        let source = include_str!("session_verification.rs");
        let start_sas = source_section(
            source,
            "pub async fn start_sas_verification",
            "pub async fn generate_qr_verification_code",
        );

        assert!(!start_sas.contains("listen_to_sas_verification_changes"));
        assert!(!start_sas.contains("did_start_sas_verification"));
    }

    #[test]
    fn qr_replacement_uses_one_cancellable_concrete_listener() {
        let source = include_str!("session_verification.rs");
        let generate = source_section(
            source,
            "pub async fn generate_qr_verification_code",
            "pub async fn scan_qr_verification_code",
        );
        let scan = source_section(
            source,
            "pub async fn scan_qr_verification_code",
            "pub async fn confirm_qr_verification",
        );

        assert!(generate.contains("replace_concrete_listener"));
        assert!(scan.contains("replace_concrete_listener"));
        assert!(scan.contains("abort_concrete_listener"));
        assert!(scan.contains("install_request_listener"));
        assert!(generate.contains("task.abort_handle()"));
        assert!(scan.contains("task.abort_handle()"));
        assert!(
            scan.find("install_request_listener") < scan.find(".scan_qr_code(data)"),
            "request fallback must be restored before fallible QR reciprocation"
        );
    }

    #[test]
    fn qr_transition_keeps_request_fallback_until_concrete_listener_is_installed() {
        let source = include_str!("session_verification.rs");
        let transitioned = source_section(
            source,
            "VerificationRequestState::Transitioned { verification } =>",
            "VerificationRequestState::Ready { .. } =>",
        );

        assert!(transitioned.contains(".qr().is_some()"));
        assert!(transitioned.contains("continue;"));
        assert!(transitioned.contains("replace_concrete_listener"));
        assert!(
            transitioned.find("replace_concrete_listener") < transitioned.find(".accept().await"),
            "incoming SAS must install terminal observation before its fallible accept"
        );
    }

    #[tokio::test]
    async fn replacing_concrete_listener_cancels_previous_task() {
        let tasks = ListenerTasks::default();
        let first = tokio::spawn(std::future::pending::<()>());
        tasks.replace_concrete_listener(first.abort_handle(), false);

        let second = tokio::spawn(std::future::pending::<()>());
        tasks.replace_concrete_listener(second.abort_handle(), false);

        assert!(first.await.expect_err("replaced listener must be cancelled").is_cancelled());
        tasks.abort_all();
        assert!(second.await.expect_err("active listener must be drained").is_cancelled());
    }

    #[tokio::test]
    async fn concrete_handoff_cancels_request_fallback() {
        let tasks = ListenerTasks::default();
        let request = tokio::spawn(std::future::pending::<()>());
        tasks.replace_request_listener(request.abort_handle());

        let concrete = tokio::spawn(std::future::pending::<()>());
        tasks.replace_concrete_listener(concrete.abort_handle(), true);

        assert!(request.await.expect_err("request fallback must be cancelled").is_cancelled());
        tasks.abort_all();
        assert!(concrete.await.expect_err("concrete listener must be drained").is_cancelled());
    }

    #[tokio::test]
    async fn dropping_final_task_owner_cancels_all_listeners() {
        let tasks = Arc::new(ListenerTasks::default());
        let weak_tasks = Arc::downgrade(&tasks);
        let request = tokio::spawn(std::future::pending::<()>());
        let concrete = tokio::spawn(std::future::pending::<()>());
        tasks.replace_request_listener(request.abort_handle());
        tasks.replace_concrete_listener(concrete.abort_handle(), false);

        drop(tasks);

        assert!(weak_tasks.upgrade().is_none());
        assert!(request.await.expect_err("request listener must be drained").is_cancelled());
        assert!(concrete.await.expect_err("concrete listener must be drained").is_cancelled());
    }
}
