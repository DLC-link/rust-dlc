//!
use std::sync::{Arc, Mutex};

use bitcoin::Script;
use dlc::channel::RevokeParams;
use lightning::{
    chain::keysinterface::{
        BaseSign, ExtraSign, InMemorySigner, KeyMaterial, KeysInterface, KeysManager, Recipient,
        Sign,
    },
    ln::{
        chan_utils::{ChannelPublicKeys, CustomScript},
        msgs::DecodeError,
        script::ShutdownScript,
    },
    util::ser::Writeable,
};
use secp256k1_zkp::{ecdsa::RecoverableSignature, All, PublicKey, SecretKey};

///
#[derive(Clone)]
pub struct CustomScriptSignInfo {
    ///
    pub offer_revoke_params: RevokeParams,
    ///
    pub accept_revoke_params: RevokeParams,
    ///
    pub own_seckey: SecretKey,
    ///
    pub own_public_key: PublicKey,
    ///
    pub counter_public_key: PublicKey,
    ///
    pub script_pubkey: Script,
    ///
    pub channel_value_satoshis: u64,
}

///
pub struct CustomSigner {
    in_memory_signer: Arc<Mutex<InMemorySigner>>,
    // TODO(tibo): this is not safe.
    channel_public_keys: ChannelPublicKeys,

    custom_script: Arc<Mutex<Option<CustomScript<CustomScriptSignInfo>>>>,
}

impl CustomSigner {
    ///
    pub fn new(in_memory_signer: InMemorySigner) -> Self {
        Self {
            channel_public_keys: in_memory_signer.pubkeys().clone(),
            in_memory_signer: Arc::new(Mutex::new(in_memory_signer)),
            custom_script: Arc::new(Mutex::new(None)),
        }
    }
}

impl Clone for CustomSigner {
    fn clone(&self) -> Self {
        Self {
            in_memory_signer: self.in_memory_signer.clone(),
            channel_public_keys: self.channel_public_keys.clone(),
            custom_script: self.custom_script.clone(),
        }
    }
}

impl BaseSign for CustomSigner {
    fn get_per_commitment_point(
        &self,
        idx: u64,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> secp256k1_zkp::PublicKey {
        self.in_memory_signer
            .lock()
            .unwrap()
            .get_per_commitment_point(idx, secp_ctx)
    }

    fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
        self.in_memory_signer
            .lock()
            .unwrap()
            .release_commitment_secret(idx)
    }

    fn validate_holder_commitment(
        &self,
        holder_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction,
        preimages: Vec<lightning::ln::PaymentPreimage>,
    ) -> Result<(), ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .validate_holder_commitment(holder_tx, preimages)
    }

    fn pubkeys(&self) -> &lightning::ln::chan_utils::ChannelPublicKeys {
        &self.channel_public_keys
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        self.in_memory_signer.lock().unwrap().channel_keys_id()
    }

    fn sign_counterparty_commitment(
        &self,
        commitment_tx: &lightning::ln::chan_utils::CommitmentTransaction,
        preimages: Vec<lightning::ln::PaymentPreimage>,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<
        (
            secp256k1_zkp::ecdsa::Signature,
            Vec<secp256k1_zkp::ecdsa::Signature>,
        ),
        (),
    > {
        let (mut commit_sig, htlc_sigs) = self
            .in_memory_signer
            .lock()
            .unwrap()
            .sign_counterparty_commitment(commitment_tx, preimages, secp_ctx)?;
        if let Some(custom_script) = &*self.custom_script.lock().unwrap() {
            let trusted_tx = commitment_tx.trust();
            let tx = &trusted_tx.built_transaction().transaction;
            commit_sig = dlc::util::get_raw_sig_for_tx_input(
                secp_ctx,
                tx,
                0,
                &custom_script.info.script_pubkey,
                custom_script.info.channel_value_satoshis,
                &custom_script.info.own_seckey,
            )
            .unwrap();
        }

        Ok((commit_sig, htlc_sigs))
    }

    fn validate_counterparty_revocation(
        &self,
        idx: u64,
        secret: &secp256k1_zkp::SecretKey,
    ) -> Result<(), ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .validate_counterparty_revocation(idx, secret)
    }

    fn sign_holder_commitment_and_htlcs(
        &self,
        commitment_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<
        (
            secp256k1_zkp::ecdsa::Signature,
            Vec<secp256k1_zkp::ecdsa::Signature>,
        ),
        (),
    > {
        let (mut commit_sig, htlc_sigs) = self
            .in_memory_signer
            .lock()
            .unwrap()
            .sign_holder_commitment_and_htlcs(commitment_tx, secp_ctx)?;
        if let Some(custom_script) = &*self.custom_script.lock().unwrap() {
            let trusted_tx = commitment_tx.trust();
            let tx = &trusted_tx.built_transaction().transaction;
            commit_sig = dlc::util::get_raw_sig_for_tx_input(
                secp_ctx,
                tx,
                0,
                &custom_script.info.script_pubkey,
                custom_script.info.channel_value_satoshis,
                &custom_script.info.own_seckey,
            )
            .unwrap();
        }

        Ok((commit_sig, htlc_sigs))
    }

    fn sign_justice_revoked_output(
        &self,
        justice_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &secp256k1_zkp::SecretKey,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<secp256k1_zkp::ecdsa::Signature, ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_justice_revoked_output(justice_tx, input, amount, per_commitment_key, secp_ctx)
    }

    fn sign_justice_revoked_htlc(
        &self,
        justice_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &secp256k1_zkp::SecretKey,
        htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<secp256k1_zkp::ecdsa::Signature, ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_justice_revoked_htlc(
                justice_tx,
                input,
                amount,
                per_commitment_key,
                htlc,
                secp_ctx,
            )
    }

    fn sign_counterparty_htlc_transaction(
        &self,
        htlc_tx: &bitcoin::Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &secp256k1_zkp::PublicKey,
        htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<secp256k1_zkp::ecdsa::Signature, ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_counterparty_htlc_transaction(
                htlc_tx,
                input,
                amount,
                per_commitment_point,
                htlc,
                secp_ctx,
            )
    }

    fn sign_closing_transaction(
        &self,
        closing_tx: &lightning::ln::chan_utils::ClosingTransaction,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<secp256k1_zkp::ecdsa::Signature, ()> {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_closing_transaction(closing_tx, secp_ctx)
    }

    fn sign_channel_announcement(
        &self,
        msg: &lightning::ln::msgs::UnsignedChannelAnnouncement,
        secp_ctx: &secp256k1_zkp::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<
        (
            secp256k1_zkp::ecdsa::Signature,
            secp256k1_zkp::ecdsa::Signature,
        ),
        (),
    > {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_channel_announcement(msg, secp_ctx)
    }

    fn ready_channel(
        &mut self,
        channel_parameters: &lightning::ln::chan_utils::ChannelTransactionParameters,
    ) {
        self.in_memory_signer
            .lock()
            .unwrap()
            .ready_channel(channel_parameters)
    }
}

impl ExtraSign for CustomSigner {
    fn sign_with_fund_key_callback<F>(&self, cb: &mut F)
    where
        F: FnMut(&secp256k1_zkp::SecretKey),
    {
        self.in_memory_signer
            .lock()
            .unwrap()
            .sign_with_fund_key_callback(cb)
    }

    fn set_channel_value_satoshis(&mut self, value: u64) {
        self.in_memory_signer
            .lock()
            .unwrap()
            .set_channel_value_satoshis(value)
    }

    fn try_add_sigs(
        &self,
        commitment_tx: bitcoin::Transaction,
        funding_redeem_script: &Script,
        own_signature: &secp256k1_zkp::ecdsa::Signature,
        counter_signature: &secp256k1_zkp::ecdsa::Signature,
    ) -> Option<bitcoin::Transaction> {
        let mut commitment_tx = commitment_tx;
        if let Some(custom_script) = &*self.custom_script.lock().unwrap() {
            dlc::channel::satisfy_buffer_descriptor(
                &mut commitment_tx,
                &custom_script.info.offer_revoke_params,
                &custom_script.info.accept_revoke_params,
                &custom_script.info.own_public_key,
                own_signature,
                &bitcoin::PublicKey {
                    inner: custom_script.info.counter_public_key,
                    compressed: true,
                },
                counter_signature,
            )
            .unwrap();
            Some(commitment_tx)
        } else {
            None
        }
    }

    fn set_custom_script_info(
        &mut self,
        custom_script_info: Option<CustomScript<Self::ScriptInfo>>,
    ) {
        *self.custom_script.lock().unwrap() = custom_script_info;
    }

    fn try_verify_commitment_signature(
        &self,
        commitment_tx: &bitcoin::Transaction,
        signature: &secp256k1_zkp::ecdsa::Signature,
        secp_ctx: &secp256k1_zkp::Secp256k1<All>,
    ) -> Option<Result<(), ()>> {
        if let Some(custom_script) = &*self.custom_script.lock().unwrap() {
            Some(
                dlc::verify_tx_input_sig(
                    secp_ctx,
                    signature,
                    commitment_tx,
                    0,
                    &custom_script.script,
                    custom_script.info.channel_value_satoshis,
                    &custom_script.info.counter_public_key,
                )
                .map_err(|_| ()),
            )
        } else {
            None
        }
    }

    type ScriptInfo = CustomScriptSignInfo;
}

impl Writeable for CustomSigner {
    fn write<W: lightning::util::ser::Writer>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.in_memory_signer.lock().unwrap().write(writer)
    }
}

impl Sign for CustomSigner {}

///
pub struct CustomKeysManager {
    keys_manager: KeysManager,
}

///
impl CustomKeysManager {
    ///
    pub fn new(keys_manager: KeysManager) -> Self {
        Self { keys_manager }
    }
}

impl KeysInterface for CustomKeysManager {
    type Signer = CustomSigner;

    fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
        self.keys_manager.get_node_secret(recipient)
    }

    fn get_inbound_payment_key_material(&self) -> KeyMaterial {
        self.keys_manager.get_inbound_payment_key_material()
    }

    fn get_destination_script(&self) -> Script {
        self.keys_manager.get_destination_script()
    }

    fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
        self.keys_manager.get_shutdown_scriptpubkey()
    }

    fn get_channel_signer(&self, inbound: bool, channel_value_satoshis: u64) -> Self::Signer {
        let in_memory = self
            .keys_manager
            .get_channel_signer(inbound, channel_value_satoshis);
        CustomSigner::new(in_memory)
    }

    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.keys_manager.get_secure_random_bytes()
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
        let in_memory = self.keys_manager.read_chan_signer(reader)?;
        Ok(CustomSigner::new(in_memory))
    }

    fn sign_invoice(
        &self,
        hrp_bytes: &[u8],
        invoice_data: &[bitcoin_bech32::u5],
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        self.keys_manager
            .sign_invoice(hrp_bytes, invoice_data, recipient)
    }
}
