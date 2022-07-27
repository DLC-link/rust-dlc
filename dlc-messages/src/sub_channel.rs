//!
//!

use bitcoin::Script;
use secp256k1_zkp::{ecdsa::Signature, EcdsaAdaptorSignature, PublicKey, SecretKey};

use crate::{contract_msgs::ContractInfo, CetAdaptorSignatures};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};

///
pub enum SubChannelMessage {
    ///
    Request(SubChannelOffer),
    ///
    Accept(SubChannelAccept),
    ///
    Confirm(SubChannelConfirm),
    ///
    Finalize(SubChannelFinalize),
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct SubChannelOffer {
    ///
    pub channel_id: [u8; 32],
    /// The base point that will be used by the offer party for revocation.
    pub revocation_basepoint: PublicKey,
    /// The base point that will be used by the offer party for generating
    /// adaptor signatures to revocable transactions.
    pub publish_basepoint: PublicKey,
    /// The base point that will be used by the offer party in the 2 of 2 output
    /// of buffer transactions.
    pub own_basepoint: PublicKey,
    ///
    pub next_per_split_point: PublicKey,
    // TODO(tibo): Channel related fields would be nice in a TLV to separate concerns.
    ///
    pub contract_info: ContractInfo,
    /// The base point that will be used by the offer party for revocation.
    pub channel_revocation_basepoint: PublicKey,
    /// The base point that will be used by the offer party for generating
    /// adaptor signatures to revocable transactions.
    pub channel_publish_basepoint: PublicKey,
    /// The base point that will be used by the offer party in the 2 of 2 output
    /// of buffer transactions.
    pub channel_own_basepoint: PublicKey,
    ///
    pub channel_first_per_update_point: PublicKey,
    /// Script used by the offer party to receive their payout on channel close.
    pub payout_spk: Script,
    /// Serial id used to order outputs.
    pub payout_serial_id: u64,
    /// The collateral input by the offer party in the channel.
    pub offer_collateral: u64,
    /// Lock time for the CETs.
    pub cet_locktime: u32,
    /// Lock time for the refund transaction.
    pub refund_locktime: u32,
    /// The nSequence value to use for the CETs.
    pub cet_nsequence: u32,
    ///
    pub fee_rate_per_vbyte: u64,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
///
pub struct SubChannelInfo {
    ///
    pub sender_satoshi: u64,
    ///
    pub receiver_satoshi: u64,
}

impl_dlc_writeable!(SubChannelInfo, {(sender_satoshi, writeable), (receiver_satoshi, writeable)});

///
pub struct SubChannelAccept {
    ///
    pub channel_id: [u8; 32],
    /// The base point that will be used by the offer party for revocation.
    pub revocation_basepoint: PublicKey,
    /// The base point that will be used by the offer party for generating
    /// adaptor signatures to revocable transactions.
    pub publish_basepoint: PublicKey,
    /// The base point that will be used by the offer party in the 2 of 2 output
    /// of buffer transactions.
    pub own_basepoint: PublicKey,
    ///
    pub split_adaptor_signature: EcdsaAdaptorSignature,
    ///
    pub commit_signature: Signature,
    ///
    pub htlc_signatures: Vec<Signature>,
    ///
    pub first_per_split_point: PublicKey,
    /// The base point that will be used by the offer party for revocation.
    pub channel_revocation_basepoint: PublicKey,
    /// The base point that will be used by the offer party for generating
    /// adaptor signatures to revocable transactions.
    pub channel_publish_basepoint: PublicKey,
    /// The base point that will be used by the offer party in the 2 of 2 output
    /// of buffer transactions.
    pub channel_own_basepoint: PublicKey,
    /// The adaptor signatures for all CETs generated by the accept party.
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    /// The adaptor signature for the buffer transaction generated by the accept
    /// party.
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    /// The refund signature generated by the accept party.
    pub refund_signature: Signature,
    ///
    pub first_per_update_point: PublicKey,
    ///
    pub payout_spk: Script,
    ///
    pub payout_serial_id: u64,
}

///
pub struct SubChannelConfirm {
    ///
    pub channel_id: [u8; 32],
    ///
    pub per_split_secret: SecretKey,
    ///
    pub next_per_commitment_point: PublicKey,
    ///
    pub split_adaptor_signature: EcdsaAdaptorSignature,
    ///
    pub commit_signature: Signature,
    ///
    pub htlc_signatures: Vec<Signature>,
    ///
    pub cet_adaptor_signatures: CetAdaptorSignatures,
    /// The adaptor signature for the buffer transaction generated by the offer
    /// party.
    pub buffer_adaptor_signature: EcdsaAdaptorSignature,
    /// The refund signature generated by the offer party.
    pub refund_signature: Signature,
}

///
pub struct SubChannelFinalize {
    ///
    pub channel_id: [u8; 32],
    ///
    pub per_split_secret: SecretKey,
    ///
    pub next_per_commitment_point: PublicKey,
}
