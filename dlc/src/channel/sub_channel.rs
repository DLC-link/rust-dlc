//!
//!

use std::collections::HashMap;

use bitcoin::{EcdsaSig, OutPoint, PublicKey, Script, Transaction, TxIn, TxOut, Witness};
use miniscript::{miniscript::satisfy::Older, Descriptor, DescriptorTrait, Satisfier};
use secp256k1_zkp::{ecdsa::Signature, PublicKey as SecpPublicKey};

use crate::Error;

use super::RevokeParams;

/**
 * Weight of the split transaction:
 * INPUT
 * Overhead -> 10.5 * 4
 * Outpoint -> 36 * 4
 * scriptSigLength -> 1 * 4
 * scriptSig -> 0
 * nSequence -> 4 * 4
 * Witness item count -> 1
 * Witness -> 220
 * OUTPUT (x2):
 *      nValue -> 8 * 4
 *      scriptPubkeyLen -> 1 * 4
 *      scriptPubkey -> 34 * 4
 * TOTAL: 771
*/
pub const SPLIT_TX_WEIGHT: usize = 771;

#[derive(Clone, Debug)]
///
pub struct SplitTx {
    ///
    pub transaction: Transaction,
    ///
    pub output_script: Script,
}

struct SplitTxSatisfier {
    sigs: HashMap<bitcoin::PublicKey, miniscript::bitcoin::EcdsaSig>,
    older: Older,
}

impl Satisfier<bitcoin::PublicKey> for SplitTxSatisfier {
    fn lookup_ecdsa_sig(&self, key: &PublicKey) -> Option<bitcoin::EcdsaSig> {
        self.sigs.get(key).map(|x| *x)
    }

    fn check_older(&self, sequence: u32) -> bool {
        <dyn Satisfier<PublicKey>>::check_older(&self.older, sequence)
    }
}

/// Returns a descriptor for a buffer transaction.
pub fn split_descriptor(
    offer_revoke_params: &RevokeParams,
    accept_revoke_params: &RevokeParams,
    csv_timelock: u32,
) -> Descriptor<PublicKey> {
    let (offer_pkh, offer_publish_pkh, offer_revoke_pkh) = offer_revoke_params.get_pubkey_hashes();
    let (accept_pkh, accept_publish_pkh, accept_revoke_pkh) =
        accept_revoke_params.get_pubkey_hashes();

    let offer_pk = offer_revoke_params.own_pk;
    let accept_pk = accept_revoke_params.own_pk;

    let (first_pk, second_pk) = if offer_pk < accept_pk {
        (offer_pk, accept_pk)
    } else {
        (accept_pk, offer_pk)
    };

    println!("first_pk: {}, second_pk: {}", first_pk, second_pk);
    // heavily inspired by: https://github.com/comit-network/maia/blob/main/src/protocol.rs#L283
    // policy: or(and(and(pk(offer_pk),pk(accept_pk)), older(csv_timelock)),or(and(pk(offer_pk),and(pk(accept_publish_pk),pk(accept_rev_pk))),and(pk(accept_pk),and(pk(offer_publish_pk),pk(offer_rev_pk)))))
    let script = format!("wsh(or_i(and_v(and_v(v:pk({first_pk}),v:pk({second_pk})),older({csv_timelock})),c:or_i(and_v(v:pkh({offer_pk_hash}),and_v(v:pkh({accept_publish_pk_hash}),pk_h({accept_revoke_pk_hash}))),and_v(v:pkh({accept_pk_hash}),and_v(v:pkh({offer_publish_pk_hash}),pk_h({offer_revoke_pk_hash}))))))",
        first_pk = first_pk,
        second_pk = second_pk,
        csv_timelock = csv_timelock,
        offer_pk_hash = offer_pkh,
        accept_pk_hash = accept_pkh,
        accept_publish_pk_hash = accept_publish_pkh,
        accept_revoke_pk_hash = accept_revoke_pkh,
        offer_publish_pk_hash = offer_publish_pkh,
        offer_revoke_pk_hash = offer_revoke_pkh);
    script.parse().expect("a valid miniscript")
}

///
pub fn create_split_tx(
    offer_revoke_params: &RevokeParams,
    accept_revoke_params: &RevokeParams,
    fund_tx_outpoint: &OutPoint,
    output_values: &[u64],
    csv_timelock: u32,
) -> SplitTx {
    let output_desc = split_descriptor(offer_revoke_params, accept_revoke_params, csv_timelock);
    println!("SCRIPT CODE: {:?}", output_desc.script_code());

    let output = output_values
        .iter()
        .map(|value| TxOut {
            value: *value,
            script_pubkey: output_desc.script_pubkey(),
        })
        .collect::<Vec<_>>();

    SplitTx {
        transaction: Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: fund_tx_outpoint.clone(),
                script_sig: Script::default(),
                sequence: 0,
                witness: Witness::default(),
            }],
            output,
        },
        output_script: output_desc.script_code().unwrap(),
    }
}

///
pub fn satisfy_split_descriptor(
    tx: &mut Transaction,
    offer_params: &RevokeParams,
    accept_params: &RevokeParams,
    own_pubkey: &SecpPublicKey,
    own_signature: &Signature,
    counter_pubkey: &PublicKey,
    counter_signature: &Signature,
    csv_timelock: u32,
) -> Result<(), Error> {
    let descriptor = split_descriptor(offer_params, accept_params, csv_timelock);
    println!("Own pk {}, Counter pk: {}", own_pubkey, counter_pubkey);
    let sigs = HashMap::from([
        (
            PublicKey {
                inner: *own_pubkey,
                compressed: true,
            },
            EcdsaSig::sighash_all(*own_signature),
        ),
        (*counter_pubkey, EcdsaSig::sighash_all(*counter_signature)),
    ]);

    let satisfier = SplitTxSatisfier {
        sigs,
        older: Older(csv_timelock),
    };

    descriptor
        .satisfy(&mut tx.input[0], &satisfier)
        .map_err(|e| {
            println!("{}", e);
            Error::InvalidArgument
        })?;

    Ok(())
}
