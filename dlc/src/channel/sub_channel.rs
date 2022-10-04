//!
//!

use bitcoin::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};
use miniscript::DescriptorTrait;

use crate::{channel::buffer_descriptor, util::ENABLE_LOCKTIME};

use super::{RevokeParams, BUFFER_TX_WEIGHT};

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

/**
 * Weight of the ln glue transaction is the same as the buffer transaction.
*/
pub const LN_GLUE_TX_WEIGHT: usize = BUFFER_TX_WEIGHT;

#[derive(Clone, Debug)]
///
pub struct SplitTx {
    ///
    pub transaction: Transaction,
    ///
    pub output_script: Script,
}

///
pub fn create_split_tx(
    offer_revoke_params: &RevokeParams,
    accept_revoke_params: &RevokeParams,
    fund_tx_outpoint: &OutPoint,
    output_values: &[u64],
) -> SplitTx {
    let output_desc = buffer_descriptor(offer_revoke_params, accept_revoke_params);

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
pub fn create_ln_glue_tx(
    split_tx_outpoint: &OutPoint,
    ln_fund_script: &Script,
    lock_time: u32,
    output_value: u64,
) -> Transaction {
    Transaction {
        version: 2,
        lock_time,
        input: {
            vec![TxIn {
                previous_output: split_tx_outpoint.clone(),
                script_sig: Script::default(),
                sequence: ENABLE_LOCKTIME,
                witness: Witness::default(),
            }]
        },
        output: vec![TxOut {
            value: output_value,
            script_pubkey: ln_fund_script.to_v0_p2wsh(),
        }],
    }
}
