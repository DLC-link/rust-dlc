use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::hex::FromHex;
use bitcoin::util::uint::Uint256;
use bitcoin::{Block, BlockHash, BlockHeader, Network, OutPoint, Script, Transaction, TxOut, Txid};
use bitcoin_test_utils::tx_to_string;
use dlc_manager::{error::Error, Blockchain, Utxo};
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning_block_sync::{BlockHeaderData, BlockSource, BlockSourceError};
use reqwest::blocking::Response;
use serde::Deserialize;
use serde::Serialize;

const MIN_FEERATE: u32 = 253;

pub struct ElectrsBlockchainProvider {
    host: String,
    client: reqwest::blocking::Client,
    network: Network,
}

impl ElectrsBlockchainProvider {
    pub fn new(host: String, network: Network) -> Self {
        Self {
            host,
            network,
            client: reqwest::blocking::Client::new(),
        }
    }

    fn get(&self, sub_url: &str) -> Result<Response, Error> {
        self.client
            .get(format!("{}{}", self.host, sub_url))
            .send()
            .map_err(|x| {
                dlc_manager::error::Error::IOError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    x,
                ))
            })
    }

    async fn get_async(&self, sub_url: &str) -> Result<reqwest::Response, reqwest::Error> {
        reqwest::get(format!("{}{}", self.host, sub_url)).await
    }

    fn get_text(&self, sub_url: &str) -> Result<String, Error> {
        self.get(sub_url)?.text().map_err(|x| {
            dlc_manager::error::Error::IOError(std::io::Error::new(std::io::ErrorKind::Other, x))
        })
    }

    fn get_u64(&self, sub_url: &str) -> Result<u64, Error> {
        self.get_text(sub_url)?
            .parse()
            .map_err(|_| Error::BlockchainError)
    }

    fn get_bytes(&self, sub_url: &str) -> Result<Vec<u8>, Error> {
        let bytes = self.get(sub_url)?.bytes();
        Ok(bytes
            .map_err(|_| Error::BlockchainError)?
            .into_iter()
            .collect::<Vec<_>>())
    }

    fn get_from_json<T>(&self, sub_url: &str) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        self.get(sub_url)?
            .json::<T>()
            .map_err(|_| Error::BlockchainError)
    }
}

impl Blockchain for ElectrsBlockchainProvider {
    fn send_transaction(&self, transaction: &Transaction) -> Result<(), dlc_manager::error::Error> {
        self.client
            .post(format!("{}tx", self.host))
            .body(tx_to_string(transaction))
            .send()
            .map_err(|x| {
                dlc_manager::error::Error::IOError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    x,
                ))
            })?;
        Ok(())
    }

    fn get_network(
        &self,
    ) -> Result<bitcoin::network::constants::Network, dlc_manager::error::Error> {
        Ok(self.network)
    }

    fn get_blockchain_height(&self) -> Result<u64, dlc_manager::error::Error> {
        Ok(self.get_u64("blocks/tip/height")?)
    }

    fn get_block_at_height(&self, height: u64) -> Result<Block, dlc_manager::error::Error> {
        let hash_at_height = self.get_text(&format!("block-height/{}", height))?;
        let raw_block = self.get_bytes(&format!("block/{}/raw", hash_at_height))?;
        Block::consensus_decode(&*raw_block).map_err(|_| Error::BlockchainError)
    }

    fn get_transaction(&self, tx_id: &Txid) -> Result<Transaction, dlc_manager::error::Error> {
        let raw_tx = self.get_bytes(&format!("tx/{}/raw", tx_id))?;
        Transaction::consensus_decode(&*raw_tx).map_err(|_| Error::BlockchainError)
    }

    fn get_transaction_confirmations(
        &self,
        tx_id: &Txid,
    ) -> Result<u32, dlc_manager::error::Error> {
        let tx_status = self.get_from_json::<TxStatus>(&format!("tx/{}/status", tx_id))?;
        if tx_status.confirmed {
            let block_chain_height = self.get_blockchain_height()?;
            if let Some(block_height) = tx_status.block_height {
                return Ok((block_chain_height - block_height + 1) as u32);
            }
        }

        return Ok(0);
    }
}

impl simple_wallet::WalletBlockchainProvider for ElectrsBlockchainProvider {
    fn get_utxos_for_address(&self, address: &bitcoin::Address) -> Result<Vec<Utxo>, Error> {
        let utxos: Vec<UtxoResp> =
            self.get_from_json(&format!("address/{}/utxo", address.to_string()))?;

        Ok(utxos
            .into_iter()
            .map(|x| {
                Ok(Utxo {
                    address: address.clone(),
                    outpoint: OutPoint {
                        txid: x.txid.parse().map_err(|_| Error::BlockchainError)?,
                        vout: x.vout,
                    },
                    redeem_script: Script::default(),
                    reserved: false,
                    tx_out: TxOut {
                        value: x.value,
                        script_pubkey: address.script_pubkey(),
                    },
                })
            })
            .collect::<Result<Vec<_>, Error>>()?)
    }

    fn is_output_spent(&self, txid: &Txid, vout: u32) -> Result<bool, Error> {
        let is_spent: SpentResp = self.get_from_json(&format!("tx/{}/outspend/{}", txid, vout))?;
        Ok(is_spent.status)
    }
}

impl FeeEstimator for ElectrsBlockchainProvider {
    fn get_est_sat_per_1000_weight(
        &self,
        confirmation_target: lightning::chain::chaininterface::ConfirmationTarget,
    ) -> u32 {
        let fee_rate_per_vb_opt = match self.get_from_json::<FeeEstimates>("fee-estimates") {
            Ok(fee_estimates) => match confirmation_target {
                lightning::chain::chaininterface::ConfirmationTarget::Background => {
                    fee_estimates.get(&144).cloned()
                }
                lightning::chain::chaininterface::ConfirmationTarget::Normal => {
                    fee_estimates.get(&18).cloned()
                }

                lightning::chain::chaininterface::ConfirmationTarget::HighPriority => {
                    fee_estimates.get(&6).cloned()
                }
            },
            Err(_) => {
                //TODO(tibo): return a default value or save previous ones.
                panic!("Could not get fee estimate");
            }
        };
        if let Some(fee_rate_per_vb) = fee_rate_per_vb_opt {
            fee_rate_per_vb.ceil() as u32 * 1000 / 4
        } else {
            MIN_FEERATE
        }
    }
}

impl BlockSource for ElectrsBlockchainProvider {
    fn get_header<'a>(
        &'a self,
        header_hash: &'a bitcoin::BlockHash,
        _: Option<u32>,
    ) -> lightning_block_sync::AsyncBlockSourceResult<'a, lightning_block_sync::BlockHeaderData>
    {
        Box::pin(async move {
            let block_info: BlockInfo = self
                .get_async(&format!("block/{:x}", header_hash))
                .await
                .map_err(|e| BlockSourceError::transient(e))?
                .json()
                .await
                .map_err(|e| BlockSourceError::transient(e))?;
            let header_hex = self
                .get_async(&format!("block/{:x}/header", header_hash))
                .await
                .map_err(|e| BlockSourceError::transient(e))?
                .bytes()
                .await
                .map_err(|e| BlockSourceError::transient(e))?;
            let header =
                BlockHeader::consensus_decode(&*header_hex).expect("to have a valid header");
            Ok(BlockHeaderData {
                header,
                height: block_info.height,
                // Electrs doesn't seem to make this available.
                chainwork: Uint256::from_u64(10).unwrap(),
            })
        })
    }

    fn get_block<'a>(
        &'a self,
        header_hash: &'a bitcoin::BlockHash,
    ) -> lightning_block_sync::AsyncBlockSourceResult<'a, Block> {
        Box::pin(async move {
            let block_raw = self
                .get_async(&format!("block/{:x}/raw", header_hash))
                .await
                .map_err(|e| BlockSourceError::transient(e))?
                .bytes()
                .await
                .map_err(|e| BlockSourceError::transient(e))?;
            let block = Block::consensus_decode(&*block_raw).expect("to have a valid header");
            Ok(block)
        })
    }

    fn get_best_block<'a>(
        &'a self,
    ) -> lightning_block_sync::AsyncBlockSourceResult<(bitcoin::BlockHash, Option<u32>)> {
        Box::pin(async move {
            let block_tip_hash: String = self
                .get_async("blocks/tip/hash")
                .await
                .map_err(|e| BlockSourceError::transient(e))?
                .text()
                .await
                .map_err(|e| BlockSourceError::transient(e))?;
            Ok((
                BlockHash::from_hex(&block_tip_hash).map_err(|e| BlockSourceError::transient(e))?,
                None,
            ))
        })
    }
}

impl BroadcasterInterface for ElectrsBlockchainProvider {
    fn broadcast_transaction(&self, tx: &Transaction) {
        self.client
            .post(&format!("{}tx", self.host))
            .body(bitcoin_test_utils::tx_to_string(tx))
            .send()
            .unwrap();
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TxStatus {
    confirmed: bool,
    block_height: Option<u64>,
    block_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct UtxoResp {
    txid: String,
    vout: u32,
    value: u64,
    status: UtxoStatus,
}

#[derive(Serialize, Deserialize, Debug)]
struct UtxoStatus {
    confirmed: bool,
    block_height: u64,
    block_hash: String,
    block_time: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct SpentResp {
    status: bool,
}

type FeeEstimates = std::collections::HashMap<u16, f32>;

#[derive(Serialize, Deserialize, Debug)]
struct BlockInfo {
    height: u32,
}
