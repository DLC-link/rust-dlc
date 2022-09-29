use bitcoin::consensus::Decodable;
use bitcoin::{Block, Network, OutPoint, Script, Transaction, TxOut, Txid};
use bitcoin_test_utils::tx_to_string;
use dlc_manager::{error::Error, Blockchain, Utxo};
use reqwest::blocking::Response;
use serde::Deserialize;
use serde::Serialize;

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
