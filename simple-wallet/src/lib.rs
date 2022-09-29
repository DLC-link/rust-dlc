use std::ops::Deref;

use bitcoin::{Address, Network, Txid};
use dlc_manager::{error::Error, Signer, Utxo, Wallet};
use rust_bitcoin_coin_selection::select_coins;
use secp256k1_zkp::{rand::thread_rng, All, PublicKey, Secp256k1, SecretKey};

type Result<T> = core::result::Result<T, Error>;

pub trait WalletBlockchainProvider {
    fn get_utxos_for_address(&self, address: &Address) -> Result<Vec<Utxo>>;
    fn is_output_spent(&self, txid: &Txid, vout: u32) -> Result<bool>;
}

pub trait WalletStorage {
    fn upsert_address(&self, address: &Address, privkey: &SecretKey) -> Result<()>;
    fn delete_address(&self, address: &Address) -> Result<()>;
    fn get_addresses(&self) -> Result<Vec<Address>>;
    fn get_priv_key_for_address(&self, address: &Address) -> Result<Option<SecretKey>>;
    fn upsert_key_pair(&self, public_key: &PublicKey, privkey: &SecretKey) -> Result<()>;
    fn get_priv_key_for_pubkey(&self, public_key: &PublicKey) -> Result<Option<SecretKey>>;
    fn upsert_utxo(&self, utxo: &Utxo) -> Result<()>;
    fn has_utxo(&self, utxo: &Utxo) -> Result<bool>;
    fn delete_utxo(&self, utxo: &Utxo) -> Result<()>;
    fn get_utxos(&self) -> Result<Vec<Utxo>>;
    fn unreserve_utxo(&self, txid: &Txid, vout: u32) -> Result<()>;
}

pub struct SimpleWallet<B: Deref, W: Deref>
where
    B::Target: WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    blockchain: B,
    storage: W,
    secp_ctx: Secp256k1<All>,
    network: Network,
}

impl<B: Deref, W: Deref> SimpleWallet<B, W>
where
    B::Target: WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    pub fn new(blockchain: B, storage: W, network: Network) -> Self {
        Self {
            blockchain,
            storage,
            secp_ctx: Secp256k1::new(),
            network,
        }
    }

    pub fn refresh(&self) -> Result<()> {
        let utxos = self.storage.get_utxos()?;

        for utxo in &utxos {
            let is_spent = self
                .blockchain
                .is_output_spent(&utxo.outpoint.txid, utxo.outpoint.vout)?;
            if is_spent {
                self.storage.delete_utxo(utxo)?;
            }
        }

        let addresses = self.storage.get_addresses()?;

        for address in &addresses {
            let utxos = self.blockchain.get_utxos_for_address(address)?;

            for utxo in &utxos {
                if !self.storage.has_utxo(utxo)? {
                    self.storage.upsert_utxo(utxo)?;
                }
            }
        }

        Ok(())
    }
}

impl<B: Deref, W: Deref> Signer for SimpleWallet<B, W>
where
    B::Target: WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    fn sign_tx_input(
        &self,
        tx: &mut bitcoin::Transaction,
        input_index: usize,
        tx_out: &bitcoin::TxOut,
        _: Option<bitcoin::Script>,
    ) -> Result<()> {
        let address = Address::from_script(&tx_out.script_pubkey, self.network)
            .expect("a valid scriptpubkey");
        let seckey = self
            .storage
            .get_priv_key_for_address(&address)?
            .expect("to have the requested private key");
        dlc::util::sign_p2wpkh_input(
            &self.secp_ctx,
            &seckey,
            tx,
            input_index,
            bitcoin::EcdsaSighashType::All,
            tx_out.value,
        )?;
        Ok(())
    }

    fn get_secret_key_for_pubkey(&self, pubkey: &PublicKey) -> Result<SecretKey> {
        Ok(self
            .storage
            .get_priv_key_for_pubkey(pubkey)?
            .expect("to have the requested private key"))
    }
}

impl<B: Deref, W: Deref> Wallet for SimpleWallet<B, W>
where
    B::Target: WalletBlockchainProvider,
    W::Target: WalletStorage,
{
    fn get_new_address(&self) -> Result<Address> {
        let seckey = SecretKey::new(&mut thread_rng());
        let pubkey = PublicKey::from_secret_key(&self.secp_ctx, &seckey);
        let address = Address::p2wpkh(
            &bitcoin::PublicKey {
                inner: pubkey,
                compressed: true,
            },
            self.network,
        )
        .map_err(|x| Error::WalletError(Box::new(x)))?;
        self.storage.upsert_address(&address, &seckey)?;
        Ok(address)
    }

    fn get_new_secret_key(&self) -> Result<SecretKey> {
        let seckey = SecretKey::new(&mut thread_rng());
        let pubkey = PublicKey::from_secret_key(&self.secp_ctx, &seckey);
        self.storage.upsert_key_pair(&pubkey, &seckey)?;
        Ok(seckey)
    }

    fn get_utxos_for_amount(
        &self,
        amount: u64,
        _: Option<u64>,
        lock_utxos: bool,
    ) -> Result<Vec<Utxo>> {
        let mut utxos = self
            .storage
            .get_utxos()?
            .into_iter()
            .filter(|x| !x.reserved)
            .map(|x| UtxoWrap { utxo: x })
            .collect::<Vec<_>>();
        let selection = select_coins(amount, 20, &mut utxos)
            .ok_or(Error::InvalidState("Not enough fund in utxos".to_string()))?;
        if lock_utxos {
            for utxo in selection.clone() {
                let updated = Utxo {
                    reserved: true,
                    ..utxo.utxo
                };
                self.storage.upsert_utxo(&updated)?;
            }
        }
        Ok(selection.into_iter().map(|x| x.utxo).collect::<Vec<_>>())
    }

    fn import_address(&self, _: &Address) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct UtxoWrap {
    utxo: Utxo,
}

impl rust_bitcoin_coin_selection::Utxo for UtxoWrap {
    fn get_value(&self) -> u64 {
        self.utxo.tx_out.value
    }
}
