//! # dlc-sled-storage-provider
//! Storage provider for dlc-manager using sled as underlying storage.

#![crate_name = "dlc_sled_storage_provider"]
// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

extern crate dlc_manager;
extern crate sled;

use dlc_manager::chain_monitor::ChainMonitor;
use dlc_manager::channel::accepted_channel::AcceptedChannel;
use dlc_manager::channel::offered_channel::OfferedChannel;
use dlc_manager::channel::signed_channel::{SignedChannel, SignedChannelStateType};
use dlc_manager::channel::{Channel, FailedAccept, FailedSign};
use dlc_manager::contract::accepted_contract::AcceptedContract;
use dlc_manager::contract::offered_contract::OfferedContract;
use dlc_manager::contract::ser::Serializable;
use dlc_manager::contract::signed_contract::SignedContract;
use dlc_manager::contract::{ClosedContract, Contract, FailedAcceptContract, FailedSignContract};
use dlc_manager::sub_channel_manager::{
    AcceptedSubChannel, OfferedSubChannel, SignedSubChannel, SubChannel, SubChannelStorage,
};
use dlc_manager::{error::Error, ContractId, Storage};
use sled::transaction::{ConflictableTransactionResult, UnabortableTransactionError};
use sled::{Db, Transactional, Tree};
use std::convert::TryInto;
use std::io::{Cursor, Read};

const CONTRACT_TREE: u8 = 1;
const CHANNEL_TREE: u8 = 2;
const SUB_CHANNEL_TREE: u8 = 3;
const CHAIN_MONITOR_TREE: u8 = 4;
const CHAIN_MONITOR_KEY: u8 = 5;

/// Implementation of Storage interface using the sled DB backend.
pub struct SledStorageProvider {
    db: Db,
}

macro_rules! convertible_enum {
    (enum $name:ident {
        $($vname:ident $(= $val:expr)?,)*;
        $($tname:ident $(= $tval:expr)?,)*
    }, $input:ident) => {
        #[derive(Debug)]
        enum $name {
            $($vname $(= $val)?,)*
            $($tname $(= $tval)?,)*
        }

        impl From<$name> for u8 {
            fn from(prefix: $name) -> u8 {
                prefix as u8
            }
        }

        impl std::convert::TryFrom<u8> for $name {
            type Error = Error;

            fn try_from(v: u8) -> Result<Self, Self::Error> {
                match v {
                    $(x if x == u8::from($name::$vname) => Ok($name::$vname),)*
                    $(x if x == u8::from($name::$tname) => Ok($name::$tname),)*
                    _ => Err(Error::StorageError("Unknown prefix".to_string())),
                }
            }
        }

        impl $name {
            fn get_prefix(input: &$input) -> u8 {
                let prefix = match input {
                    $($input::$vname(_) => $name::$vname,)*
                    $($input::$tname{..} => $name::$tname,)*
                };
                prefix.into()
            }
        }
    }
}

convertible_enum!(
    enum ContractPrefix {
        Offered = 1,
        Accepted,
        Signed,
        Confirmed,
        Closed,
        FailedAccept,
        FailedSign,
        Refunded,
        Rejected,;
    },
    Contract
);

convertible_enum!(
    enum ChannelPrefix {
        Offered = 100,
        Accepted,
        Signed,
        FailedAccept,
        FailedSign,;
    },
    Channel
);

convertible_enum!(
    enum SignedChannelPrefix {;
        Established = 1,
        SettledOffered,
        SettledReceived,
        SettledAccepted,
        SettledConfirmed,
        Settled,
        Closing,
        Closed,
        CounterClosed,
        ClosedPunished,
        CollaborativeCloseOffered,
        CollaborativelyClosed,
        RenewAccepted,
        RenewOffered,
        RenewConfirmed,
    },
    SignedChannelStateType
);

convertible_enum!(
    enum SubChannelPrefix {;
        Offered = 500,
        Accepted,
        Signed,
    },
    SubChannel
);

fn to_storage_error<T>(e: T) -> Error
where
    T: std::fmt::Display,
{
    Error::StorageError(e.to_string())
}

impl SledStorageProvider {
    /// Creates a new instance of a SledStorageProvider.
    pub fn new(path: &str) -> Result<Self, sled::Error> {
        Ok(SledStorageProvider {
            db: sled::open(path)?,
        })
    }

    fn get_data_with_prefix<T: Serializable>(
        &self,
        tree: &Tree,
        prefix: &[u8],
        consume: Option<u64>,
    ) -> Result<Vec<T>, Error> {
        let iter = tree.iter();
        iter.values()
            .filter_map(|res| {
                let value = res.unwrap();
                let mut cursor = Cursor::new(&value);
                let mut pref = vec![0u8; prefix.len()];
                cursor.read_exact(&mut pref).expect("Error reading prefix");
                if pref == prefix {
                    if let Some(c) = consume {
                        cursor.set_position(cursor.position() + c);
                    }
                    Some(Ok(T::deserialize(&mut cursor).ok()?))
                } else {
                    None
                }
            })
            .collect()
    }

    fn open_tree(&self, tree_id: &[u8; 1]) -> Result<Tree, Error> {
        self.db
            .open_tree(tree_id)
            .map_err(|e| Error::StorageError(format!("Error opening contract tree: {}", e)))
    }

    fn contract_tree(&self) -> Result<Tree, Error> {
        self.open_tree(&[CONTRACT_TREE])
    }

    fn channel_tree(&self) -> Result<Tree, Error> {
        self.open_tree(&[CHANNEL_TREE])
    }

    fn sub_channel_tree(&self) -> Result<Tree, Error> {
        self.open_tree(&[SUB_CHANNEL_TREE])
    }
}

impl Storage for SledStorageProvider {
    fn get_contract(&self, contract_id: &ContractId) -> Result<Option<Contract>, Error> {
        match self
            .contract_tree()?
            .get(contract_id)
            .map_err(to_storage_error)?
        {
            Some(res) => Ok(Some(contract::deserialize(&res)?)),
            None => Ok(None),
        }
    }

    fn get_contracts(&self) -> Result<Vec<Contract>, Error> {
        self.contract_tree()?
            .iter()
            .values()
            .map(|x| contract::deserialize(&x.unwrap()))
            .collect::<Result<Vec<Contract>, Error>>()
    }

    fn create_contract(&self, contract: &OfferedContract) -> Result<(), Error> {
        let serialized = contract::serialize(&Contract::Offered(contract.clone()))?;
        self.contract_tree()?
            .insert(&contract.id, serialized)
            .map_err(to_storage_error)?;
        Ok(())
    }

    fn delete_contract(&self, contract_id: &ContractId) -> Result<(), Error> {
        self.contract_tree()?
            .remove(&contract_id)
            .map_err(to_storage_error)?;
        Ok(())
    }

    fn update_contract(&self, contract: &Contract) -> Result<(), Error> {
        let serialized = contract::serialize(contract)?;
        self.contract_tree()?
            .transaction::<_, _, UnabortableTransactionError>(|db| {
                match contract {
                    a @ Contract::Accepted(_) | a @ Contract::Signed(_) => {
                        db.remove(&a.get_temporary_id())?;
                    }
                    _ => {}
                };

                db.insert(&contract.get_id(), serialized.clone())?;
                Ok(())
            })
            .map_err(to_storage_error)?;
        Ok(())
    }

    fn get_signed_contracts(&self) -> Result<Vec<SignedContract>, Error> {
        self.get_data_with_prefix(
            &self.contract_tree()?,
            &[ContractPrefix::Signed.into()],
            None,
        )
    }

    fn get_confirmed_contracts(&self) -> Result<Vec<SignedContract>, Error> {
        self.get_data_with_prefix(
            &self.contract_tree()?,
            &[ContractPrefix::Confirmed.into()],
            None,
        )
    }

    fn get_contract_offers(&self) -> Result<Vec<OfferedContract>, Error> {
        self.get_data_with_prefix(
            &self.contract_tree()?,
            &[ContractPrefix::Offered.into()],
            None,
        )
    }

    fn upsert_channel(&self, channel: Channel, contract: Option<Contract>) -> Result<(), Error> {
        let serialized = channel::serialize(&channel)?;
        let serialized_contract = match contract.as_ref() {
            Some(c) => Some(contract::serialize(c)?),
            None => None,
        };
        let channel_tree = self.channel_tree()?;
        let contract_tree = self.contract_tree()?;
        (&channel_tree, &contract_tree)
            .transaction::<_, ()>(
                |(channel_db, contract_db)| -> ConflictableTransactionResult<(), UnabortableTransactionError> {
                    match &channel {
                        a @ Channel::Accepted(_) | a @ Channel::Signed(_) => {
                            channel_db.remove(&a.get_temporary_id())?;
                        }
                        _ => {}
                    };

                    channel_db.insert(&channel.get_id(), serialized.clone())?;

                    if let Some(c) = contract.as_ref() {
                        contract_db.insert(b"a".to_vec(), b"a".to_vec())?;
                        insert_contract(
                            contract_db,
                            serialized_contract
                                .clone()
                                .expect("to have the serialized version"),
                            c,
                        )?;
                    }
                    Ok(())
                },
            )
        .map_err(to_storage_error)?;
        Ok(())
    }

    fn delete_channel(&self, channel_id: &dlc_manager::ChannelId) -> Result<(), Error> {
        self.channel_tree()?
            .remove(channel_id)
            .map_err(to_storage_error)?;
        Ok(())
    }

    fn get_channel(&self, channel_id: &dlc_manager::ChannelId) -> Result<Option<Channel>, Error> {
        match self
            .channel_tree()?
            .get(channel_id)
            .map_err(to_storage_error)?
        {
            Some(res) => Ok(Some(channel::deserialize(&res)?)),
            None => Ok(None),
        }
    }

    fn get_signed_channels(
        &self,
        channel_state: Option<SignedChannelStateType>,
    ) -> Result<Vec<SignedChannel>, Error> {
        let (prefix, consume) = if let Some(state) = &channel_state {
            (
                vec![
                    ChannelPrefix::Signed.into(),
                    SignedChannelPrefix::get_prefix(state),
                ],
                None,
            )
        } else {
            (vec![ChannelPrefix::Signed.into()], Some(1))
        };

        self.get_data_with_prefix(&self.channel_tree()?, &prefix, consume)
    }

    fn get_offered_channels(&self) -> Result<Vec<OfferedChannel>, Error> {
        self.get_data_with_prefix(
            &self.channel_tree()?,
            &[ChannelPrefix::Offered.into()],
            None,
        )
    }

    fn persist_chain_monitor(&self, monitor: &ChainMonitor) -> Result<(), Error> {
        self.open_tree(&[CHAIN_MONITOR_TREE])?
            .insert(&[CHAIN_MONITOR_KEY], monitor.serialize()?)
            .map_err(|e| Error::StorageError(format!("Error writing chain monitor: {}", e)))?;
        Ok(())
    }
    fn get_chain_monitor(&self) -> Result<Option<ChainMonitor>, dlc_manager::error::Error> {
        let serialized = self
            .open_tree(&[CHAIN_MONITOR_TREE])?
            .get(&[CHAIN_MONITOR_KEY])
            .map_err(|e| Error::StorageError(format!("Error reading chain monitor: {}", e)))?;
        let deserialized = match serialized {
            Some(s) => Some(
                ChainMonitor::deserialize(&mut ::std::io::Cursor::new(s))
                    .map_err(to_storage_error)?,
            ),
            None => None,
        };
        Ok(deserialized)
    }
}

impl SubChannelStorage for SledStorageProvider {
    fn upsert_sub_channel(&self, subchannel: &SubChannel) -> Result<(), Error> {
        let serialized = sub_channel::serialize(&subchannel)?;
        self.sub_channel_tree()?
            .insert(subchannel.get_id(), serialized)
            .map_err(to_storage_error)?;
        Ok(())
    }

    fn get_sub_channel(
        &self,
        channel_id: dlc_manager::ChannelId,
    ) -> Result<Option<dlc_manager::sub_channel_manager::SubChannel>, Error> {
        match self
            .sub_channel_tree()?
            .get(channel_id)
            .map_err(to_storage_error)?
        {
            Some(res) => Ok(Some(sub_channel::deserialize(&res)?)),
            None => Ok(None),
        }
    }
}

fn insert_contract(
    db: &sled::transaction::TransactionalTree,
    serialized: Vec<u8>,
    contract: &Contract,
) -> Result<Option<sled::IVec>, UnabortableTransactionError> {
    match contract {
        a @ Contract::Accepted(_) | a @ Contract::Signed(_) => {
            db.remove(&a.get_temporary_id())?;
        }
        _ => {}
    };

    db.insert(&contract.get_id(), serialized)
}

macro_rules! serialize_object {
    ($type: ident, $prefixtype: ident, $name: ident, $(($state: ident, $cstate: ident)),*) => {
        mod $name {
            use super::*;
            pub(super) fn serialize($name: &$type) -> Result<Vec<u8>, ::std::io::Error> {
                let mut serialized = match $name {
                    $(
                        $type::$state(o) => o.serialize()?,
                    )*
                };
                let mut res = Vec::with_capacity(serialized.len() + 1);
                res.push($prefixtype::get_prefix($name));
                res.append(&mut serialized);
                Ok(res)
            }

            pub(super) fn deserialize(buff: &sled::IVec) -> Result<$type, Error> {
                let mut cursor = ::std::io::Cursor::new(buff);
                let mut prefix = [0u8; 1];
                cursor.read_exact(&mut prefix)?;
                let prefix: $prefixtype = prefix[0].try_into()?;
                let $name = match prefix {
                    $($prefixtype::$state => {
                        $type::$state($cstate::deserialize(&mut cursor).map_err(to_storage_error)?)
                    })*
                };
                Ok($name)
            }
        }
    };
}

serialize_object!(
    Contract,
    ContractPrefix,
    contract,
    (Offered, OfferedContract),
    (Rejected, OfferedContract),
    (Accepted, AcceptedContract),
    (Confirmed, SignedContract),
    (Refunded, SignedContract),
    (Signed, SignedContract),
    (FailedAccept, FailedAcceptContract),
    (FailedSign, FailedSignContract),
    (Closed, ClosedContract)
);

serialize_object!(
    Channel,
    ChannelPrefix,
    channel,
    (Offered, OfferedChannel),
    (Accepted, AcceptedChannel),
    (Signed, SignedChannel),
    (FailedAccept, FailedAccept),
    (FailedSign, FailedSign)
);

serialize_object!(
    SubChannel,
    SubChannelPrefix,
    sub_channel,
    (Offered, OfferedSubChannel),
    (Accepted, AcceptedSubChannel),
    (Signed, SignedSubChannel)
);

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! sled_test {
        ($name: ident, $body: expr) => {
            #[test]
            fn $name() {
                let path = format!("{}{}", "test_files/sleddb/", std::stringify!($name));
                {
                    let storage = SledStorageProvider::new(&path).expect("Error opening sled DB");
                    $body(storage);
                }
                std::fs::remove_dir_all(path).unwrap();
            }
        };
    }

    fn deserialize_object<T>(serialized: &[u8]) -> T
    where
        T: Serializable,
    {
        let mut cursor = std::io::Cursor::new(&serialized);
        T::deserialize(&mut cursor).unwrap()
    }

    sled_test!(
        create_contract_can_be_retrieved,
        |storage: SledStorageProvider| {
            let serialized = include_bytes!("../test_files/Offered");
            let contract = deserialize_object(serialized);

            storage
                .create_contract(&contract)
                .expect("Error creating contract");

            let retrieved = storage
                .get_contract(&contract.id)
                .expect("Error retrieving contract.");

            if let Some(Contract::Offered(retrieved_offer)) = retrieved {
                assert_eq!(serialized[..], retrieved_offer.serialize().unwrap()[..]);
            } else {
                unreachable!();
            }
        }
    );

    sled_test!(
        update_contract_is_updated,
        |storage: SledStorageProvider| {
            let serialized = include_bytes!("../test_files/Offered");
            let offered_contract = deserialize_object(serialized);
            let serialized = include_bytes!("../test_files/Accepted");
            let accepted_contract = deserialize_object(serialized);
            let accepted_contract = Contract::Accepted(accepted_contract);

            storage
                .create_contract(&offered_contract)
                .expect("Error creating contract");

            storage
                .update_contract(&accepted_contract)
                .expect("Error updating contract.");
            let retrieved = storage
                .get_contract(&accepted_contract.get_id())
                .expect("Error retrieving contract.");

            if let Some(Contract::Accepted(_)) = retrieved {
            } else {
                unreachable!();
            }
        }
    );

    sled_test!(
        delete_contract_is_deleted,
        |storage: SledStorageProvider| {
            let serialized = include_bytes!("../test_files/Offered");
            let contract = deserialize_object(serialized);
            storage
                .create_contract(&contract)
                .expect("Error creating contract");

            storage
                .delete_contract(&contract.id)
                .expect("Error deleting contract");

            assert!(storage
                .get_contract(&contract.id)
                .expect("Error querying contract")
                .is_none());
        }
    );

    fn insert_offered_signed_and_confirmed(storage: &mut SledStorageProvider) {
        let serialized = include_bytes!("../test_files/Offered");
        let offered_contract = deserialize_object(serialized);
        storage
            .create_contract(&offered_contract)
            .expect("Error creating contract");

        let serialized = include_bytes!("../test_files/Signed");
        let signed_contract = Contract::Signed(deserialize_object(serialized));
        storage
            .update_contract(&signed_contract)
            .expect("Error creating contract");
        let serialized = include_bytes!("../test_files/Signed1");
        let signed_contract = Contract::Signed(deserialize_object(serialized));
        storage
            .update_contract(&signed_contract)
            .expect("Error creating contract");

        let serialized = include_bytes!("../test_files/Confirmed");
        let confirmed_contract = Contract::Confirmed(deserialize_object(serialized));
        storage
            .update_contract(&confirmed_contract)
            .expect("Error creating contract");
        let serialized = include_bytes!("../test_files/Confirmed1");
        let confirmed_contract = Contract::Confirmed(deserialize_object(serialized));
        storage
            .update_contract(&confirmed_contract)
            .expect("Error creating contract");
    }

    fn insert_offered_and_signed_channels(storage: &mut SledStorageProvider) {
        let serialized = include_bytes!("../test_files/Offered");
        let offered_contract = deserialize_object(serialized);
        let serialized = include_bytes!("../test_files/OfferedChannel");
        let offered_channel = deserialize_object(serialized);
        storage
            .upsert_channel(
                Channel::Offered(offered_channel),
                Some(Contract::Offered(offered_contract)),
            )
            .expect("Error creating contract");

        let serialized = include_bytes!("../test_files/SignedChannelEstablished");
        let signed_channel = Channel::Signed(deserialize_object(serialized));
        storage
            .upsert_channel(signed_channel, None)
            .expect("Error creating contract");

        let serialized = include_bytes!("../test_files/SignedChannelSettled");
        let signed_channel = Channel::Signed(deserialize_object(serialized));
        storage
            .upsert_channel(signed_channel, None)
            .expect("Error creating contract");
    }

    sled_test!(
        get_signed_contracts_only_signed,
        |mut storage: SledStorageProvider| {
            insert_offered_signed_and_confirmed(&mut storage);

            let signed_contracts = storage
                .get_signed_contracts()
                .expect("Error retrieving signed contracts");

            assert_eq!(2, signed_contracts.len());
        }
    );

    sled_test!(
        get_confirmed_contracts_only_confirmed,
        |mut storage: SledStorageProvider| {
            insert_offered_signed_and_confirmed(&mut storage);

            let confirmed_contracts = storage
                .get_confirmed_contracts()
                .expect("Error retrieving signed contracts");

            assert_eq!(2, confirmed_contracts.len());
        }
    );

    sled_test!(
        get_offered_contracts_only_offered,
        |mut storage: SledStorageProvider| {
            insert_offered_signed_and_confirmed(&mut storage);

            let offered_contracts = storage
                .get_contract_offers()
                .expect("Error retrieving signed contracts");

            assert_eq!(1, offered_contracts.len());
        }
    );

    sled_test!(
        get_contracts_all_returned,
        |mut storage: SledStorageProvider| {
            insert_offered_signed_and_confirmed(&mut storage);

            let contracts = storage.get_contracts().expect("Error retrieving contracts");

            assert_eq!(5, contracts.len());
        }
    );

    sled_test!(
        get_offered_channels_only_offered,
        |mut storage: SledStorageProvider| {
            insert_offered_and_signed_channels(&mut storage);

            let offered_channels = storage
                .get_offered_channels()
                .expect("Error retrieving offered channels");
            assert_eq!(1, offered_channels.len());
        }
    );

    sled_test!(
        get_signed_established_channel_only_established,
        |mut storage: SledStorageProvider| {
            insert_offered_and_signed_channels(&mut storage);

            let signed_channels = storage
                .get_signed_channels(Some(
                    dlc_manager::channel::signed_channel::SignedChannelStateType::Established,
                ))
                .expect("Error retrieving offered channels");
            assert_eq!(1, signed_channels.len());
            if let dlc_manager::channel::signed_channel::SignedChannelState::Established {
                ..
            } = &signed_channels[0].state
            {
            } else {
                panic!(
                    "Expected established state got {:?}",
                    &signed_channels[0].state
                );
            }
        }
    );

    sled_test!(
        get_channel_by_id_returns_correct_channel,
        |mut storage: SledStorageProvider| {
            insert_offered_and_signed_channels(&mut storage);

            let serialized = include_bytes!("../test_files/AcceptedChannel");
            let accepted_channel: AcceptedChannel = deserialize_object(serialized);
            let channel_id = accepted_channel.channel_id;
            storage
                .upsert_channel(Channel::Accepted(accepted_channel), None)
                .expect("Error creating contract");

            storage
                .get_channel(&channel_id)
                .expect("error retrieving previously inserted channel.")
                .expect("to have found the previously inserted channel.");
        }
    );

    sled_test!(
        delete_channel_is_not_returned,
        |mut storage: SledStorageProvider| {
            insert_offered_and_signed_channels(&mut storage);

            let serialized = include_bytes!("../test_files/AcceptedChannel");
            let accepted_channel: AcceptedChannel = deserialize_object(serialized);
            let channel_id = accepted_channel.channel_id;
            storage
                .upsert_channel(Channel::Accepted(accepted_channel), None)
                .expect("Error creating contract");

            storage
                .get_channel(&channel_id)
                .expect("could not retrieve previously inserted channel.");

            storage
                .delete_channel(&channel_id)
                .expect("to be able to delete the channel");

            assert!(storage
                .get_channel(&channel_id)
                .expect("error getting channel.")
                .is_none());
        }
    );

    sled_test!(
        persist_chain_monitor_test,
        |storage: SledStorageProvider| {
            let chain_monitor = ChainMonitor::new(123);

            storage
                .persist_chain_monitor(&chain_monitor)
                .expect("to be able to persist the chain monistor.");

            let retrieved = storage
                .get_chain_monitor()
                .expect("to be able to retrieve the chain monitor.")
                .expect("to have a persisted chain monitor.");

            assert_eq!(chain_monitor, retrieved);
        }
    );
}
