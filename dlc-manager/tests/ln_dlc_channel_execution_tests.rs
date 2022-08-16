#[macro_use]
mod test_utils;
mod console_logger;

use std::{
    collections::HashMap,
    ops::Deref,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use bitcoin::{consensus::Decodable, hashes::Hash, network, Amount, Network, Transaction};
use bitcoin_bech32::WitnessProgram;
use bitcoin_rpc_provider::BitcoinCoreProvider;
use bitcoin_test_utils::rpc_helpers::init_clients;
use bitcoincore_rpc::{Client, RpcApi};
use bitcoincore_rpc_json::FundRawTransactionOptions;
use console_logger::ConsoleLogger;
use dlc_manager::{
    custom_signer::{CustomKeysManager, CustomSigner},
    manager::Manager,
    sub_channel_manager::SubChannelManager,
    Blockchain, Oracle,
};
use dlc_messages::{
    sub_channel::{SubChannelInfo, SubChannelMessage},
    Message,
};
use lightning::{
    chain::{
        keysinterface::{KeysInterface, KeysManager, Recipient},
        BestBlock, Filter, Listen,
    },
    ln::{
        channelmanager::{ChainParameters, SimpleArcChannelManager},
        features::Features,
        peer_handler::{IgnoringMessageHandler, MessageHandler},
    },
    routing::{
        gossip::{NetworkGraph, NodeId},
        router::{Route, RouteHop, RouteParameters},
        scoring::{ChannelUsage, Score},
    },
    util::{
        config::UserConfig,
        events::{Event, EventHandler, EventsProvider, PaymentPurpose},
        logger::Logger,
    },
};
use lightning_persister::FilesystemPersister;
use mocks::{
    memory_storage_provider::MemoryStorage,
    mock_oracle_provider::MockOracle,
    mock_time::{self, MockTime},
};
use secp256k1_zkp::{
    rand::{thread_rng, RngCore},
    Secp256k1,
};

use crate::test_utils::{get_enum_test_params, TestParams};

type ChainMonitor = lightning::chain::chainmonitor::ChainMonitor<
    CustomSigner,
    Arc<dyn Filter>,
    Arc<BitcoinCoreProvider>,
    Arc<BitcoinCoreProvider>,
    Arc<ConsoleLogger>,
    Arc<FilesystemPersister>,
>;

pub(crate) type ChannelManager = lightning::ln::channelmanager::ChannelManager<
    CustomSigner,
    Arc<ChainMonitor>,
    Arc<BitcoinCoreProvider>,
    Arc<CustomKeysManager>,
    Arc<BitcoinCoreProvider>,
    Arc<ConsoleLogger>,
>;

pub(crate) type PeerManager = lightning::ln::peer_handler::PeerManager<
    MockSocketDescriptor,
    Arc<ChannelManager>,
    Arc<IgnoringMessageHandler>,
    Arc<ConsoleLogger>,
    Arc<IgnoringMessageHandler>,
>;

type DlcChannelManager = Manager<
    Arc<BitcoinCoreProvider>,
    Arc<BitcoinCoreProvider>,
    Arc<MemoryStorage>,
    Arc<MockOracle>,
    Arc<MockTime>,
    Arc<BitcoinCoreProvider>,
>;
struct LnDlcParty {
    peer_manager: Arc<PeerManager>,
    channel_manager: Arc<ChannelManager>,
    chain_monitor: Arc<ChainMonitor>,
    bitcoind_client: Arc<BitcoinCoreProvider>,
    keys_manager: Arc<CustomKeysManager>,
    logger: Arc<ConsoleLogger>,
    network_graph: NetworkGraph<Arc<ConsoleLogger>>,
    chain_height: u64,
    sub_channel_manager: SubChannelManager<
        Arc<BitcoinCoreProvider>,
        Arc<ChannelManager>,
        Arc<MemoryStorage>,
        Arc<BitcoinCoreProvider>,
        Arc<MockOracle>,
        Arc<MockTime>,
        Arc<BitcoinCoreProvider>,
        Arc<DlcChannelManager>,
    >,
    dlc_manager: Arc<DlcChannelManager>,
}

impl LnDlcParty {
    fn update_to_chain_tip(&mut self) {
        let chain_tip_height = self.bitcoind_client.get_blockchain_height().unwrap();
        for i in self.chain_height + 1..=chain_tip_height {
            println!("HEIGHT :{}", i);
            let block = self.bitcoind_client.get_block_at_height(i).unwrap();
            self.channel_manager.block_connected(&block, i as u32);
            for ftxo in self.chain_monitor.list_monitors() {
                self.chain_monitor
                    .get_monitor(ftxo)
                    .unwrap()
                    .block_connected(
                        &block.header,
                        &block.txdata.iter().enumerate().collect::<Vec<_>>(),
                        i as u32,
                        self.bitcoind_client.clone(),
                        self.bitcoind_client.clone(),
                        self.logger.clone(),
                    );
            }
        }
        self.chain_height = chain_tip_height;
    }

    fn process_events(&self) {
        self.peer_manager.process_events();
        self.channel_manager.process_pending_events(self);
        self.chain_monitor.process_pending_events(self);
    }
}

#[derive(Clone)]
struct MockSocketDescriptor {
    counter_peer_mng: Arc<PeerManager>,
    counter_descriptor: Option<Box<MockSocketDescriptor>>,
    id: u64,
}

impl std::hash::Hash for MockSocketDescriptor {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl PartialEq for MockSocketDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for MockSocketDescriptor {}

impl MockSocketDescriptor {
    fn new(id: u64, counter_peer_mng: Arc<PeerManager>) -> Self {
        MockSocketDescriptor {
            counter_peer_mng,
            id,
            counter_descriptor: None,
        }
    }
}

impl lightning::ln::peer_handler::SocketDescriptor for MockSocketDescriptor {
    fn send_data(&mut self, data: &[u8], _resume_read: bool) -> usize {
        println!("Sending data! {}", self.id);
        self.counter_peer_mng
            .clone()
            .read_event(&mut self.counter_descriptor.as_mut().unwrap(), data)
            .unwrap();
        data.len()
    }

    fn disconnect_socket(&mut self) {}
}

#[derive(Clone)]
/// [`Score`] implementation that uses a fixed penalty.
pub struct TestScorer {
    penalty_msat: u64,
}

impl TestScorer {
    /// Creates a new scorer using `penalty_msat`.
    pub fn with_penalty(penalty_msat: u64) -> Self {
        Self { penalty_msat }
    }
}

impl Score for TestScorer {
    fn channel_penalty_msat(&self, _: u64, _: &NodeId, _: &NodeId, _: ChannelUsage) -> u64 {
        self.penalty_msat
    }

    fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}

    fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}
}

impl EventHandler for LnDlcParty {
    fn handle_event(&self, event: &lightning::util::events::Event) {
        match event {
            Event::FundingGenerationReady {
                temporary_channel_id,
                counterparty_node_id,
                channel_value_satoshis,
                output_script,
                ..
            } => {
                // Construct the raw transaction with one output, that is paid the amount of the
                // channel.
                let addr = WitnessProgram::from_scriptpubkey(
                    &output_script[..],
                    bitcoin_bech32::constants::Network::Regtest,
                )
                .expect("Lightning funding tx should always be to a SegWit output")
                .to_address();
                let mut outputs = HashMap::with_capacity(1);
                outputs.insert(addr, bitcoin::Amount::from_sat(*channel_value_satoshis));
                let raw_tx_hex = self
                    .bitcoind_client
                    .get_client()
                    .lock()
                    .unwrap()
                    .create_raw_transaction_hex(&[], &outputs, None, None)
                    .unwrap();

                // Have your wallet put the inputs into the transaction such that the output is
                // satisfied.
                let mut funding_options = FundRawTransactionOptions::default();
                funding_options.fee_rate = Some(Amount::from_sat(1050));
                let funded_tx = self
                    .bitcoind_client
                    .get_client()
                    .lock()
                    .unwrap()
                    .fund_raw_transaction(raw_tx_hex, Some(&funding_options), None)
                    .unwrap();

                // Sign the final funding transaction and broadcast it.
                let signed_tx = self
                    .bitcoind_client
                    .get_client()
                    .lock()
                    .unwrap()
                    .sign_raw_transaction_with_wallet(&funded_tx.hex, None, None)
                    .unwrap();
                assert_eq!(signed_tx.complete, true);
                let final_tx: Transaction = Transaction::consensus_decode(&*signed_tx.hex).unwrap();
                // Give the funding transaction back to LDK for opening the channel.
                self.channel_manager
                    .funding_transaction_generated(
                        &temporary_channel_id,
                        counterparty_node_id,
                        final_tx,
                    )
                    .unwrap();
            }
            Event::PendingHTLCsForwardable { .. } => {
                self.channel_manager.process_pending_htlc_forwards();
            }
            Event::PaymentReceived { purpose, .. } => {
                let payment_preimage = match purpose {
                    PaymentPurpose::InvoicePayment {
                        payment_preimage, ..
                    } => *payment_preimage,
                    PaymentPurpose::SpontaneousPayment(preimage) => Some(*preimage),
                };
                self.channel_manager.claim_funds(payment_preimage.unwrap());
            }
            _ => {
                //Ignore
            }
        }
    }
}

fn create_ln_node(
    name: String,
    rpc_client: Client,
    data_dir: &str,
    test_params: &TestParams,
) -> LnDlcParty {
    let bitcoind_client = Arc::new(BitcoinCoreProvider::new_from_rpc_client(rpc_client));
    let mut key = [0; 32];
    thread_rng().fill_bytes(&mut key);
    let cur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let keys_manager = KeysManager::new(&key, cur.as_secs(), cur.subsec_nanos());
    let consistent_keys_manager = Arc::new(CustomKeysManager::new(keys_manager));
    let logger = Arc::new(console_logger::ConsoleLogger { name });

    std::fs::create_dir_all(data_dir.clone()).unwrap();
    let persister = Arc::new(FilesystemPersister::new(data_dir.to_string()));

    let chain_monitor: Arc<ChainMonitor> =
        Arc::new(lightning::chain::chainmonitor::ChainMonitor::new(
            None,
            bitcoind_client.clone(),
            logger.clone(),
            bitcoind_client.clone(),
            persister.clone(),
        ));

    let mut user_config = UserConfig::default();
    user_config.peer_channel_config_limits.max_funding_satoshis = 200000000;
    user_config
        .peer_channel_config_limits
        .force_announced_channel_preference = false;
    let (blockhash, chain_height, channel_manager) = {
        let height = bitcoind_client.get_blockchain_height().unwrap();
        let last_block = bitcoind_client.get_block_at_height(height).unwrap();

        let chain_params = ChainParameters {
            network: Network::Regtest,
            best_block: BestBlock::new(last_block.block_hash(), height as u32),
        };

        let fresh_channel_manager = Arc::new(ChannelManager::new(
            bitcoind_client.clone(),
            chain_monitor.clone(),
            bitcoind_client.clone(),
            logger.clone(),
            consistent_keys_manager.clone(),
            user_config,
            chain_params,
        ));
        (last_block.block_hash(), height, fresh_channel_manager)
    };

    // Step 12: Initialize the PeerManager
    let mut ephemeral_bytes = [0; 32];
    thread_rng().fill_bytes(&mut ephemeral_bytes);
    let lightning_msg_handler = MessageHandler {
        chan_handler: channel_manager.clone(),
        route_handler: Arc::new(IgnoringMessageHandler {}),
    };
    let peer_manager = PeerManager::new(
        lightning_msg_handler,
        consistent_keys_manager
            .get_node_secret(Recipient::Node)
            .unwrap(),
        &ephemeral_bytes,
        logger.clone(),
        Arc::new(IgnoringMessageHandler {}),
    );

    let network_graph = NetworkGraph::new(blockhash, logger.clone());

    let storage = Arc::new(MemoryStorage::new());

    let mut oracles = HashMap::with_capacity(1);

    for oracle in &test_params.oracles {
        let oracle = Arc::new(oracle.clone());
        oracles.insert(oracle.get_public_key(), Arc::clone(&oracle));
    }

    let dlc_manager = Arc::new(
        Manager::new(
            bitcoind_client.clone(),
            bitcoind_client.clone(),
            storage.clone(),
            oracles,
            Arc::new(mock_time::MockTime {}),
            bitcoind_client.clone(),
        )
        .unwrap(),
    );

    let sub_channel_manager = SubChannelManager::new(
        Secp256k1::new(),
        bitcoind_client.clone(),
        channel_manager.clone(),
        storage,
        bitcoind_client.clone(),
        dlc_manager.clone(),
    );

    LnDlcParty {
        peer_manager: Arc::new(peer_manager),
        channel_manager: channel_manager.clone(),
        chain_monitor,
        bitcoind_client: bitcoind_client.clone(),
        keys_manager: consistent_keys_manager,
        logger,
        network_graph,
        chain_height,
        sub_channel_manager,
        dlc_manager,
    }
}

#[test]
#[ignore]
fn ln_dlc_test() {
    // Initialize the LDK data directory if necessary.
    let ldk_data_dir = "./.ldk".to_string();
    std::fs::create_dir_all(ldk_data_dir.clone()).unwrap();
    let (alice_rpc, bob_rpc, sink_rpc) = init_clients();

    let test_params = get_enum_test_params(1, 1, None);
    let mut alice_node =
        create_ln_node("Alice".to_string(), alice_rpc, "./.alicedir", &test_params);
    let mut bob_node = create_ln_node("Bob".to_string(), bob_rpc, "./.bobdir", &test_params);

    alice_node.update_to_chain_tip();
    bob_node.update_to_chain_tip();

    let mut alice_descriptor = MockSocketDescriptor::new(0, bob_node.peer_manager.clone());
    let mut bob_descriptor = MockSocketDescriptor::new(1, alice_node.peer_manager.clone());

    alice_descriptor.counter_descriptor = Some(Box::new(bob_descriptor.clone()));
    bob_descriptor.counter_descriptor = Some(Box::new(alice_descriptor.clone()));

    let initial_send = alice_node
        .peer_manager
        .new_outbound_connection(
            bob_node.channel_manager.get_our_node_id(),
            alice_descriptor.clone(),
            None,
        )
        .unwrap();

    bob_node
        .peer_manager
        .new_inbound_connection(bob_descriptor.clone(), None)
        .unwrap();

    // bob_node.peer_manager.timer_tick_occurred();

    bob_node
        .peer_manager
        .read_event(&mut bob_descriptor, &initial_send)
        .unwrap();
    bob_node.peer_manager.process_events();
    alice_node.peer_manager.process_events();
    bob_node.peer_manager.process_events();

    alice_node
        .channel_manager
        .create_channel(
            bob_node.channel_manager.get_our_node_id(),
            100000000,
            0,
            1,
            None,
        )
        .unwrap();

    bob_node.peer_manager.process_events();
    alice_node.peer_manager.process_events();
    bob_node.peer_manager.process_events();

    alice_node
        .channel_manager
        .process_pending_events(&alice_node);
    alice_node.peer_manager.process_events();
    bob_node.peer_manager.process_events();

    let sink_address = sink_rpc.get_new_address(None, None).expect("RPC Error");
    sink_rpc
        .generate_to_address(6, &sink_address)
        .expect("RPC Error");

    alice_node.update_to_chain_tip();
    bob_node.update_to_chain_tip();

    alice_node.peer_manager.process_events();
    bob_node.peer_manager.process_events();

    assert_eq!(1, alice_node.channel_manager.list_channels().len());
    assert_eq!(1, alice_node.channel_manager.list_usable_channels().len());

    let payment_params = lightning::routing::router::PaymentParameters::from_node_id(
        bob_node.channel_manager.get_our_node_id(),
    )
    .with_features(lightning::ln::features::InvoiceFeatures::known());

    let payment_preimage = lightning::ln::PaymentPreimage([0; 32]);
    let payment_hash = lightning::ln::PaymentHash(
        bitcoin::hashes::sha256::Hash::hash(&payment_preimage.0[..]).into_inner(),
    );
    let payment_secret = bob_node
        .channel_manager
        .create_inbound_payment_for_hash(payment_hash, None, 7200)
        .unwrap();

    let scorer = TestScorer::with_penalty(0);
    let random_seed_bytes = bob_node.keys_manager.get_secure_random_bytes();
    let route_params = RouteParameters {
        payment_params: payment_params.clone(),
        final_value_msat: 10000000000,
        final_cltv_expiry_delta: 70,
    };

    let route = lightning::routing::router::find_route(
        &alice_node.channel_manager.get_our_node_id(),
        &route_params,
        &alice_node.network_graph.read_only(),
        Some(
            &alice_node
                .channel_manager
                .list_usable_channels()
                .iter()
                .collect::<Vec<_>>(),
        ),
        alice_node.logger.clone(),
        &scorer,
        &random_seed_bytes,
    )
    .unwrap();

    alice_node
        .channel_manager
        .send_spontaneous_payment(&route, Some(payment_preimage))
        .unwrap();

    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();
    alice_node.process_events();
    bob_node.process_events();

    let alice_channel_details = alice_node.channel_manager.list_usable_channels().remove(0);
    let bob_channel_details = bob_node.channel_manager.list_usable_channels().remove(0);

    let channel_id = bob_channel_details.channel_id;

    let oracle_announcements = test_params
        .oracles
        .iter()
        .map(|x| x.get_announcement(test_utils::EVENT_ID).unwrap())
        .collect::<Vec<_>>();

    let offer = alice_node
        .sub_channel_manager
        .offer_sub_channel(
            &alice_channel_details.channel_id,
            &test_params.contract_input,
            &vec![oracle_announcements],
        )
        .unwrap();
    println!("{:?}", offer.channel_id);
    println!("{:?}", channel_id);
    bob_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Request(offer.clone()),
            &alice_node.channel_manager.get_our_node_id(),
        )
        .unwrap();
    let accept = bob_node
        .sub_channel_manager
        .accept_sub_channel(&channel_id)
        .unwrap();
    println!("a");
    let confirm = alice_node
        .sub_channel_manager
        .on_sub_channel_message(
            &SubChannelMessage::Accept(accept),
            &bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap()
        .unwrap();
    println!("b");

    let finalize = bob_node
        .sub_channel_manager
        .on_sub_channel_message(&confirm, &alice_node.channel_manager.get_our_node_id())
        .unwrap()
        .unwrap();

    alice_node
        .sub_channel_manager
        .on_sub_channel_message(&finalize, &bob_node.channel_manager.get_our_node_id())
        .unwrap();

    let route_params = RouteParameters {
        payment_params,
        final_value_msat: 100000000,
        final_cltv_expiry_delta: 70,
    };

    let route = lightning::routing::router::find_route(
        &alice_node.channel_manager.get_our_node_id(),
        &route_params,
        &alice_node.network_graph.read_only(),
        Some(
            &alice_node
                .channel_manager
                .list_usable_channels()
                .iter()
                .collect::<Vec<_>>(),
        ),
        alice_node.logger.clone(),
        &scorer,
        &random_seed_bytes,
    )
    .unwrap();

    alice_node
        .channel_manager
        .send_spontaneous_payment(&route, Some(payment_preimage))
        .unwrap();

    let (renew_offer, _) = bob_node
        .dlc_manager
        .renew_offer(
            &offer.channel_id,
            test_params.contract_input.accept_collateral,
            &test_params.contract_input,
        )
        .unwrap();

    alice_node
        .dlc_manager
        .on_dlc_message(
            &Message::RenewOffer(renew_offer),
            bob_node.channel_manager.get_our_node_id(),
        )
        .unwrap();

    mocks::mock_time::set_time((test_params.contract_input.maturity_time as u64) + 1);

    alice_node
        .sub_channel_manager
        .initiate_force_close_sub_channels(&channel_id)
        .unwrap();

    sink_rpc
        .generate_to_address(500, &sink_address)
        .expect("RPC Error");

    alice_node
        .sub_channel_manager
        .finalize_force_close_sub_channels(&channel_id)
        .unwrap();
}
