// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::{HashSet, BTreeMap, VecDeque};
use std::cmp;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Weak};
use std::time::{Instant, Duration};

// util
use hash::keccak;
use bytes::Bytes;
use itertools::Itertools;
use journaldb;
use trie::{TrieSpec, TrieFactory, Trie};
use kvdb::{DBValue, KeyValueDB, DBTransaction};

// other
use ethereum_types::{H256, Address, U256};
use block::{IsBlock, LockedBlock, Drain, ClosedBlock, OpenBlock, enact_verified, SealedBlock};
use blockchain::{BlockReceipts, BlockChain, BlockChainDB, BlockProvider, TreeRoute, ImportRoute, TransactionAddress, ExtrasInsert};
use client::ancient_import::AncientVerifier;
use client::{
	Nonce, Balance, ChainInfo, BlockInfo, CallContract, TransactionInfo,
	RegistryInfo, ReopenBlock, PrepareOpenBlock, ScheduleInfo, ImportSealedBlock,
	BroadcastProposalBlock, ImportBlock, StateOrBlock, StateInfo, StateClient, Call,
	AccountData, BlockChain as BlockChainTrait, BlockProducer, SealedBlockImporter,
	ClientIoMessage, ProvingCallContract
};
use client::{
	BlockId, TransactionId, UncleId, TraceId, ClientConfig, BlockChainClient,
	TraceFilter, CallAnalytics, Mode,
	ChainNotify, NewBlocks, ChainRoute, PruningInfo, ProvingBlockChainClient, EngineInfo, ChainMessageType,
	IoClient, BadBlocks,
};
use client::bad_blocks;
use encoded;
use engines::{EthEngine, EpochTransition, ForkChoice};
use error::{
	ImportErrorKind, ExecutionError, CallError, BlockError,
	QueueError, QueueErrorKind, Error as EthcoreError, EthcoreResult, ErrorKind as EthcoreErrorKind
};
use vm::{EnvInfo, LastHashes};
use evm::Schedule;
use executive::{Executive, Executed, TransactOptions, contract_address};
use factory::{Factories, VmFactory};
use header::{BlockNumber, Header, ExtendedHeader};
use io::IoChannel;
use log_entry::LocalizedLogEntry;
use miner::{Miner, MinerService, BlockChainClient as MinerBlockChainClient};
use ethcore_miner::pool::VerifiedTransaction;
use parking_lot::{Mutex, RwLock};
use rand::OsRng;
use receipt::{Receipt, LocalizedReceipt};
use snapshot::{self, io as snapshot_io, SnapshotClient};
use spec::Spec;
use state_db::StateDB;
use state::{self, State, backend::Backend, backend::Proof, backend::ProofElement};
use trace;
use trace::{TraceDB, ImportRequest as TraceImportRequest, LocalizedTrace, Database as TraceDatabase};
use transaction::{self, LocalizedTransaction, UnverifiedTransaction, SignedTransaction, Transaction, Action};
use types::filter::Filter;
use types::ancestry_action::AncestryAction;
use verification;
use verification::{PreverifiedBlock, Verifier, BlockQueue};
use verification::queue::kind::blocks::Unverified;
use verification::queue::kind::BlockLike;

// re-export
pub use types::blockchain_info::BlockChainInfo;
pub use types::block_status::BlockStatus;
pub use blockchain::CacheSize as BlockChainCacheSize;
pub use verification::QueueInfo as BlockQueueInfo;

use_contract!(registry, "res/contracts/registrar.json");

const MAX_ANCIENT_BLOCKS_QUEUE_SIZE: usize = 4096;
// Max number of blocks imported at once.
const MAX_ANCIENT_BLOCKS_TO_IMPORT: usize = 4;
const MAX_QUEUE_SIZE_TO_SLEEP_ON: usize = 2;
const MIN_HISTORY_SIZE: u64 = 8;

/// Report on the status of a client.
#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct ClientReport {
	/// How many blocks have been imported so far.
	pub blocks_imported: usize,
	/// How many transactions have been applied so far.
	pub transactions_applied: usize,
	/// How much gas has been processed so far.
	pub gas_processed: U256,
	/// Memory used by state DB
	pub state_db_mem: usize,
}

impl ClientReport {
	/// Alter internal reporting to reflect the additional `block` has been processed.
	pub fn accrue_block(&mut self, header: &Header, transactions: usize) {
		self.blocks_imported += 1;
		self.transactions_applied += transactions;
		self.gas_processed = self.gas_processed + *header.gas_used();
	}
}

impl<'a> ::std::ops::Sub<&'a ClientReport> for ClientReport {
	type Output = Self;

	fn sub(mut self, other: &'a ClientReport) -> Self {
		let higher_mem = ::std::cmp::max(self.state_db_mem, other.state_db_mem);
		let lower_mem = ::std::cmp::min(self.state_db_mem, other.state_db_mem);

		self.blocks_imported -= other.blocks_imported;
		self.transactions_applied -= other.transactions_applied;
		self.gas_processed = self.gas_processed - other.gas_processed;
		self.state_db_mem = higher_mem - lower_mem;

		self
	}
}

struct SleepState {
	last_activity: Option<Instant>,
	last_autosleep: Option<Instant>,
}

impl SleepState {
	fn new(awake: bool) -> Self {
		SleepState {
			last_activity: match awake { false => None, true => Some(Instant::now()) },
			last_autosleep: match awake { false => Some(Instant::now()), true => None },
		}
	}
}

/// Blockchain database client backed by a persistent database. Owns and manages a blockchain and a block queue.
/// Call `import_block()` to import a block asynchronously; `flush_queue()` flushes the queue.
pub struct Core<V: BlockChainClient + MinerBlockChainClient> {
	/// Flag used to disable the client forever. Not to be confused with `liveness`.
	///
	/// For example, auto-updater will disable client forever if there is a
	/// hard fork registered on-chain that we don't have capability for.
	/// When hard fork block rolls around, the client (if `update` is false)
	/// knows it can't proceed further.
	enabled: AtomicBool,

	/// Operating mode for the client
	mode: Mutex<Mode>,

	chain: RwLock<Arc<BlockChain>>,
	tracedb: RwLock<TraceDB<BlockChain>>,
	engine: Arc<EthEngine>,

	/// Client configuration
	config: ClientConfig,

	/// Database pruning strategy to use for StateDB
	pruning: journaldb::Algorithm,

	/// Client uses this to store blocks, traces, etc.
	db: RwLock<Arc<BlockChainDB>>,

	state_db: RwLock<StateDB>,

	/// Report on the status of client
	report: RwLock<ClientReport>,

	sleep_state: Mutex<SleepState>,

	/// Flag changed by `sleep` and `wake_up` methods. Not to be confused with `enabled`.
	liveness: AtomicBool,
	io_channel: RwLock<IoChannel<ClientIoMessage>>,

	/// List of actors to be notified on certain chain events
	notify: RwLock<Vec<Weak<ChainNotify>>>,

	/// Queued ancient blocks, make sure they are imported in order.
	queued_ancient_blocks: Arc<RwLock<(
		HashSet<H256>,
		VecDeque<(Unverified, Bytes)>
	)>>,
	ancient_blocks_import_lock: Arc<Mutex<()>>,

	last_hashes: RwLock<VecDeque<H256>>,

	factories: Factories,

	/// Number of eras kept in a journal before they are pruned
	history: u64,

	/// An action to be done if a mode/spec_name change happens
	on_user_defaults_change: Mutex<Option<Box<FnMut(Option<Mode>) + 'static + Send>>>,

	registrar_address: Option<Address>,

	/// A closure to call when we want to restart the client
	exit_handler: Mutex<Option<Box<Fn(String) + 'static + Send>>>,

	/// Lock used during block import
	import_lock: Mutex<()>, // FIXME Maybe wrap the whole `Importer` instead?

	/// Used to verify blocks
	verifier: Box<Verifier<V>>,

	/// Queue containing pending blocks
	block_queue: BlockQueue,

	/// Ancient block verifier: import an ancient sequence of blocks in order from a starting epoch
	ancient_verifier: AncientVerifier,

	/// A lru cache of recently detected bad blocks
	bad_blocks: bad_blocks::BadBlocks,

	/// Miner instance
	miner: Arc<Miner>,
}

impl<V: BlockChainClient + MinerBlockChainClient> Core<V> {
	/// Create a new client with given parameters.
	/// The database is assumed to have been initialized with the correct columns.
	pub fn new(
		config: ClientConfig,
		spec: &Spec,
		db: Arc<BlockChainDB>,
		miner: Arc<Miner>,
		message_channel: IoChannel<ClientIoMessage>,
	) -> Result<Arc<Core<V>>, ::error::Error> {
		let trie_spec = match config.fat_db {
			true => TrieSpec::Fat,
			false => TrieSpec::Secure,
		};

		let trie_factory = TrieFactory::new(trie_spec);
		let factories = Factories {
			vm: VmFactory::new(config.vm_type.clone(), config.jump_table_size),
			trie: trie_factory,
			accountdb: Default::default(),
		};

		let journal_db = journaldb::new(db.key_value().clone(), config.pruning, ::db::COL_STATE);
		let mut state_db = StateDB::new(journal_db, config.state_cache_size);
		if state_db.journal_db().is_empty() {
			// Sets the correct state root.
			state_db = spec.ensure_db_good(state_db, &factories)?;
			let mut batch = DBTransaction::new();
			state_db.journal_under(&mut batch, 0, &spec.genesis_header().hash())?;
			db.key_value().write(batch)?;
		}

		let gb = spec.genesis_block();
		let chain = Arc::new(BlockChain::new(config.blockchain.clone(), &gb, db.clone()));
		let tracedb = RwLock::new(TraceDB::new(config.tracing.clone(), db.clone(), chain.clone()));

		trace!("Cleanup journal: DB Earliest = {:?}, Latest = {:?}", state_db.journal_db().earliest_era(), state_db.journal_db().latest_era());

		let history = if config.history < MIN_HISTORY_SIZE {
			info!(target: "client", "Ignoring pruning history parameter of {}\
				, falling back to minimum of {}",
				config.history, MIN_HISTORY_SIZE);
			MIN_HISTORY_SIZE
		} else {
			config.history
		};

		if !chain.block_header_data(&chain.best_block_hash()).map_or(true, |h| state_db.journal_db().contains(&h.state_root())) {
			warn!("State root not found for block #{} ({:x})", chain.best_block_number(), chain.best_block_hash());
		}

		let engine = spec.engine.clone();

		let awake = match config.mode { Mode::Dark(..) | Mode::Off => false, _ => true };

		let block_queue = BlockQueue::new(config.queue.clone(), engine.clone(), message_channel.clone(), config.verifier_type.verifying_seal());

		let registrar_address = engine.additional_params().get("registrar").and_then(|s| Address::from_str(s).ok());
		if let Some(ref addr) = registrar_address {
			trace!(target: "client", "Found registrar at {}", addr);
		}

		let verifier_type = config.verifier_type.clone();
		let client = Arc::new(Core {
			enabled: AtomicBool::new(true),
			sleep_state: Mutex::new(SleepState::new(awake)),
			liveness: AtomicBool::new(awake),
			mode: Mutex::new(config.mode.clone()),
			chain: RwLock::new(chain),
			tracedb: tracedb,
			engine: engine.clone(),
			pruning: config.pruning.clone(),
			db: RwLock::new(db.clone()),
			state_db: RwLock::new(state_db),
			report: RwLock::new(Default::default()),
			io_channel: RwLock::new(message_channel),
			notify: RwLock::new(Vec::new()),
			queued_ancient_blocks: Default::default(),
			ancient_blocks_import_lock: Default::default(),
			last_hashes: RwLock::new(VecDeque::new()),
			factories: factories,
			history: history,
			on_user_defaults_change: Mutex::new(None),
			registrar_address,
			exit_handler: Mutex::new(None),
			config,
			import_lock: Mutex::new(()),
			verifier: verification::new(verifier_type),
			block_queue,
			ancient_verifier: AncientVerifier::new(engine),
			bad_blocks: Default::default(),
			miner,
		});

		// ensure buffered changes are flushed.
		client.db.read().key_value().flush()?;
		Ok(client)
	}

	/// Wakes up client if it's a sleep.
	pub fn keep_alive(&self) {

		let should_wake = match *self.mode.lock() {
			Mode::Dark(..) | Mode::Passive(..) => true,
			_ => false,
		};
		if should_wake {
			self.wake_up();
			(*self.sleep_state.lock()).last_activity = Some(Instant::now());
		}
	}

	/// Adds an actor to be notified on certain events
	pub fn add_notify(&self, target: Arc<ChainNotify>) {
		self.notify.write().push(Arc::downgrade(&target));
	}

	/// Set a closure to call when the client wants to be restarted.
	///
	/// The parameter passed to the callback is the name of the new chain spec to use after
	/// the restart.
	pub fn set_exit_handler<F>(&self, f: F) where F: Fn(String) + 'static + Send {
		*self.exit_handler.lock() = Some(Box::new(f));
	}

	/// Returns engine reference.
	pub fn engine(&self) -> &EthEngine {
		&*self.engine
	}

	fn notify<F>(&self, f: F) where F: Fn(&ChainNotify) {
		for np in &*self.notify.read() {
			if let Some(n) = np.upgrade() {
				f(&*n);
			}
		}
	}

	/// Register an action to be done if a mode/spec_name change happens.
	pub fn on_user_defaults_change<F>(&self, f: F) where F: 'static + FnMut(Option<Mode>) + Send {
		*self.on_user_defaults_change.lock() = Some(Box::new(f));
	}

	/// Flush the block import queue.
	pub fn flush_queue(&self, client: &V) {
		self.block_queue.flush();
		while !self.block_queue.is_empty() {
			self.import_verified_blocks(client);
		}
	}

	/// The env info as of the best block.
	pub fn latest_env_info<C: super::traits::EngineClient>(&self, client: &C) -> EnvInfo {
		self.env_info(BlockId::Latest, client).expect("Best block header always stored; qed")
	}

	/// The env info as of a given block.
	/// returns `None` if the block unknown.
	pub fn env_info<C: super::traits::EngineClient>(&self, id: BlockId, client: &C) -> Option<EnvInfo> {
		client.block_header(id).map(|header| {
			EnvInfo {
				number: header.number(),
				author: header.author(),
				timestamp: header.timestamp(),
				difficulty: header.difficulty(),
				last_hashes: self.build_last_hashes(&header.parent_hash()),
				gas_used: U256::default(),
				gas_limit: header.gas_limit(),
			}
		})
	}

	fn build_last_hashes(&self, parent_hash: &H256) -> Arc<LastHashes> {
		{
			let hashes = self.last_hashes.read();
			if hashes.front().map_or(false, |h| h == parent_hash) {
				let mut res = Vec::from(hashes.clone());
				res.resize(256, H256::default());
				return Arc::new(res);
			}
		}
		let mut last_hashes = LastHashes::new();
		last_hashes.resize(256, H256::default());
		last_hashes[0] = parent_hash.clone();
		let chain = self.chain.read();
		for i in 0..255 {
			match chain.block_details(&last_hashes[i]) {
				Some(details) => {
					last_hashes[i + 1] = details.parent.clone();
				},
				None => break,
			}
		}
		let mut cached_hashes = self.last_hashes.write();
		*cached_hashes = VecDeque::from(last_hashes.clone());
		Arc::new(last_hashes)
	}

	// use a state-proving closure for the given block.
	fn with_proving_caller<F, T, C: ProvingBlockChainClient>(&self, id: BlockId, with_call: F, client: &C) -> T
		where F: FnOnce(&::machine::Call) -> T
	{
		let call = |a, d| {
			let tx = self.contract_call_tx(id, a, d, client);
			let (result, items) = client.prove_transaction(tx, id)
				.ok_or_else(|| format!("Unable to make call. State unavailable?"))?;

			let items = items.into_iter().map(|x| x.to_vec()).collect();
			Ok((result, items))
		};

		with_call(&call)
	}

	// prune ancient states until below the memory limit or only the minimum amount remain.
	fn prune_ancient(&self, mut state_db: StateDB, chain: &BlockChain) -> Result<(), ::error::Error> {
		let number = match state_db.journal_db().latest_era() {
			Some(n) => n,
			None => return Ok(()),
		};

		// prune all ancient eras until we're below the memory target,
		// but have at least the minimum number of states.
		loop {
			let needs_pruning = state_db.journal_db().is_pruned() &&
				state_db.journal_db().journal_size() >= self.config.history_mem;

			if !needs_pruning { break }
			match state_db.journal_db().earliest_era() {
				Some(era) if era + self.history <= number => {
					trace!(target: "client", "Pruning state for ancient era {}", era);
					match chain.block_hash(era) {
						Some(ancient_hash) => {
							let mut batch = DBTransaction::new();
							state_db.mark_canonical(&mut batch, era, &ancient_hash)?;
							self.db.read().key_value().write_buffered(batch);
							state_db.journal_db().flush();
						}
						None =>
							debug!(target: "client", "Missing expected hash for block {}", era),
					}
				}
				_ => break, // means that every era is kept, no pruning necessary.
			}
		}

		Ok(())
	}

	fn update_last_hashes(&self, parent: &H256, hash: &H256) {
		let mut hashes = self.last_hashes.write();
		if hashes.front().map_or(false, |h| h == parent) {
			if hashes.len() > 255 {
				hashes.pop_back();
			}
			hashes.push_front(hash.clone());
		}
	}

	/// Get shared miner reference.
	#[cfg(test)]
	pub fn miner(&self) -> Arc<Miner> {
		self.miner.clone()
	}

	#[cfg(test)]
	pub fn state_db(&self) -> ::parking_lot::RwLockReadGuard<StateDB> {
		self.state_db.read()
	}

	#[cfg(test)]
	pub fn chain(&self) -> Arc<BlockChain> {
		self.chain.read().clone()
	}

	/// Replace io channel. Useful for testing.
	pub fn set_io_channel(&self, io_channel: IoChannel<ClientIoMessage>) {
		*self.io_channel.write() = io_channel;
	}

	/// Get info on the cache.
	pub fn blockchain_cache_info(&self) -> BlockChainCacheSize {
		self.chain.read().cache_size()
	}

	/// Tick the client.
	// TODO: manage by real events.
	pub fn tick<C: BlockChainClient>(&self, prevent_sleep: bool, client: &C) {
		self.check_garbage();
		if !prevent_sleep {
			self.check_snooze(client);
		}
	}

	fn check_garbage(&self) {
		self.chain.read().collect_garbage();
		self.block_queue.collect_garbage();
		self.tracedb.read().collect_garbage();
	}

	fn check_snooze<C: BlockChainClient>(&self, client: &C) {
		let mode = self.mode.lock().clone();
		match mode {
			Mode::Dark(timeout) => {
				let mut ss = self.sleep_state.lock();
				if let Some(t) = ss.last_activity {
					if Instant::now() > t + timeout {
						self.sleep(client);
						ss.last_activity = None;
					}
				}
			}
			Mode::Passive(timeout, wakeup_after) => {
				let mut ss = self.sleep_state.lock();
				let now = Instant::now();
				if let Some(t) = ss.last_activity {
					if now > t + timeout {
						self.sleep(client);
						ss.last_activity = None;
						ss.last_autosleep = Some(now);
					}
				}
				if let Some(t) = ss.last_autosleep {
					if now > t + wakeup_after {
						self.wake_up();
						ss.last_activity = Some(now);
						ss.last_autosleep = None;
					}
				}
			}
			_ => {}
		}
	}

	/// Take a snapshot at the given block.
	/// If the ID given is "latest", this will default to 1000 blocks behind.
	pub fn take_snapshot<W: snapshot_io::SnapshotWriter + Send, C: BlockChainClient>(&self, writer: W, at: BlockId, p: &snapshot::Progress, client: &C) -> Result<(), EthcoreError> {
		let db = self.state_db.read().journal_db().boxed_clone();
		let best_block_number = self.chain_info().best_block_number;
		let block_number = client.block_number(at).ok_or(snapshot::Error::InvalidStartingBlock(at))?;

		if db.is_pruned() && client.pruning_info().earliest_state > block_number {
			return Err(snapshot::Error::OldBlockPrunedDB.into());
		}

		let history = ::std::cmp::min(self.history, 1000);

		let start_hash = match at {
			BlockId::Latest => {
				let start_num = match db.earliest_era() {
					Some(era) => ::std::cmp::max(era, best_block_number.saturating_sub(history)),
					None => best_block_number.saturating_sub(history),
				};

				match client.block_hash(BlockId::Number(start_num)) {
					Some(h) => h,
					None => return Err(snapshot::Error::InvalidStartingBlock(at).into()),
				}
			}
			_ => match client.block_hash(at) {
				Some(hash) => hash,
				None => return Err(snapshot::Error::InvalidStartingBlock(at).into()),
			},
		};

		let processing_threads = self.config.snapshot.processing_threads;
		snapshot::take_snapshot(&*self.engine, &self.chain.read(), start_hash, db.as_hashdb(), writer, p, processing_threads)?;

		Ok(())
	}

	/// Ask the client what the history parameter is.
	pub fn pruning_history(&self) -> u64 {
		self.history
	}

	fn block_hash(chain: &BlockChain, id: BlockId) -> Option<H256> {
		match id {
			BlockId::Hash(hash) => Some(hash),
			BlockId::Number(number) => chain.block_hash(number),
			BlockId::Earliest => chain.block_hash(0),
			BlockId::Latest => Some(chain.best_block_hash()),
		}
	}

	fn transaction_address(&self, id: TransactionId) -> Option<TransactionAddress> {
		match id {
			TransactionId::Hash(ref hash) => self.chain.read().transaction_address(hash),
			TransactionId::Location(id, index) => Self::block_hash(&self.chain.read(), id).map(|hash| TransactionAddress {
				block_hash: hash,
				index: index,
			})
		}
	}

	fn wake_up(&self) {
		if !self.liveness.load(AtomicOrdering::Relaxed) {
			self.liveness.store(true, AtomicOrdering::Relaxed);
			self.notify(|n| n.start());
			info!(target: "mode", "wake_up: Waking.");
		}
	}

	fn sleep<C: BlockChainClient>(&self, client: &C) {
		if self.liveness.load(AtomicOrdering::Relaxed) {
			// only sleep if the import queue is mostly empty.
			if client.queue_info().total_queue_size() <= MAX_QUEUE_SIZE_TO_SLEEP_ON {
				self.liveness.store(false, AtomicOrdering::Relaxed);
				self.notify(|n| n.stop());
				info!(target: "mode", "sleep: Sleeping.");
			} else {
				info!(target: "mode", "sleep: Cannot sleep - syncing ongoing.");
				// TODO: Consider uncommenting.
				//(*self.sleep_state.lock()).last_activity = Some(Instant::now());
			}
		}
	}

	// transaction for calling contracts from services like engine.
	// from the null sender, with 50M gas.
	fn contract_call_tx<C: Nonce>(&self, block_id: BlockId, address: Address, data: Bytes, client: &C) -> SignedTransaction {
		let from = Address::default();
		Transaction {
			nonce: client.nonce(&from, block_id).unwrap_or_else(|| self.engine.account_start_nonce(0)),
			action: Action::Call(address),
			gas: U256::from(50_000_000),
			gas_price: U256::default(),
			value: U256::default(),
			data: data,
		}.fake_sign(from)
	}

	fn do_virtual_call<B: Backend + Clone>(
		machine: &::machine::EthereumMachine,
		env_info: &EnvInfo,
		state: &mut State<B>,
		t: &SignedTransaction,
		analytics: CallAnalytics,
	) -> Result<Executed, CallError> {
		fn call<V, T, B: Backend + Clone>(
			state: &mut State<B>,
			env_info: &EnvInfo,
			machine: &::machine::EthereumMachine,
			state_diff: bool,
			transaction: &SignedTransaction,
			options: TransactOptions<T, V>,
		) -> Result<Executed<T::Output, V::Output>, CallError> where
			T: trace::Tracer,
			V: trace::VMTracer,
		{
			let options = options
				.dont_check_nonce()
				.save_output_from_contract();
			let original_state = if state_diff { Some(state.clone()) } else { None };
			let schedule = machine.schedule(env_info.number);

			let mut ret = Executive::new(state, env_info, &machine, &schedule).transact_virtual(transaction, options)?;

			if let Some(original) = original_state {
				ret.state_diff = Some(state.diff_from(original).map_err(ExecutionError::from)?);
			}
			Ok(ret)
		}

		let state_diff = analytics.state_diffing;

		match (analytics.transaction_tracing, analytics.vm_tracing) {
			(true, true) => call(state, env_info, machine, state_diff, t, TransactOptions::with_tracing_and_vm_tracing()),
			(true, false) => call(state, env_info, machine, state_diff, t, TransactOptions::with_tracing()),
			(false, true) => call(state, env_info, machine, state_diff, t, TransactOptions::with_vm_tracing()),
			(false, false) => call(state, env_info, machine, state_diff, t, TransactOptions::with_no_tracing()),
		}
	}

	fn block_number_ref(&self, id: &BlockId) -> Option<BlockNumber> {
		match *id {
			BlockId::Number(number) => Some(number),
			BlockId::Hash(ref hash) => self.chain.read().block_number(hash),
			BlockId::Earliest => Some(0),
			BlockId::Latest => Some(self.chain.read().best_block_number()),
		}
	}

	/// Retrieve a decoded header given `BlockId`
	///
	/// This method optimizes access patterns for latest block header
	/// to avoid excessive RLP encoding, decoding and hashing.
	fn block_header_decoded<C: BlockInfo>(&self, id: BlockId, client: &C) -> Option<Header> {
		match id {
			BlockId::Latest
				=> Some(self.chain.read().best_block_header()),
			BlockId::Hash(ref hash) if hash == &self.chain.read().best_block_hash()
				=> Some(self.chain.read().best_block_header()),
			BlockId::Number(number) if number == self.chain.read().best_block_number()
				=> Some(self.chain.read().best_block_header()),
			_   => client.block_header(id).and_then(|h| h.decode().ok())
		}
	}

	/// This is triggered by a message coming from a block queue when the block is ready for insertion
	pub fn import_verified_blocks(&self, client: &V) -> usize {
		// Shortcut out if we know we're incapable of syncing the chain.
		if !self.enabled.load(AtomicOrdering::Relaxed) {
			return 0;
		}

		let max_blocks_to_import = self.config.max_round_blocks_to_import;
		let (imported_blocks, import_results, invalid_blocks, imported, proposed_blocks, duration, has_more_blocks_to_import) = {
			let mut imported_blocks = Vec::with_capacity(max_blocks_to_import);
			let mut invalid_blocks = HashSet::new();
			let mut proposed_blocks = Vec::with_capacity(max_blocks_to_import);
			let mut import_results = Vec::with_capacity(max_blocks_to_import);

			let _import_lock = self.import_lock.lock();
			let blocks = self.block_queue.drain(max_blocks_to_import);
			if blocks.is_empty() {
				return 0;
			}
			trace_time!("import_verified_blocks");
			let start = Instant::now();

			for block in blocks {
				let header = block.header.clone();
				let bytes = block.bytes.clone();
				let hash = header.hash();

				let is_invalid = invalid_blocks.contains(header.parent_hash());
				if is_invalid {
					invalid_blocks.insert(hash);
					continue;
				}

				match self.check_and_lock_block(block, client) {
					Ok(closed_block) => {
						if self.engine.is_proposal(&header) {
							self.block_queue.mark_as_good(&[hash]);
							proposed_blocks.push(bytes);
						} else {
							imported_blocks.push(hash);

							let transactions_len = closed_block.transactions().len();

							let route = self.commit_block(closed_block, &header, encoded::Block::new(bytes), client);
							import_results.push(route);

							self.report.write().accrue_block(&header, transactions_len);
						}
					},
					Err(err) => {
						self.bad_blocks.report(bytes, format!("{:?}", err));
						invalid_blocks.insert(hash);
					},
				}
			}

			let imported = imported_blocks.len();
			let invalid_blocks = invalid_blocks.into_iter().collect::<Vec<H256>>();

			if !invalid_blocks.is_empty() {
				self.block_queue.mark_as_bad(&invalid_blocks);
			}
			let has_more_blocks_to_import = !self.block_queue.mark_as_good(&imported_blocks);
			(imported_blocks, import_results, invalid_blocks, imported, proposed_blocks, start.elapsed(), has_more_blocks_to_import)
		};

		{
			if !imported_blocks.is_empty() {
				let route = ChainRoute::from(import_results.as_ref());

				if !has_more_blocks_to_import {
					self.miner.chain_new_blocks(client, &imported_blocks, &invalid_blocks, route.enacted(), route.retracted(), false);
				}

				self.notify(|notify| {
					notify.new_blocks(
						NewBlocks::new(
						imported_blocks.clone(),
						invalid_blocks.clone(),
						route.clone(),
						Vec::new(),
						proposed_blocks.clone(),
						duration,
							has_more_blocks_to_import,
						)
					);
				});
			}
		}

		let db = self.db.read();
		db.key_value().flush().expect("DB flush failed.");
		imported
	}

	fn check_and_lock_block(&self, block: PreverifiedBlock, client: &V) -> EthcoreResult<LockedBlock> {
		let engine = &*self.engine;
		let header = block.header.clone();

		// Check the block isn't so old we won't be able to enact it.
		let best_block_number = self.chain.read().best_block_number();
		if client.pruning_info().earliest_state > header.number() {
			warn!(target: "client", "Block import failed for #{} ({})\nBlock is ancient (current best block: #{}).", header.number(), header.hash(), best_block_number);
			bail!("Block is ancient");
		}

		// Check if parent is in chain
		let parent = match self.block_header_decoded(BlockId::Hash(*header.parent_hash()), client) {
			Some(h) => h,
			None => {
				warn!(target: "client", "Block import failed for #{} ({}): Parent not found ({}) ", header.number(), header.hash(), header.parent_hash());
				bail!("Parent not found");
			}
		};

		let chain = self.chain.read();
		// Verify Block Family
		let verify_family_result = self.verifier.verify_block_family(
			&header,
			&parent,
			engine,
			Some(verification::FullFamilyParams {
				block: &block,
				block_provider: &**chain,
				client: client,
			}),
		);

		if let Err(e) = verify_family_result {
			warn!(target: "client", "Stage 3 block verification failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
			bail!(e);
		};

		let verify_external_result = self.verifier.verify_block_external(&header, engine);
		if let Err(e) = verify_external_result {
			warn!(target: "client", "Stage 4 block verification failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
			bail!(e);
		};

		// Enact Verified Block
		let last_hashes = self.build_last_hashes(header.parent_hash());
		let db = self.state_db.read().boxed_clone_canon(header.parent_hash());

		let is_epoch_begin = chain.epoch_transition(parent.number(), *header.parent_hash()).is_some();
		let enact_result = enact_verified(
			block,
			engine,
			self.tracedb.read().tracing_enabled(),
			db,
			&parent,
			last_hashes,
			self.factories.clone(),
			is_epoch_begin,
			&mut chain.ancestry_with_metadata_iter(*header.parent_hash()),
		);

		let mut locked_block = match enact_result {
			Ok(b) => b,
			Err(e) => {
				warn!(target: "client", "Block import failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
				bail!(e);
			}
		};

		// Strip receipts for blocks before validate_receipts_transition,
		// if the expected receipts root header does not match.
		// (i.e. allow inconsistency in receipts outcome before the transition block)
		if header.number() < engine.params().validate_receipts_transition
			&& header.receipts_root() != locked_block.block().header().receipts_root()
		{
			locked_block.strip_receipts_outcomes();
		}

		// Final Verification
		if let Err(e) = self.verifier.verify_block_final(&header, locked_block.block().header()) {
			warn!(target: "client", "Stage 5 block verification failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
			bail!(e);
		}

		Ok(locked_block)
	}

	/// Import a block with transaction receipts.
	///
	/// The block is guaranteed to be the next best blocks in the
	/// first block sequence. Does no sealing or transaction validation.
	fn import_old_block(&self, unverified: Unverified, receipts_bytes: &[u8], db: &KeyValueDB, chain: &BlockChain) -> EthcoreResult<()> {
		let receipts = ::rlp::decode_list(receipts_bytes);
		let _import_lock = self.import_lock.lock();

		{
			trace_time!("import_old_block");
			// verify the block, passing the chain for updating the epoch verifier.
			let mut rng = OsRng::new()?;
			self.ancient_verifier.verify(&mut rng, &unverified.header, &chain)?;

			// Commit results
			let mut batch = DBTransaction::new();
			chain.insert_unordered_block(&mut batch, encoded::Block::new(unverified.bytes), receipts, None, false, true);
			// Final commit to the DB
			db.write_buffered(batch);
			chain.commit();
		}
		db.flush().expect("DB flush failed.");
		Ok(())
	}

	// NOTE: the header of the block passed here is not necessarily sealed, as
	// it is for reconstructing the state transition.
	//
	// The header passed is from the original block data and is sealed.
	fn commit_block<B, C: BlockInfo + Nonce>(&self, block: B, header: &Header, block_data: encoded::Block, client: &C) -> ImportRoute where B: Drain {
		let hash = &header.hash();
		let number = header.number();
		let parent = header.parent_hash();
		let chain = self.chain.read();
		let mut is_finalized = false;

		// Commit results
		let block = block.drain();
		debug_assert_eq!(header.hash(), block_data.header_view().hash());

		let mut batch = DBTransaction::new();

		let ancestry_actions = self.engine.ancestry_actions(&header, &mut chain.ancestry_with_metadata_iter(*parent));

		let receipts = block.receipts;
		let traces = block.traces.drain();
		let best_hash = chain.best_block_hash();

		let new = ExtendedHeader {
			header: header.clone(),
			is_finalized,
			parent_total_difficulty: chain.block_details(&parent).expect("Parent block is in the database; qed").total_difficulty
		};

		let best = {
			let hash = best_hash;
			let header = chain.block_header_data(&hash)
				.expect("Best block is in the database; qed")
				.decode()
				.expect("Stored block header is valid RLP; qed");
			let details = chain.block_details(&hash)
				.expect("Best block is in the database; qed");

			ExtendedHeader {
				parent_total_difficulty: details.total_difficulty - *header.difficulty(),
				is_finalized: details.is_finalized,
				header: header,
			}
		};

		let route = chain.tree_route(best_hash, *parent).expect("forks are only kept when it has common ancestors; tree route from best to prospective's parent always exists; qed");
		let fork_choice = if route.is_from_route_finalized {
			ForkChoice::Old
		} else {
			self.engine.fork_choice(&new, &best)
		};

		// CHECK! I *think* this is fine, even if the state_root is equal to another
		// already-imported block of the same number.
		// TODO: Prove it with a test.
		let mut prove_state = block.state.drop().1;
		prove_state.persist();
		let mut state = prove_state.base();

		// check epoch end signal, potentially generating a proof on the current
		// state.
		self.check_epoch_end_signal(
			&header,
			block_data.raw(),
			&receipts,
			&state,
			&chain,
			&mut batch,
			client
		);

		state.journal_under(&mut batch, number, hash).expect("DB commit failed");

		let finalized: Vec<_> = ancestry_actions.into_iter().map(|ancestry_action| {
			let AncestryAction::MarkFinalized(a) = ancestry_action;

			if a != header.hash() {
				chain.mark_finalized(&mut batch, a).expect("Engine's ancestry action must be known blocks; qed");
			} else {
				// we're finalizing the current block
				is_finalized = true;
			}

			a
		}).collect();

		let route = chain.insert_block(&mut batch, block_data, receipts.clone(), ExtrasInsert {
			fork_choice: fork_choice,
			is_finalized,
		});

		self.tracedb.read().import(&mut batch, TraceImportRequest {
			traces: traces.into(),
			block_hash: hash.clone(),
			block_number: number,
			enacted: route.enacted.clone(),
			retracted: route.retracted.len()
		});

		let is_canon = route.enacted.last().map_or(false, |h| h == hash);
		state.sync_cache(&route.enacted, &route.retracted, is_canon);
		// Final commit to the DB
		self.db.read().key_value().write_buffered(batch);
		chain.commit();

		self.check_epoch_end(&header, &finalized, &chain, client);

		self.update_last_hashes(&parent, hash);

		if let Err(e) = self.prune_ancient(state, &chain) {
			warn!("Failed to prune ancient state data: {}", e);
		}

		route
	}

	// check for epoch end signal and write pending transition if it occurs.
	// state for the given block must be available.
	fn check_epoch_end_signal<C: Nonce>(
		&self,
		header: &Header,
		block_bytes: &[u8],
		receipts: &[Receipt],
		state_db: &StateDB,
		chain: &BlockChain,
		batch: &mut DBTransaction,
		client: &C,
	) {
		use engines::EpochChange;

		let hash = header.hash();
		let auxiliary = ::machine::AuxiliaryData {
			bytes: Some(block_bytes),
			receipts: Some(&receipts),
		};

		match self.engine.signals_epoch_end(header, auxiliary) {
			EpochChange::Yes(proof) => {
				use engines::epoch::PendingTransition;
				use engines::Proof;

				let proof = match proof {
					Proof::Known(proof) => proof,
					Proof::WithState(with_state) => {
						let env_info = EnvInfo {
							number: header.number(),
							author: header.author().clone(),
							timestamp: header.timestamp(),
							difficulty: header.difficulty().clone(),
							last_hashes: self.build_last_hashes(header.parent_hash()),
							gas_used: U256::default(),
							gas_limit: u64::max_value().into(),
						};

						let call = move |addr, data| {
							let mut state_db = state_db.boxed_clone();
							let backend = ::state::backend::Proving::new(state_db.as_hashdb_mut());

							let transaction =
								self.contract_call_tx(BlockId::Hash(*header.parent_hash()), addr, data, client);

							let mut state = State::from_existing(
								backend,
								header.state_root().clone(),
								self.engine.account_start_nonce(header.number()),
								self.factories.clone(),
							).expect("state known to be available for just-imported block; qed");

							let options = TransactOptions::with_no_tracing().dont_check_nonce();
							let machine = self.engine.machine();
							let schedule = machine.schedule(env_info.number);
							let res = Executive::new(&mut state, &env_info, &machine, &schedule)
								.transact(&transaction, options);

							match res {
								Err(ExecutionError::Internal(e)) =>
									Err(format!("Internal error: {}", e)),
								Err(e) => {
									trace!(target: "client", "Proved call failed: {}", e);
									let proof_vec: Vec<ProofElement> = state.drop().1.extract_proof().into();
									let proof_data: Vec<Vec<u8>> = proof_vec.into_iter().map(|x| {
										let value: DBValue = x.into();
										value.into_vec()
									}).collect();
									Ok((Vec::new(), proof_data))
								}
								Ok(res) => {
									let proof_vec: Vec<ProofElement> = state.drop().1.extract_proof().into();
									let proof_data: Vec<Vec<u8>> = proof_vec.into_iter().map(|x| {
										let value: DBValue = x.into();
										value.into_vec()
									}).collect();
									Ok((res.output, proof_data))
								},
							}
						};

						match with_state.generate_proof(&call) {
							Ok(proof) => proof,
							Err(e) => {
								warn!(target: "client", "Failed to generate transition proof for block {}: {}", hash, e);
								warn!(target: "client", "Snapshots produced by this client may be incomplete");
								Vec::new()
							}
						}
					}
				};

				debug!(target: "client", "Block {} signals epoch end.", hash);

				let pending = PendingTransition { proof: proof };
				chain.insert_pending_transition(batch, hash, pending);
			},
			EpochChange::No => {},
			EpochChange::Unsure(_) => {
				warn!(target: "client", "Detected invalid engine implementation.");
				warn!(target: "client", "Engine claims to require more block data, but everything provided.");
			}
		}
	}

	// check for ending of epoch and write transition if it occurs.
	fn check_epoch_end<'a, C: BlockInfo>(&self, header: &'a Header, finalized: &'a [H256], chain: &BlockChain, client: &C) {
		let is_epoch_end = self.engine.is_epoch_end(
			header,
			finalized,
			&(|hash| self.block_header_decoded(BlockId::Hash(hash), client)),
			&(|hash| chain.get_pending_transition(hash)), // TODO: limit to current epoch.
		);

		if let Some(proof) = is_epoch_end {
			debug!(target: "client", "Epoch transition at block {}", header.hash());

			let mut batch = DBTransaction::new();
			chain.insert_epoch_transition(&mut batch, header.number(), EpochTransition {
				block_hash: header.hash(),
				block_number: header.number(),
				proof: proof,
			});

			// always write the batch directly since epoch transition proofs are
			// fetched from a DB iterator and DB iterators are only available on
			// flushed data.
			self.db.read().key_value().write(batch).expect("DB flush failed");
		}
	}

	fn call<B: Backend + Clone>(&self, transaction: &SignedTransaction, analytics: CallAnalytics, state: &mut State<B>, header: &Header) -> Result<Executed, CallError> {
		let env_info = EnvInfo {
			number: header.number(),
			author: header.author().clone(),
			timestamp: header.timestamp(),
			difficulty: header.difficulty().clone(),
			last_hashes: self.build_last_hashes(header.parent_hash()),
			gas_used: U256::default(),
			gas_limit: U256::max_value(),
		};
		let machine = self.engine.machine();

		Self::do_virtual_call(&machine, &env_info, state, transaction, analytics)
	}

	fn call_many<B: Backend + Clone>(&self, transactions: &[(SignedTransaction, CallAnalytics)], state: &mut State<B>, header: &Header) -> Result<Vec<Executed>, CallError> {
		let mut env_info = EnvInfo {
			number: header.number(),
			author: header.author().clone(),
			timestamp: header.timestamp(),
			difficulty: header.difficulty().clone(),
			last_hashes: self.build_last_hashes(header.parent_hash()),
			gas_used: U256::default(),
			gas_limit: U256::max_value(),
		};

		let mut results = Vec::with_capacity(transactions.len());
		let machine = self.engine.machine();

		for &(ref t, analytics) in transactions {
			let ret = Self::do_virtual_call(machine, &env_info, state, t, analytics)?;
			env_info.gas_used = ret.cumulative_gas_used;
			results.push(ret);
		}

		Ok(results)
	}

	fn estimate_gas<B: Backend + Clone>(&self, t: &SignedTransaction, state: &State<B>, header: &Header) -> Result<U256, CallError> {
		let (mut upper, max_upper, env_info) = {
			let init = *header.gas_limit();
			let max = init * U256::from(10);

			let env_info = EnvInfo {
				number: header.number(),
				author: header.author().clone(),
				timestamp: header.timestamp(),
				difficulty: header.difficulty().clone(),
				last_hashes: self.build_last_hashes(header.parent_hash()),
				gas_used: U256::default(),
				gas_limit: max,
			};

			(init, max, env_info)
		};

		let sender = t.sender();
		let options = || TransactOptions::with_tracing().dont_check_nonce();

		let exec = |gas| {
			let mut tx = t.as_unsigned().clone();
			tx.gas = gas;
			let tx = tx.fake_sign(sender);

			let mut clone = state.clone();
			let machine = self.engine.machine();
			let schedule = machine.schedule(env_info.number);
			Executive::new(&mut clone, &env_info, &machine, &schedule)
				.transact_virtual(&tx, options())
				.ok()
				.map(|r| r.exception.is_none())
		};

		let cond = |gas| exec(gas).unwrap_or(false);

		if !cond(upper) {
			upper = max_upper;
			match exec(upper) {
				Some(false) => return Err(CallError::Exceptional),
				None => {
					trace!(target: "estimate_gas", "estimate_gas failed with {}", upper);
					let err = ExecutionError::Internal(format!("Requires higher than upper limit of {}", upper));
					return Err(err.into())
				},
				_ => {},
			}
		}
		let lower = t.gas_required(&self.engine.schedule(env_info.number)).into();
		if cond(lower) {
			trace!(target: "estimate_gas", "estimate_gas succeeded with {}", lower);
			return Ok(lower)
		}

		/// Find transition point between `lower` and `upper` where `cond` changes from `false` to `true`.
		/// Returns the lowest value between `lower` and `upper` for which `cond` returns true.
		/// We assert: `cond(lower) = false`, `cond(upper) = true`
		fn binary_chop<F, E>(mut lower: U256, mut upper: U256, mut cond: F) -> Result<U256, E>
			where F: FnMut(U256) -> bool
		{
			while upper - lower > 1.into() {
				let mid = (lower + upper) / 2;
				trace!(target: "estimate_gas", "{} .. {} .. {}", lower, mid, upper);
				let c = cond(mid);
				match c {
					true => upper = mid,
					false => lower = mid,
				};
				trace!(target: "estimate_gas", "{} => {} .. {}", c, lower, upper);
			}
			Ok(upper)
		}

		// binary chop to non-excepting call with gas somewhere between 21000 and block gas limit
		trace!(target: "estimate_gas", "estimate_gas chopping {} .. {}", lower, upper);
		binary_chop(lower, upper, cond)
	}

	/// Restart the client with a new backend
	fn restore_db(&self, new_db: &str) -> Result<(), EthcoreError> {
		trace!(target: "snapshot", "Replacing client database with {:?}", new_db);

		let _import_lock = self.import_lock.lock();
		let mut state_db = self.state_db.write();
		let mut chain = self.chain.write();
		let mut tracedb = self.tracedb.write();
		self.miner.clear();
		let db = self.db.write();
		db.restore(new_db)?;

		let cache_size = state_db.cache_size();
		*chain = Arc::new(BlockChain::new(self.config.blockchain.clone(), &[], db.clone()));
		*tracedb = TraceDB::new(self.config.tracing.clone(), db.clone(), chain.clone());
		Ok(())
	}

	fn import_sealed_block<C: MinerBlockChainClient>(&self, block: SealedBlock, client: &C) -> EthcoreResult<H256> {
		let start = Instant::now();
		let raw = block.rlp_bytes();
		let header = block.header().clone();
		let hash = header.hash();
		self.notify(|n| n.block_pre_import(&raw, &hash, header.difficulty()));

		let route = {
			// Do a super duper basic verification to detect potential bugs
			if let Err(e) = self.engine.verify_block_basic(&header) {
				self.bad_blocks.report(
					block.rlp_bytes(),
					format!("Detected an issue with locally sealed block: {}", e),
				);
				return Err(e.into());
			}

			// scope for self.import_lock
			let _import_lock = self.import_lock.lock();
			trace_time!("import_sealed_block");

			let block_data = block.rlp_bytes();

			let route = self.commit_block(block, &header, encoded::Block::new(block_data), client);
			trace!(target: "client", "Imported sealed block #{} ({})", header.number(), hash);
			self.state_db.write().sync_cache(&route.enacted, &route.retracted, false);
			route
		};
		let route = ChainRoute::from([route].as_ref());
		self.miner.chain_new_blocks(
			client,
			&[hash],
			&[],
			route.enacted(),
			route.retracted(),
			self.engine.seals_internally().is_some(),
		);
		self.notify(|notify| {
			notify.new_blocks(
				NewBlocks::new(
					vec![hash],
					vec![],
					route.clone(),
					vec![hash],
					vec![],
					start.elapsed(),
					false
				)
			);
		});
		self.db.read().key_value().flush().expect("DB flush failed.");
		Ok(hash)
	}

	fn update_sealing<C: BlockChainTrait + CallContract + BlockProducer + SealedBlockImporter + Nonce + ProvingCallContract + Sync>(&self, client: &C) {
		self.miner.update_sealing(client)
	}

	fn submit_seal<C: BlockChainClient + MinerBlockChainClient>(&self, block_hash: H256, seal: Vec<Bytes>, client: &C) {
		let import = self.miner.submit_seal(block_hash, seal).and_then(|block| self.import_sealed_block(block, client));
		if let Err(err) = import {
			warn!(target: "poa", "Wrong internal seal submission! {:?}", err);
		}
	}

	fn broadcast_consensus_message(&self, message: Bytes) {
		self.notify(|notify| notify.broadcast(ChainMessageType::Consensus(message.clone())));
	}

	fn epoch_transition_for(&self, parent_hash: H256) -> Option<::engines::EpochTransition> {
		self.chain.read().epoch_transition_for(parent_hash)
	}

	fn registry_address<C: CallContract>(&self, name: String, block: BlockId, client: &C) -> Option<Address> {
		use ethabi::FunctionOutputDecoder;

		let address = self.registrar_address?;

		let (data, decoder) = registry::functions::get_address::call(keccak(name.as_bytes()), "A");
		let value = decoder.decode(&client.call_contract(block, address, data).ok()?).ok()?;
		if value.is_zero() {
			None
		} else {
			Some(value)
		}
	}

	fn latest_schedule<C: super::traits::EngineClient>(&self, client: &C) -> Schedule {
		self.engine.schedule(self.latest_env_info(client).number)
	}
}

impl<V: BlockChainClient + MinerBlockChainClient> ChainInfo for Core<V> {
	fn chain_info(&self) -> BlockChainInfo {
		let mut chain_info = self.chain.read().chain_info();
		chain_info.pending_total_difficulty = chain_info.total_difficulty + self.block_queue.total_difficulty();
		chain_info
	}
}

impl<V: BlockChainClient + MinerBlockChainClient> TransactionInfo for Core<V> {
	fn transaction_block(&self, id: TransactionId) -> Option<H256> {
		self.transaction_address(id).map(|addr| addr.block_hash)
	}
}


impl<V: BlockChainClient + MinerBlockChainClient> EngineInfo for Core<V> {
	fn engine(&self) -> &EthEngine {
		Core::engine(self)
	}
}

impl<V: BlockChainClient + MinerBlockChainClient> BadBlocks for Core<V> {
	fn bad_blocks(&self) -> Vec<(Unverified, String)> {
		self.bad_blocks.bad_blocks()
	}
}

impl<V: BlockChainClient + MinerBlockChainClient> ReopenBlock for Core<V> {
	fn reopen_block(&self, block: ClosedBlock) -> OpenBlock {
		let engine = &*self.engine;
		let mut block = block.reopen(engine);
		let max_uncles = engine.maximum_uncle_count(block.header().number());
		if block.uncles().len() < max_uncles {
			let chain = self.chain.read();
			let h = chain.best_block_hash();
			// Add new uncles
			let uncles = chain
				.find_uncle_hashes(&h, engine.maximum_uncle_age())
				.unwrap_or_else(Vec::new);

			for h in uncles {
				if !block.uncles().iter().any(|header| header.hash() == h) {
					let uncle = chain.block_header_data(&h).expect("find_uncle_hashes only returns hashes for existing headers; qed");
					let uncle = uncle.decode().expect("decoding failure");
					block.push_uncle(uncle).expect("pushing up to maximum_uncle_count;
												push_uncle is not ok only if more than maximum_uncle_count is pushed;
												so all push_uncle are Ok;
												qed");
					if block.uncles().len() >= max_uncles { break }
				}
			}

		}
		block
	}
}

impl<V: BlockChainClient + MinerBlockChainClient> BroadcastProposalBlock for Core<V> {
	fn broadcast_proposal_block(&self, block: SealedBlock) {
		const DURATION_ZERO: Duration = Duration::from_millis(0);
		self.notify(|notify| {
			notify.new_blocks(
				NewBlocks::new(
					vec![],
					vec![],
					ChainRoute::default(),
					vec![],
					vec![block.rlp_bytes()],
					DURATION_ZERO,
					false
				)
			);
		});
	}
}

impl<V: BlockChainClient + MinerBlockChainClient> Drop for Core<V> {
	fn drop(&mut self) {
		self.engine.stop();
	}
}

/// Returns `LocalizedReceipt` given `LocalizedTransaction`
/// and a vector of receipts from given block up to transaction index.
fn transaction_receipt(
	machine: &::machine::EthereumMachine,
	mut tx: LocalizedTransaction,
	receipt: Receipt,
	prior_gas_used: U256,
	prior_no_of_logs: usize,
) -> LocalizedReceipt {
	let sender = tx.sender();
	let transaction_hash = tx.hash();
	let block_hash = tx.block_hash;
	let block_number = tx.block_number;
	let transaction_index = tx.transaction_index;

	LocalizedReceipt {
		from: sender,
		to: match tx.action {
				Action::Create => None,
				Action::Call(ref address) => Some(address.clone().into())
		},
		transaction_hash: transaction_hash,
		transaction_index: transaction_index,
		block_hash: block_hash,
		block_number: block_number,
		cumulative_gas_used: receipt.gas_used,
		gas_used: receipt.gas_used - prior_gas_used,
		contract_address: match tx.action {
			Action::Call(_) => None,
			Action::Create => Some(contract_address(machine.create_address_scheme(block_number), &sender, &tx.nonce, &tx.data).0)
		},
		logs: receipt.logs.into_iter().enumerate().map(|(i, log)| LocalizedLogEntry {
			entry: log,
			block_hash: block_hash,
			block_number: block_number,
			transaction_hash: transaction_hash,
			transaction_index: transaction_index,
			transaction_log_index: i,
			log_index: prior_no_of_logs + i,
		}).collect(),
		log_bloom: receipt.log_bloom,
		outcome: receipt.outcome,
	}
}
