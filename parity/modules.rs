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

use std::sync::{Arc, mpsc};

use ethcore::client::BlockChainClient;
use sync::{self, AttachedProtocol, SyncConfig, NetworkConfiguration, Params, ConnectionFilter};
use ethcore::snapshot::SnapshotService;
use ethcore::client::ClientBackend;
use light::Provider;

pub use sync::{EthSync, SyncProvider, ManageNetwork, PrivateTxHandler};
pub use ethcore::client::ChainNotify;
use ethcore_logger::Config as LogConfig;

pub type SyncModules = (
	Arc<SyncProvider>,
	Arc<ManageNetwork>,
	Arc<ChainNotify>,
	mpsc::Sender<sync::PriorityTask>,
);

pub fn sync<BC: ClientBackend>(
	config: SyncConfig,
	network_config: NetworkConfiguration,
	chain: Arc<BlockChainClient<StateBackend = BC>>,
	snapshot_service: Arc<SnapshotService>,
	private_tx_handler: Arc<PrivateTxHandler>,
	provider: Arc<Provider>,
	_log_settings: &LogConfig,
	attached_protos: Vec<AttachedProtocol>,
	connection_filter: Option<Arc<ConnectionFilter>>,
) -> Result<SyncModules, sync::Error> {
	let eth_sync = EthSync::new(Params::new(
		config,
		chain,
		snapshot_service,
		private_tx_handler,
		provider,
		network_config,
		attached_protos
	),
	connection_filter)?;

	Ok((
		eth_sync.clone() as Arc<SyncProvider>,
		eth_sync.clone() as Arc<ManageNetwork>,
		eth_sync.clone() as Arc<ChainNotify>,
		eth_sync.priority_tasks()
	))
}
