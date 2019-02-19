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

//! No-op verifier.

use rich_phantoms::PhantomCovariantAlwaysSendSync as SafePhantomData;
use std::marker::PhantomData;
use client::{BlockInfo, CallContract};
use engines::EthEngine;
use error::Error;
use header::Header;
use state::backend::Backend;
use super::{verification, Verifier};

/// A no-op verifier -- this will verify everything it's given immediately.
#[allow(dead_code)]
pub struct NoopVerifier<B> { _phantom: SafePhantomData<B> }

impl<B> NoopVerifier<B> {
	pub fn new() -> Self { Self { _phantom: PhantomData } }
}

impl<C: BlockInfo + CallContract, B: Backend + Clone> Verifier<C> for NoopVerifier<B> {
	type EngineStateBackend = B;
	fn verify_block_family(
		&self,
		_: &Header,
		_t: &Header,
		_: &EthEngine<B>,
		_: Option<verification::FullFamilyParams<C>>
	) -> Result<(), Error> {
		Ok(())
	}

	fn verify_block_final(&self, _expected: &Header, _got: &Header) -> Result<(), Error> {
		Ok(())
	}

	fn verify_block_external(&self, _header: &Header, _engine: &EthEngine<B>) -> Result<(), Error> {
		Ok(())
	}
}
