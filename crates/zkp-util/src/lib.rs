/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

use ark_bls12_381::Bls12_381;
use ark_secp256r1::{Affine as SecpAffine, G_GENERATOR_X, G_GENERATOR_Y};
use bbs_plus::prelude::{KeypairG1, SignatureG1};

pub mod circuits;
pub mod constants;
pub mod device_binding;
pub mod keypair;
pub mod vc;

pub use ecdsa_pops;
pub use rok;

pub const SECP_GEN: SecpAffine = SecpAffine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

pub type EcdsaSignature = kvac::bbs_sharp::ecdsa::Signature;

pub type BBSKeypair = KeypairG1<Bls12_381>;
pub type BBSSignature = SignatureG1<Bls12_381>;
