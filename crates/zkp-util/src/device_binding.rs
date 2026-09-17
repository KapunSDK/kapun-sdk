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

use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::time::Instant;

use anyhow::{anyhow, Context};
use ark_bls12_381::G1Affine as BlsG1Affine;
use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::Engine;
use ecdsa_pops::halo2curves::ff::derive::byteorder::{
    self, BigEndian, ReadBytesExt, WriteBytesExt,
};
use ecdsa_pops::halo2curves::secp256r1::Secp256r1Affine;
use ecdsa_pops::utils::ecdsa::{ECDSASignature, ECDSA};
use ecdsa_pops::utils::{arkfp_to_fp, arkfq_to_fq, arkp256_to_p256, fp_to_scalars};
use ecdsa_pops::{
    bincode, G1Affine, PoPNativeComposedRoK, PoPNativeNizk, PoPSigmaNizk, RelECDSA, RelECDSAParams,
    RelECDSAStatement, RelECDSAWitness,
};

use ecdsa_pops::halo2curves::ff::{Field, PrimeField};
use kvac::bbs_sharp::ecdsa;
use num_bigint::BigUint;
use rand_core::{OsRng, RngCore};
use rok::{Nizk, Relation, RoK};

pub const DEVICE_BINDING_KEY: &str = "https://zkp-ld.org/deviceBinding";
pub const DEVICE_BINDING_KEY_X: &str = "https://zkp-ld.org/deviceBinding#x";
pub const DEVICE_BINDING_KEY_Y: &str = "https://zkp-ld.org/deviceBinding#y";
pub const DEVICE_BINDING_KEY_X_1: &str = "https://zkp-ld.org/deviceBinding#x1";
pub const DEVICE_BINDING_KEY_X_2: &str = "https://zkp-ld.org/deviceBinding#x2";
pub const DEVICE_BINDING_KEY_Y_1: &str = "https://zkp-ld.org/deviceBinding#y1";
pub const DEVICE_BINDING_KEY_Y_2: &str = "https://zkp-ld.org/deviceBinding#y2";

pub type SecpFr = ark_secp256r1::Fr;
pub type SecpFq = ark_secp256r1::Fq;
pub type SecpAffine = ark_secp256r1::Affine;
pub type BlsFr = ark_bls12_381::Fr;

type PoPSigmaProof = <PoPSigmaNizk as Nizk>::Proof;

#[allow(nonstandard_style)]
#[derive(Clone)]
pub struct DeviceBindingSigma {
    pub proof: PoPSigmaProof,
    pub bls_comm_key: Vec<BlsG1Affine>,
    pub bls_comm_pk_x1: BlsG1Affine,
    pub bls_comm_pk_x2: BlsG1Affine,
    pub bls_comm_pk_y1: BlsG1Affine,
    pub bls_comm_pk_y2: BlsG1Affine,
    pub bls_scalars_x1: Vec<BlsFr>,
    pub bls_scalars_x2: Vec<BlsFr>,
    pub bls_scalars_y1: Vec<BlsFr>,
    pub bls_scalars_y2: Vec<BlsFr>,
    pub K: Secp256r1Affine,
}

#[allow(nonstandard_style)]
pub struct DeviceBindingNative {
    pub proof: <PoPNativeComposedRoK as RoK>::Proof,
    pub params: PoPNativeNizk,

    pub bls_comm_pk_x1: ecdsa_pops::G1Affine,
    pub bls_comm_pk_x2: ecdsa_pops::G1Affine,
    pub bls_comm_pk_y1: ecdsa_pops::G1Affine,
    pub bls_comm_pk_y2: ecdsa_pops::G1Affine,

    pub bls_scalar_x1: ecdsa_pops::halo2curves::bls12381::Fr,
    pub bls_scalar_x2: ecdsa_pops::halo2curves::bls12381::Fr,
    pub bls_scalar_x1_blinding: ecdsa_pops::halo2curves::bls12381::Fr,
    pub bls_scalar_x2_blinding: ecdsa_pops::halo2curves::bls12381::Fr,
    pub bls_scalar_y1: ecdsa_pops::halo2curves::bls12381::Fr,
    pub bls_scalar_y2: ecdsa_pops::halo2curves::bls12381::Fr,
    pub bls_scalar_y1_blinding: ecdsa_pops::halo2curves::bls12381::Fr,
    pub bls_scalar_y2_blinding: ecdsa_pops::halo2curves::bls12381::Fr,

    pub K: Secp256r1Affine,
}
impl std::fmt::Debug for DeviceBindingNative {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceBindingNative")
    }
}

#[derive(Clone)]
#[allow(nonstandard_style)]
pub struct DeviceBindingPresentationSigma {
    pub proof: PoPSigmaProof,
    pub bls_comm_key: Vec<BlsG1Affine>,
    pub bls_comm_pk_x1: BlsG1Affine,
    pub bls_comm_pk_x2: BlsG1Affine,
    pub bls_comm_pk_y1: BlsG1Affine,
    pub bls_comm_pk_y2: BlsG1Affine,
    pub K: Secp256r1Affine,
}

const SIGMA_SERIALIZATION_MAGIC: &[u8] = b"zkp-util-device-binding-sigma-v2";
const SIGMA_TRANSCRIPT_LABEL: &[u8] = b"pop sigma proof";

fn sigma_setup_label(label: &[u8]) -> String {
    format!(
        "zkp-util device binding sigma:{}",
        base64::prelude::BASE64_STANDARD.encode(label)
    )
}

impl std::fmt::Debug for DeviceBindingPresentationSigma {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceBindingPresentationSigma")
            .field("proof", &"<ecdsa_pops sigma proof>")
            .field("bls_comm_pk_x1", &self.bls_comm_pk_x1)
            .field("bls_comm_pk_x2", &self.bls_comm_pk_x2)
            .field("bls_comm_pk_y1", &self.bls_comm_pk_y1)
            .field("bls_comm_pk_y2", &self.bls_comm_pk_y2)
            .field("K", &self.K)
            .finish()
    }
}

impl DeviceBindingPresentationSigma {
    pub fn serialize_compressed<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(SIGMA_SERIALIZATION_MAGIC)?;

        let proof = bincode::serialize(&self.proof).map_err(std::io::Error::other)?;
        writer.write_u64::<BigEndian>(proof.len() as u64)?;
        writer.write_all(&proof)?;

        for point in [
            &self.bls_comm_key[0],
            &self.bls_comm_key[1],
            &self.bls_comm_pk_x1,
            &self.bls_comm_pk_x2,
            &self.bls_comm_pk_y1,
            &self.bls_comm_pk_y2,
        ] {
            writer.write_u64::<BigEndian>(point.compressed_size() as u64)?;
            point
                .serialize_compressed(&mut writer)
                .map_err(std::io::Error::other)?;
        }

        let k = bincode::serialize(&self.K).map_err(std::io::Error::other)?;
        writer.write_u64::<BigEndian>(k.len() as u64)?;
        writer.write_all(&k)?;
        Ok(())
    }

    pub fn deserialize_compressed<R: Read>(reader: R) -> anyhow::Result<Self> {
        let mut reader = BufReader::new(reader);
        let mut magic = vec![0; SIGMA_SERIALIZATION_MAGIC.len()];
        reader.read_exact(&mut magic)?;
        anyhow::ensure!(
            magic == SIGMA_SERIALIZATION_MAGIC,
            "unsupported Sigma device-binding serialization"
        );

        let read_blob = |reader: &mut BufReader<R>| -> anyhow::Result<Vec<u8>> {
            let len = reader.read_u64::<BigEndian>()?;
            let len: usize = len
                .try_into()
                .map_err(|_| anyhow!("serialized field is too large"))?;
            let mut bytes = vec![0; len];
            reader.read_exact(&mut bytes)?;
            Ok(bytes)
        };

        let proof_bytes = read_blob(&mut reader)?;
        let proof = bincode::deserialize(&proof_bytes)?;

        let point = |reader: &mut BufReader<R>| -> anyhow::Result<BlsG1Affine> {
            let bytes = read_blob(reader)?;
            Ok(BlsG1Affine::deserialize_compressed(bytes.as_slice())?)
        };

        let bls_comm_key_0 = point(&mut reader)?;
        let bls_comm_key_1 = point(&mut reader)?;
        let bls_comm_pk_x1 = point(&mut reader)?;
        let bls_comm_pk_x2 = point(&mut reader)?;
        let bls_comm_pk_y1 = point(&mut reader)?;
        let bls_comm_pk_y2 = point(&mut reader)?;
        let k_bytes = read_blob(&mut reader)?;
        let k = bincode::deserialize(&k_bytes)?;

        Ok(Self {
            proof,
            bls_comm_key: vec![bls_comm_key_0, bls_comm_key_1],
            bls_comm_pk_x1,
            bls_comm_pk_x2,
            bls_comm_pk_y1,
            bls_comm_pk_y2,
            K: k,
        })
    }
}

#[derive(Clone)]
#[allow(nonstandard_style)]
pub struct DeviceBindingPresentationNative {
    pub proof: <PoPNativeComposedRoK as RoK>::Proof,
    pub params: PoPNativeNizk,
    pub bls_comm_pk_x1: BlsG1Affine,
    pub bls_comm_pk_x2: BlsG1Affine,
    pub bls_comm_pk_y1: BlsG1Affine,
    pub bls_comm_pk_y2: BlsG1Affine,
    pub K: Secp256r1Affine,
}

impl DeviceBindingPresentationNative {
    pub fn serialize(&self) -> Vec<u8> {
        let bytes = vec![];
        let mut w = BufWriter::new(bytes);
        let p = bincode::serialize(&self.proof).unwrap();
        w.write_u64::<byteorder::BigEndian>(p.len() as u64).unwrap();
        w.write_all(&p).unwrap();
        let p = bincode::serialize(&self.params).unwrap();
        w.write_u64::<byteorder::BigEndian>(p.len() as u64).unwrap();
        w.write_all(&p).unwrap();
        let compressed_size = self.bls_comm_pk_x1.compressed_size();
        w.write_u64::<byteorder::BigEndian>(compressed_size as u64)
            .unwrap();
        self.bls_comm_pk_x1.serialize_compressed(&mut w).unwrap();
        let compressed_size = self.bls_comm_pk_x2.compressed_size();
        w.write_u64::<byteorder::BigEndian>(compressed_size as u64)
            .unwrap();
        self.bls_comm_pk_x2.serialize_compressed(&mut w).unwrap();
        let compressed_size = self.bls_comm_pk_y1.compressed_size();
        w.write_u64::<byteorder::BigEndian>(compressed_size as u64)
            .unwrap();
        self.bls_comm_pk_y1.serialize_compressed(&mut w).unwrap();
        let compressed_size = self.bls_comm_pk_y2.compressed_size();
        w.write_u64::<byteorder::BigEndian>(compressed_size as u64)
            .unwrap();
        self.bls_comm_pk_y2.serialize_compressed(&mut w).unwrap();

        let k_bytes = bincode::serialize(&self.K).unwrap();
        w.write_u64::<byteorder::BigEndian>(k_bytes.len() as u64)
            .unwrap();
        w.write_all(&k_bytes).unwrap();
        w.into_inner().unwrap()
    }

    #[allow(nonstandard_style)]
    pub fn deserialize<T: Read + Seek>(bytes: T) -> Self {
        let mut reader = BufReader::new(bytes);

        let len_proof = reader.read_u64::<BigEndian>().unwrap();
        let mut proof_bytes = vec![0; len_proof as usize];
        reader.read_exact(&mut proof_bytes).unwrap();
        let proof = bincode::deserialize(&proof_bytes).unwrap();

        let len_params = reader.read_u64::<BigEndian>().unwrap();
        let mut params_bytes = vec![0; len_params as usize];
        reader.read_exact(&mut params_bytes).unwrap();
        let params = bincode::deserialize(&params_bytes).unwrap();

        let len_x1 = reader.read_u64::<BigEndian>().unwrap();
        let mut x1_bytes = vec![0; len_x1 as usize];
        reader.read_exact(&mut x1_bytes).unwrap();

        let len_x2 = reader.read_u64::<BigEndian>().unwrap();
        let mut x2_bytes = vec![0; len_x2 as usize];
        reader.read_exact(&mut x2_bytes).unwrap();
        let x1 = BlsG1Affine::deserialize_compressed(&x1_bytes[..]).unwrap();

        let x2 = BlsG1Affine::deserialize_compressed(&x2_bytes[..]).unwrap();

        let len_y1 = reader.read_u64::<BigEndian>().unwrap();
        let mut y1_bytes = vec![0; len_y1 as usize];
        reader.read_exact(&mut y1_bytes).unwrap();

        let len_y2 = reader.read_u64::<BigEndian>().unwrap();
        let mut y2_bytes = vec![0; len_y2 as usize];
        reader.read_exact(&mut y2_bytes).unwrap();
        let y1 = BlsG1Affine::deserialize_compressed(&y1_bytes[..]).unwrap();
        let y2 = BlsG1Affine::deserialize_compressed(&y2_bytes[..]).unwrap();

        let len_K = reader.read_u64::<BigEndian>().unwrap();
        let mut k_bytes = vec![0; len_K as usize];
        reader.read_exact(&mut k_bytes).unwrap();
        let K = bincode::deserialize(&k_bytes).unwrap();

        Self {
            proof,
            params,
            bls_comm_pk_x1: x1,
            bls_comm_pk_x2: x2,
            bls_comm_pk_y1: y1,
            bls_comm_pk_y2: y2,
            K,
        }
    }

    pub fn verify(&self, label: &'static [u8], message: SecpFr) -> anyhow::Result<()> {
        let mut transcript_verifier = ecdsa_pops::merlin::Transcript::new(label);
        let x = RelECDSAStatement::new(
            [
                from_arkg1_to_g1(&self.bls_comm_pk_x1),
                from_arkg1_to_g1(&self.bls_comm_pk_x2),
            ],
            Some([
                from_arkg1_to_g1(&self.bls_comm_pk_y1),
                from_arkg1_to_g1(&self.bls_comm_pk_y2),
            ]),
            arkfq_to_fq(&message).unwrap(),
            self.K,
        );
        let ecdsa = ECDSA {
            pp: Secp256r1Affine::generator(),
        };
        let nizk = self.params.clone();
        let gs = [*nizk.ck_bls(), *nizk.ck_bls()];
        let h = nizk.ck_bls_blinding();
        let pp = RelECDSAParams::<G1Affine, 2>::new(gs, *h, ecdsa);
        let r_verifier = RelECDSA::new(pp, x, None);
        let _ = self
            .params
            .verify(&mut transcript_verifier, &r_verifier, &self.proof)
            .unwrap();
        Ok(())
    }
}

pub fn from_ark_point_to_halo_point(p: &SecpAffine) -> Secp256r1Affine {
    arkp256_to_p256(p).unwrap()
}

use ark_bls12_381::Fq as BlsFq;

pub fn from_g1_to_arkg1(g: &ecdsa_pops::G1Affine) -> BlsG1Affine {
    let x_rep = g.x.to_repr();
    let y_rep = g.y.to_repr();
    let x = x_rep.as_ref();
    let y = y_rep.as_ref();
    let x = <BlsFq as ArkPrimeField>::from_le_bytes_mod_order(&x);
    let y = <BlsFq as ArkPrimeField>::from_le_bytes_mod_order(&y);
    BlsG1Affine::new(x, y)
}
pub fn from_arkg1_to_g1(g: &BlsG1Affine) -> ecdsa_pops::G1Affine {
    let x: BigUint = g.x.clone().into();
    let y: BigUint = g.y.clone().into();
    let xbs = x.to_bytes_le();
    let ybs = y.to_bytes_le();
    let mut xbytes = [0u8; 48];
    let mut ybytes = [0u8; 48];
    xbytes[..xbs.len()].copy_from_slice(&xbs);
    ybytes[..ybs.len()].copy_from_slice(&ybs);

    ecdsa_pops::G1Affine {
        x: ecdsa_pops::halo2curves::bls12381::Fq::from_repr(xbytes.into()).unwrap(),
        y: ecdsa_pops::halo2curves::bls12381::Fq::from_repr(ybytes.into()).unwrap(),
    }
}
pub fn from_blsfr_to_arkblsfr(a: &ecdsa_pops::halo2curves::bls12381::Fr) -> BlsFr {
    let a = a.to_repr();
    let aref = a.as_ref();
    <BlsFr as ArkPrimeField>::from_le_bytes_mod_order(aref)
}

impl DeviceBindingNative {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        public_key: SecpAffine,
        message: SecpFr,
        message_signature: ecdsa::Signature,
        label: &str,
        setup: Option<PoPNativeNizk>,
    ) -> anyhow::Result<Self> {
        let start = Instant::now();
        let nizk = if let Some(setup) = setup {
            setup
        } else {
            PoPNativeNizk::new(label)
        };
        let end = Instant::now();
        println!("elapsed [conversion]: {}", (end - start).as_millis());
        let ecdsa = ECDSA {
            pp: Secp256r1Affine::generator(),
        };
        let gs = [*nizk.ck_bls(), *nizk.ck_bls()];
        let h = nizk.ck_bls_blinding();

        let pp = RelECDSAParams::<G1Affine, 2>::new(gs, *h, ecdsa);

        let pk = arkp256_to_p256(&public_key).unwrap();
        println!("successfully converted point");

        let m = arkfq_to_fq(&message).unwrap();
        let sigma = ECDSASignature {
            Rx: arkfq_to_fq(&message_signature.rand_x_coord).unwrap(),
            response: arkfq_to_fq(&message_signature.response).unwrap(),
        };

        let start = Instant::now();

        let sigma_converted = ecdsa.convert(&pk, &m, &sigma);
        // sample randomness for the commitments
        let rho_x: [ecdsa_pops::halo2curves::bls12381::Fr; 2] = (0..2)
            .map(|_| <ecdsa_pops::halo2curves::bls12381::Fr>::random(OsRng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let rho_y: [ecdsa_pops::halo2curves::bls12381::Fr; 2] = (0..2)
            .map(|_| <ecdsa_pops::halo2curves::bls12381::Fr>::random(OsRng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        println!("everything ready start proofs");
        // create witness
        let w = RelECDSAWitness::new(pk, sigma_converted.z, rho_x, Some(rho_y));
        println!("witness ready");
        // create the commitment to the public key
        let commitments = (0..2)
            .map(|i| RelECDSA::<G1Affine, 2>::create_commitment(&pp, &w, i).unwrap())
            .collect::<Vec<_>>();
        let coms_x = [commitments[0].0, commitments[1].0];
        let coms_y = [commitments[0].1.unwrap(), commitments[1].1.unwrap()];
        println!("commitments done");
        let x = RelECDSAStatement::new(coms_x, Some(coms_y), m, sigma_converted.K);

        let limbs_x = fp_to_scalars::<ecdsa_pops::G1Affine, 2>(&w.q().x).unwrap();
        let limbs_y = fp_to_scalars::<ecdsa_pops::G1Affine, 2>(&w.q().y).unwrap();

        let r_prover = RelECDSA::new(pp, x, Some(w));
        println!("elapsed [setup]: {}", (end - start).as_millis());
        let mut transcript_prover = ecdsa_pops::merlin::Transcript::new(b"pop native proof");
        println!("start proof");
        let start = Instant::now();
        let proof = nizk
            .prove(&mut transcript_prover, &r_prover, &mut OsRng)
            .unwrap();
        let end = Instant::now();
        println!("elapsed [actual proof]: {}", (end - start).as_millis());
        println!("proof finished");
        Ok(Self {
            proof,
            params: nizk,
            bls_comm_pk_x1: coms_x[0],
            bls_comm_pk_x2: coms_x[1],
            bls_comm_pk_y1: coms_y[0],
            bls_comm_pk_y2: coms_y[1],
            bls_scalar_x1: limbs_x[0],
            bls_scalar_x2: limbs_x[1],
            bls_scalar_x1_blinding: rho_x[0],
            bls_scalar_x2_blinding: rho_x[1],
            bls_scalar_y1: limbs_y[0],
            bls_scalar_y2: limbs_y[1],
            bls_scalar_y1_blinding: rho_y[0],
            bls_scalar_y2_blinding: rho_y[1],
            K: sigma_converted.K,
        })
    }
    pub fn present(&self) -> DeviceBindingPresentationNative {
        DeviceBindingPresentationNative {
            proof: self.proof.clone(),
            params: self.params.clone(),
            bls_comm_pk_x1: from_g1_to_arkg1(&self.bls_comm_pk_x1),
            bls_comm_pk_x2: from_g1_to_arkg1(&self.bls_comm_pk_x2),
            bls_comm_pk_y1: from_g1_to_arkg1(&self.bls_comm_pk_y1),
            bls_comm_pk_y2: from_g1_to_arkg1(&self.bls_comm_pk_y2),
            K: self.K,
        }
    }
}

impl DeviceBindingSigma {
    #[allow(clippy::too_many_arguments)]
    pub fn new<R: RngCore>(
        rng: &mut R,
        public_key: SecpAffine,
        message: SecpFr,
        message_signature: ecdsa::Signature,
        _comm_key_secp_label: &[u8],
        _comm_key_tom_label: &[u8],
        comm_key_bls_label: &[u8],
        _bpp_setup_label: &[u8],
        _merlin_transcript_label: &'static [u8],
        _challenge_label: &'static [u8],
    ) -> anyhow::Result<Self> {
        let nizk = PoPSigmaNizk::new(&sigma_setup_label(comm_key_bls_label));
        let ecdsa = ECDSA {
            pp: Secp256r1Affine::generator(),
        };
        let pp = RelECDSAParams::<G1Affine, 2>::new(
            [*nizk.ck_bls(), *nizk.ck_bls()],
            *nizk.ck_bls_blinding(),
            ecdsa,
        );

        let pk =
            arkp256_to_p256(&public_key).ok_or_else(|| anyhow!("failed to convert public key"))?;
        let m = arkfq_to_fq(&message).ok_or_else(|| anyhow!("failed to convert message"))?;
        let sigma = ECDSASignature {
            Rx: arkfq_to_fq(&message_signature.rand_x_coord)
                .ok_or_else(|| anyhow!("failed to convert signature nonce"))?,
            response: arkfq_to_fq(&message_signature.response)
                .ok_or_else(|| anyhow!("failed to convert signature response"))?,
        };
        let sigma_converted = ecdsa.convert(&pk, &m, &sigma);

        let rho_x = [
            ecdsa_pops::halo2curves::bls12381::Fr::random(&mut *rng),
            ecdsa_pops::halo2curves::bls12381::Fr::random(&mut *rng),
        ];
        let rho_y = [
            ecdsa_pops::halo2curves::bls12381::Fr::random(&mut *rng),
            ecdsa_pops::halo2curves::bls12381::Fr::random(&mut *rng),
        ];
        let witness = RelECDSAWitness::new(pk, sigma_converted.z, rho_x, Some(rho_y));
        let limbs_x = fp_to_scalars::<G1Affine, 2>(&witness.q().x)
            .map_err(|e| anyhow!("failed to split public key x coordinate: {e:?}"))?;
        let limbs_y = fp_to_scalars::<G1Affine, 2>(&witness.q().y)
            .map_err(|e| anyhow!("failed to split public key y coordinate: {e:?}"))?;
        let commitments = (0..2)
            .map(|i| RelECDSA::<G1Affine, 2>::create_commitment(&pp, &witness, i))
            .collect::<Result<Vec<_>, _>>()?;
        let coms_x = [commitments[0].0, commitments[1].0];
        let coms_y = [commitments[0].1.unwrap(), commitments[1].1.unwrap()];
        let statement = RelECDSAStatement::new(coms_x, Some(coms_y), m, sigma_converted.K);
        let relation = RelECDSA::new(pp, statement, Some(witness));
        let mut transcript = ecdsa_pops::merlin::Transcript::new(SIGMA_TRANSCRIPT_LABEL);
        let proof = nizk
            .prove(&mut transcript, &relation, &mut OsRng)
            .map_err(|e| anyhow!("failed to create Sigma device-binding proof: {e:?}"))?;

        Ok(Self {
            proof,
            bls_comm_key: vec![
                from_g1_to_arkg1(nizk.ck_bls()),
                from_g1_to_arkg1(nizk.ck_bls_blinding()),
            ],
            bls_comm_pk_x1: from_g1_to_arkg1(&coms_x[0]),
            bls_comm_pk_x2: from_g1_to_arkg1(&coms_x[1]),
            bls_comm_pk_y1: from_g1_to_arkg1(&coms_y[0]),
            bls_comm_pk_y2: from_g1_to_arkg1(&coms_y[1]),
            bls_scalars_x1: vec![
                from_blsfr_to_arkblsfr(&limbs_x[0]),
                from_blsfr_to_arkblsfr(&rho_x[0]),
            ],
            bls_scalars_x2: vec![
                from_blsfr_to_arkblsfr(&limbs_x[1]),
                from_blsfr_to_arkblsfr(&rho_x[1]),
            ],
            bls_scalars_y1: vec![
                from_blsfr_to_arkblsfr(&limbs_y[0]),
                from_blsfr_to_arkblsfr(&rho_y[0]),
            ],
            bls_scalars_y2: vec![
                from_blsfr_to_arkblsfr(&limbs_y[1]),
                from_blsfr_to_arkblsfr(&rho_y[1]),
            ],
            K: sigma_converted.K,
        })
    }

    pub fn present(self) -> DeviceBindingPresentationSigma {
        DeviceBindingPresentationSigma {
            proof: self.proof,
            bls_comm_key: self.bls_comm_key,
            bls_comm_pk_x1: self.bls_comm_pk_x1,
            bls_comm_pk_x2: self.bls_comm_pk_x2,
            bls_comm_pk_y1: self.bls_comm_pk_y1,
            bls_comm_pk_y2: self.bls_comm_pk_y2,
            K: self.K,
        }
    }
}

impl DeviceBindingPresentationSigma {
    pub fn verify(&self, message: SecpFr, comm_key_bls_label: &[u8]) -> anyhow::Result<()> {
        let nizk = PoPSigmaNizk::new(&sigma_setup_label(comm_key_bls_label));
        let ecdsa = ECDSA {
            pp: Secp256r1Affine::generator(),
        };
        let pp = RelECDSAParams::<G1Affine, 2>::new(
            [*nizk.ck_bls(), *nizk.ck_bls()],
            *nizk.ck_bls_blinding(),
            ecdsa,
        );
        let statement = RelECDSAStatement::new(
            [
                from_arkg1_to_g1(&self.bls_comm_pk_x1),
                from_arkg1_to_g1(&self.bls_comm_pk_x2),
            ],
            Some([
                from_arkg1_to_g1(&self.bls_comm_pk_y1),
                from_arkg1_to_g1(&self.bls_comm_pk_y2),
            ]),
            arkfq_to_fq(&message).ok_or_else(|| anyhow!("failed to convert message"))?,
            self.K,
        );
        let relation = RelECDSA::new(pp, statement, None);
        let mut transcript = ecdsa_pops::merlin::Transcript::new(SIGMA_TRANSCRIPT_LABEL);
        nizk.verify(&mut transcript, &relation, &self.proof)
            .map_err(|e| anyhow!("failed to verify Sigma device-binding proof: {e:?}"))?;
        Ok(())
    }
}

/// Splits a secp256r1 field element into two BLS-scalar-sized limbs `(x1, x2)`
/// such that `x1 + x2 * 2^128` reconstructs the original value modulo the BLS
/// scalar field order. Used to bind a device's public key x coordinate to a
/// credential without requiring the raw (too large) coordinate itself.
pub fn secp_x_to_bls_limbs(x: &SecpFq) -> anyhow::Result<(BlsFr, BlsFr)> {
    let fp = arkfp_to_fp(x).context("Failed to convert x coordinate")?;
    let limbs = fp_to_scalars::<ecdsa_pops::G1Affine, 2>(&fp)
        .map_err(|e| anyhow!("Failed to split x coordinate into limbs: {e:?}"))?;
    Ok((
        from_blsfr_to_arkblsfr(&limbs[0]),
        from_blsfr_to_arkblsfr(&limbs[1]),
    ))
}

pub fn limbs_from_coordinate(x: &str) -> anyhow::Result<(String, String)> {
    use base64::prelude::BASE64_STANDARD;
    let x = BASE64_STANDARD.decode(x).context("Invalid B64")?;
    let x = SecpFq::from(BigUint::from_bytes_be(&x));
    let (x1, x2) = secp_x_to_bls_limbs(&x).context("Failed to convert to bls limbs")?;

    let x1_bytes = x1.into_bigint().to_bytes_be();
    let x2_bytes = x2.into_bigint().to_bytes_be();

    Ok((
        BASE64_STANDARD.encode(x1_bytes),
        BASE64_STANDARD.encode(x2_bytes),
    ))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use ark_std::UniformRand;

    #[test]
    pub fn test_device_binding() {
        use std::io::Cursor;

        use ark_ec::CurveGroup;
        use ark_secp256r1::{G_GENERATOR_X, G_GENERATOR_Y};

        const SECP_GEN: SecpAffine = SecpAffine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

        let mut rng = rand_core::OsRng;

        let secret_key = SecpFr::rand(&mut rng);
        let public_key = (SECP_GEN * secret_key).into_affine();

        let message = SecpFr::rand(&mut rng);
        let message_signature = ecdsa::Signature::new_prehashed(&mut rng, message, secret_key);

        let db = DeviceBindingSigma::new(
            &mut rng,
            public_key,
            message,
            message_signature,
            b"comm-key-secp",
            b"comm-key-tom",
            b"comm-key-bls",
            b"bpp-setup",
            b"transcript",
            b"challenge",
        )
        .unwrap();

        let presentation = db.present();

        let mut bytes = Vec::<u8>::new();
        presentation.serialize_compressed(&mut bytes).unwrap();

        println!("{}", bytes.len());

        let presentation =
            DeviceBindingPresentationSigma::deserialize_compressed(Cursor::new(bytes)).unwrap();

        presentation.verify(message, b"comm-key-bls").unwrap();
    }

    #[test]
    pub fn test_device_binding_native() {
        use ark_ec::CurveGroup;
        use ark_secp256r1::{G_GENERATOR_X, G_GENERATOR_Y};

        const SECP_GEN: SecpAffine = SecpAffine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

        let mut rng = rand_core::OsRng;

        let secret_key = SecpFr::rand(&mut rng);
        let public_key = (SECP_GEN * secret_key).into_affine();

        let message = SecpFr::rand(&mut rng);
        let message_signature = ecdsa::Signature::new_prehashed(&mut rng, message, secret_key);

        let db = DeviceBindingNative::new(
            public_key,
            message,
            message_signature,
            "comm-key-secp",
            None,
        )
        .unwrap();

        let presentation = db.present();

        let bytes = presentation.serialize();
        println!("{}", bytes.len());
        let proof = DeviceBindingPresentationNative::deserialize(Cursor::new(bytes.clone()));

        proof.verify(b"pop native proof", message).unwrap();

        let mut transcript_verifier = ecdsa_pops::merlin::Transcript::new(b"pop native proof");
        let x = RelECDSAStatement::new(
            [
                from_arkg1_to_g1(&proof.bls_comm_pk_x1),
                from_arkg1_to_g1(&proof.bls_comm_pk_x2),
            ],
            Some([
                from_arkg1_to_g1(&proof.bls_comm_pk_y1),
                from_arkg1_to_g1(&proof.bls_comm_pk_y2),
            ]),
            arkfq_to_fq(&message).unwrap(),
            proof.K,
        );
        let ecdsa = ECDSA {
            pp: Secp256r1Affine::generator(),
        };
        let nizk = proof.params;
        let gs = [*nizk.ck_bls(), *nizk.ck_bls()];
        let h = nizk.ck_bls_blinding();
        let pp = RelECDSAParams::<G1Affine, 2>::new(gs, *h, ecdsa);
        let r_verifier = RelECDSA::new(pp, x, None);
        let _ = nizk
            .verify(&mut transcript_verifier, &r_verifier, &proof.proof)
            .unwrap();
    }
}
