// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_openssl::mldsa::MlDsaVariant;
use pyo3::types::PyAnyMethods;

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

const MAX_CONTEXT_BYTES: usize = 255;

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA44PrivateKey"
)]
pub(crate) struct MlDsa44PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA44PublicKey"
)]
pub(crate) struct MlDsa44PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

pub(crate) fn mldsa44_private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlDsa44PrivateKey {
    MlDsa44PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn mldsa44_public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlDsa44PublicKey {
    MlDsa44PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn generate_mldsa44_key() -> CryptographyResult<MlDsa44PrivateKey> {
    let mut seed = [0u8; 32];
    cryptography_openssl::rand::rand_bytes(&mut seed)?;
    let pkey = cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa44, &seed)?;
    Ok(MlDsa44PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa44_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa44PrivateKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa44, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("An ML-DSA-44 seed is 32 bytes long")
            })?;
    Ok(MlDsa44PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa44_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa44PublicKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_public_key(MlDsaVariant::MlDsa44, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "An ML-DSA-44 public key is 1312 bytes long",
                )
            })?;
    Ok(MlDsa44PublicKey { pkey })
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA65PrivateKey"
)]
pub(crate) struct MlDsa65PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA65PublicKey"
)]
pub(crate) struct MlDsa65PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

pub(crate) fn mldsa65_private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlDsa65PrivateKey {
    MlDsa65PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn mldsa65_public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlDsa65PublicKey {
    MlDsa65PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn generate_mldsa65_key() -> CryptographyResult<MlDsa65PrivateKey> {
    let mut seed = [0u8; 32];
    cryptography_openssl::rand::rand_bytes(&mut seed)?;
    let pkey = cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa65, &seed)?;
    Ok(MlDsa65PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa65_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa65PrivateKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa65, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("An ML-DSA-65 seed is 32 bytes long")
            })?;
    Ok(MlDsa65PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa65_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa65PublicKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_public_key(MlDsaVariant::MlDsa65, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "An ML-DSA-65 public key is 1952 bytes long",
                )
            })?;
    Ok(MlDsa65PublicKey { pkey })
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA87PrivateKey"
)]
pub(crate) struct MlDsa87PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSA87PublicKey"
)]
pub(crate) struct MlDsa87PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

pub(crate) fn mldsa87_private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> MlDsa87PrivateKey {
    MlDsa87PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn mldsa87_public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> MlDsa87PublicKey {
    MlDsa87PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn generate_mldsa87_key() -> CryptographyResult<MlDsa87PrivateKey> {
    let mut seed = [0u8; 32];
    cryptography_openssl::rand::rand_bytes(&mut seed)?;
    let pkey = cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa87, &seed)?;
    Ok(MlDsa87PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa87_seed_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa87PrivateKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_private_key(MlDsaVariant::MlDsa87, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("An ML-DSA-87 seed is 32 bytes long")
            })?;
    Ok(MlDsa87PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_mldsa87_public_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<MlDsa87PublicKey> {
    let pkey =
        cryptography_openssl::mldsa::new_raw_public_key(MlDsaVariant::MlDsa87, data.as_bytes())
            .map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "An ML-DSA-87 public key is 2592 bytes long",
                )
            })?;
    Ok(MlDsa87PublicKey { pkey })
}


/// Extract the raw public key bytes from any ML-DSA public key object.
fn mldsa_public_key_raw(public_key: &pyo3::Bound<'_, pyo3::PyAny>) -> CryptographyResult<Vec<u8>> {
    if let Ok(k) = public_key.cast::<MlDsa44PublicKey>() {
        Ok(k.get().pkey.raw_public_key()?)
    } else if let Ok(k) = public_key.cast::<MlDsa65PublicKey>() {
        Ok(k.get().pkey.raw_public_key()?)
    } else if let Ok(k) = public_key.cast::<MlDsa87PublicKey>() {
        Ok(k.get().pkey.raw_public_key()?)
    } else {
        Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err("public_key must be an ML-DSA public key."),
        ))
    }
}
