// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::error::CryptographyResult;
use crate::types;

use pyo3::types::{PyAnyMethods, PyBytes};
use crate::serialization::Encoding;

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ec")]
pub(crate) struct ECPrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ec")]
pub(crate) struct ECPublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
    #[pyo3(get)]
    curve: pyo3::Py<pyo3::PyAny>,
}

#[pyo3::pyfunction]
#[pyo3(signature = (curve))]
pub(crate) fn generate_private_key(
    py: pyo3::Python<'_>,
    curve: pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<ECPrivateKey> {
    let ossl_curve = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1,)?;

    let key = openssl::ec::EcKey::generate(&ossl_curve)?;
    let pkey = openssl::pkey::PKey::from_ec_key(key)?;

    Ok(ECPrivateKey {pkey, curve: types::CURVE_TYPES.get(py)?.get_item("prime256v1")?.into(),})
}

fn pkey_private_bytes<'p>(
    py: pyo3::Python<'p>,
    pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
    encoding: Encoding,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let parsed = cryptography_key_parsing::ParsedPrivateKey::Pkey(pkey.to_owned());
    let der_bytes = cryptography_key_parsing::pkcs8::serialize_private_key(&parsed)?;
    crate::asn1::encode_der_data(py, "PRIVATE KEY".to_string(), der_bytes, encoding)
}

#[pyo3::pymethods]
impl ECPrivateKey {
    #[getter]
    fn key_size<'p>(
        &'p self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        self.curve.bind(py).getattr(pyo3::intern!(py, "key_size"))
    }

    fn public_key(&self, py: pyo3::Python<'_>) -> CryptographyResult<ECPublicKey> {
        let orig_ec = self.pkey.ec_key().unwrap();
        let ec = openssl::ec::EcKey::from_public_key(orig_ec.group(), orig_ec.public_key())?;
        let pkey = openssl::pkey::PKey::from_ec_key(ec)?;

        Ok(ECPublicKey {
            pkey,
            curve: self.curve.clone_ref(py),
        })
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        pkey_private_bytes(py, &slf.borrow().pkey, encoding,)
    }
}


#[pyo3::pymethods]
impl ECPublicKey {
    #[getter]
    fn key_size<'p>(
        &'p self,
        py: pyo3::Python<'p>,
    ) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
        self.curve.bind(py).getattr(pyo3::intern!(py, "key_size"))
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, false)
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod ec {
    #[pymodule_export]
    use super::{generate_private_key};
}

