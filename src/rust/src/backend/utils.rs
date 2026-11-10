// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use pyo3::types::{PyAnyMethods, PyBytesMethods, PyBytes};

use crate::backend::hashes::Hash;
use crate::error::{CryptographyError, CryptographyResult};
use crate::serialization::{Encoding, PrivateFormat, PublicFormat};
use crate::types;

pub(crate) fn py_int_to_bn(
    py: pyo3::Python<'_>,
    v: &pyo3::Bound<'_, pyo3::PyAny>,
) -> CryptographyResult<openssl::bn::BigNum> {
    let n = v
        .call_method0(pyo3::intern!(py, "bit_length"))?
        .extract::<usize>()?
        / 8
        + 1;
    let bytes = v
        .call_method1(pyo3::intern!(py, "to_bytes"), (n, pyo3::intern!(py, "big")))?
        .extract::<pyo3::pybacked::PyBackedBytes>()?;

    Ok(openssl::bn::BigNum::from_slice(&bytes)?)
}

pub(crate) fn bn_to_py_int<'p>(
    py: pyo3::Python<'p>,
    b: &openssl::bn::BigNumRef,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    assert!(!b.is_negative());

    let int_type = py.get_type::<pyo3::types::PyInt>();
    Ok(int_type.call_method1(
        pyo3::intern!(py, "from_bytes"),
        (b.to_vec(), pyo3::intern!(py, "big")),
    )?)
}

pub(crate) fn pkey_public_bytes<'p>(
    py: pyo3::Python<'p>,
    key_obj: &pyo3::Bound<'p, pyo3::PyAny>,
    pkey: &openssl::pkey::PKey<openssl::pkey::Public>,
    encoding: Encoding,
    format: PublicFormat,
    openssh_allowed: bool,
    raw_allowed: bool,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    if let Ok(ec) = pkey.ec_key() {
        let point_form = match format {
            PublicFormat::UncompressedPoint => openssl::ec::PointConversionForm::UNCOMPRESSED,
            PublicFormat::CompressedPoint => openssl::ec::PointConversionForm::COMPRESSED,
            _ => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "X962 encoding must be used with CompressedPoint or UncompressedPoint format"
                    )
                ));
            }
        };
        let mut bn_ctx = openssl::bn::BigNumContext::new()?;
        let data = ec
            .public_key()
            .to_bytes(ec.group(), point_form, &mut bn_ctx)?;
        return Ok(pyo3::types::PyBytes::new(py, &data));
    }

    Err(CryptographyError::from(
        pyo3::exceptions::PyValueError::new_err("format is invalid with this key"),
    ))
}

pub(crate) enum BytesOrPyBytes<'a> {
    Bytes(&'a [u8]),
    PyBytes(pyo3::Bound<'a, pyo3::types::PyBytes>),
}

impl BytesOrPyBytes<'_> {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            BytesOrPyBytes::Bytes(v) => v,
            BytesOrPyBytes::PyBytes(v) => v.as_bytes(),
        }
    }
}

pub(crate) fn calculate_digest_and_algorithm<'p>(
    py: pyo3::Python<'p>,
    data: &'p [u8],
    algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
) -> CryptographyResult<(BytesOrPyBytes<'p>, pyo3::Bound<'p, pyo3::PyAny>)> {
    let (algorithm, data) = if algorithm.is_instance(&types::PREHASHED.get(py)?)? {
        (
            algorithm.getattr("_algorithm")?,
            BytesOrPyBytes::Bytes(data),
        )
    } else {
        // Potential optimization: rather than allocate a PyBytes in
        // `h.finalize()`, have a way to get the `DigestBytes` directly.
        let mut h = Hash::new(py, algorithm, None)?;
        h.update_bytes(py, data)?;
        (algorithm.clone(), BytesOrPyBytes::PyBytes(h.finalize(py)?))
    };

    if data.as_bytes().len() != (algorithm.getattr("digest_size")?.extract::<usize>()?) {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(
                "The provided data must be the same length as the hash algorithm's digest size.",
            ),
        ));
    }

    Ok((data, algorithm))
}
