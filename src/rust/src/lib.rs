// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]
#![allow(unknown_lints, non_local_definitions, clippy::result_large_err)]
use std::env;

use openssl::provider;
use pyo3::PyTypeInfo;

use crate::error::CryptographyResult;
mod asn1;
mod backend;
mod buf;
mod declarative_asn1;
mod error;
mod exceptions;
mod fernet;
pub(crate) mod oid;
mod padding;
mod pkcs12;
mod pkcs7;
pub(crate) mod serialization;
pub(crate) mod types;
mod x509;

struct LoadedProviders {
    legacy: Option<provider::Provider>,
    _default: provider::Provider,

    fips: Option<provider::Provider>,
}

#[pyo3::pymodule(gil_used = false)]
mod _rust {
    use pyo3::types::PyModuleMethods;
    #[pymodule_export]
    use crate::serialization::{Encoding, ParameterFormat, PrivateFormat, PublicFormat};

    #[pyo3::pymodule(gil_used = false)]
    mod openssl {
        use pyo3::prelude::PyModuleMethods;
        #[pymodule_export]
        use crate::backend::dh::dh;
        #[pymodule_export]
        use crate::backend::ec::ec;
        #[pymodule_export]
        use crate::backend::hashes::hashes;
        #[pymodule_export]
        use crate::backend::keys::keys;

        #[pymodule_init]
        fn init(openssl_mod: &pyo3::Bound<'_, pyo3::types::PyModule>) -> pyo3::PyResult<()> {
            Ok(())
        }
    }
}
