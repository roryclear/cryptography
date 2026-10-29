# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc
from cryptography.hazmat._oid import ObjectIdentifier
from cryptography.hazmat.bindings._rust import openssl as rust_openssl


class EllipticCurve(metaclass=abc.ABCMeta): pass
class EllipticCurveSignatureAlgorithm(metaclass=abc.ABCMeta): pass
class EllipticCurvePrivateKey(metaclass=abc.ABCMeta): pass



EllipticCurvePrivateKeyWithSerialization = EllipticCurvePrivateKey
EllipticCurvePrivateKey.register(rust_openssl.ec.ECPrivateKey)


class EllipticCurvePublicKey(metaclass=abc.ABCMeta): pass

class SECP521R1(EllipticCurve):
    name = "secp521r1"
    key_size = 521
    group_order = 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409  # noqa: E501


class SECP384R1(EllipticCurve):
    name = "secp384r1"
    key_size = 384
    group_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973  # noqa: E501


class SECP256R1(EllipticCurve):
    name = "secp256r1"
    key_size = 256
    group_order = (
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    )


class SECP256K1(EllipticCurve):
    name = "secp256k1"
    key_size = 256
    group_order = (
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    )


class SECP224R1(EllipticCurve):
    name = "secp224r1"
    key_size = 224
    group_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D


class SECP192R1(EllipticCurve):
    name = "secp192r1"
    key_size = 192
    group_order = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831


class BrainpoolP256R1(EllipticCurve):
    name = "brainpoolP256r1"
    key_size = 256
    group_order = (
        0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
    )


class BrainpoolP384R1(EllipticCurve):
    name = "brainpoolP384r1"
    key_size = 384
    group_order = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565  # noqa: E501


class BrainpoolP512R1(EllipticCurve):
    name = "brainpoolP512r1"
    key_size = 512
    group_order = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069  # noqa: E501


_CURVE_TYPES: dict[str, EllipticCurve] = {
    "prime192v1": SECP192R1(),
    "prime256v1": SECP256R1(),
    "secp192r1": SECP192R1(),
    "secp224r1": SECP224R1(),
    "secp256r1": SECP256R1(),
    "secp384r1": SECP384R1(),
    "secp521r1": SECP521R1(),
    "secp256k1": SECP256K1(),
    "brainpoolP256r1": BrainpoolP256R1(),
    "brainpoolP384r1": BrainpoolP384R1(),
    "brainpoolP512r1": BrainpoolP512R1(),
}

