# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc

class EllipticCurve(metaclass=abc.ABCMeta): pass
class EllipticCurveSignatureAlgorithm(metaclass=abc.ABCMeta): pass
class EllipticCurvePrivateKey(metaclass=abc.ABCMeta): pass



class EllipticCurvePublicKey(metaclass=abc.ABCMeta): pass

class SECP256R1(metaclass=abc.ABCMeta):
    name = "secp256r1"
    key_size = 256
    group_order = (
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    )

_CURVE_TYPES = {
    "prime256v1": SECP256R1(),
}

