from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Type

from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import SigningKey, VerifyingKey
from ecdsa import ellipticcurve
from ecdsa.curves import Curve, NIST256p, SECP256k1, NIST384p, NIST521p

from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
from didsdk.document.encoding import EncodeType


@dataclass
class CurveTypePlate:
    curve_name: str
    algorithm_type: AlgorithmType
    openssl_name: str
    curve_ec: Curve
    curve_cry: Type[ec.EllipticCurve]


# TODO: Remove one attribute of curves(ec, cry).
class CurveType(Enum):
    CURVE_P256 = CurveTypePlate(curve_name="P-256", algorithm_type=AlgorithmType.ES256,
                                openssl_name='secp256r1', curve_ec=NIST256p, curve_cry=ec.SECP256R1)
    CURVE_P256K = CurveTypePlate(curve_name="P-256K", algorithm_type=AlgorithmType.ES256K,
                                 openssl_name="secp256k1", curve_ec=SECP256k1, curve_cry=ec.SECP256K1)
    CURVE_P384 = CurveTypePlate(curve_name="P-384", algorithm_type=AlgorithmType.ES256K,
                                openssl_name="secp384r1", curve_ec=NIST384p, curve_cry=ec.SECP384R1)
    CURVE_P521 = CurveTypePlate(curve_name="P-521", algorithm_type=AlgorithmType.NONE,
                                openssl_name="secp521r1", curve_ec=NIST521p, curve_cry=ec.SECP521R1)


    @classmethod
    def from_curve_name(cls, curve_name: str) -> CurveTypePlate:
        if not curve_name:
            raise ValueError("The attribute of 'curve_name' can not be None or emptied.")

        for member in cls.__members__.values():
            obj: CurveTypePlate = member.value
            if curve_name == obj.curve_name:
                return member

        raise ValueError(f"The identifier of '{curve_name}' is not supported.")

    @classmethod
    def from_name(cls, name: str) -> CurveTypePlate:
        return cls.__members__.get(name)


# TODO: Checked the class that works or not for the designed purpose.
@dataclass
class ECDHKey:
    kty: str
    crv: str
    x: str
    y: str
    d: str = None

    @staticmethod
    def generate_key(curve_name: str) -> 'ECDHKey':
        provider = AlgorithmProvider.create(CurveType.from_curve_name(curve_name).algorithm_type)
        key = SigningKey.generate(curve=CurveType.from_curve_name(curve_name).curve_ec)

        public_key = key.verifying_key
        length = (public_key.verifying_key_length + 7)/8
        x = public_key.pubkey.point.x().to_bytes(length=length, byteorder='big')
        y = public_key.pubkey.point.y().to_bytes(length=length, byteorder='big')

        private_key = key.privkey
        d = private_key.secret_multiplier.to_bytes(length=length, byteorder='big')
        encoder = EncodeType.BASE64URL.value
        return ECDHKey(kty=provider.type.key_algorithm, crv=curve_name,
                       x=encoder.encode(x), y=encoder.encode(y), d=encoder.encode(d))

    def get_ec_public_key(self) -> VerifyingKey:
        x = int.from_bytes(self.x, 'big')
        y = int.from_bytes(self.y, 'big')
        curve = CurveType.from_curve_name(self.crv).curve_ec

        return VerifyingKey.from_public_point(ellipticcurve.Point(curve.generator.curve, x, y), hashfunc=sha256)

    def get_ec_private_key(self) -> SigningKey:
        d = int.from_bytes(self.d, 'big')
        curve = CurveType.from_curve_name(self.crv).curve_ec

        return SigningKey.from_secret_exponent(secexp=d, curve=curve, hashfunc=sha256)

    @classmethod
    def get_jwe_header_key(cls, private_key: 'ECDHKey'):
        return cls(private_key.kty, private_key.crv, private_key.x, private_key.y)
