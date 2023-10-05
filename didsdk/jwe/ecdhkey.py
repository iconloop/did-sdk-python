import dataclasses
import json
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Union

import ecdsa
from ecdsa import ellipticcurve
from ecdsa.curves import Curve, NIST256p, NIST384p, NIST521p, SECP256k1
from eth_keyfile import load_keyfile
from jwcrypto.jwk import JWK

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.document.encoding import EncodeType


@dataclass
class CurveTypePlate:
    curve_name: str
    algorithm_type: AlgorithmType
    openssl_name: str
    curve_ec: Curve


class EcdhCurveType(Enum):
    P256 = CurveTypePlate(
        curve_name="P-256",
        algorithm_type=AlgorithmType.ES256,
        openssl_name="secp256r1",
        curve_ec=NIST256p,
    )
    P256K = CurveTypePlate(
        curve_name="P-256K",
        algorithm_type=AlgorithmType.ES256K,
        openssl_name="secp256k1",
        curve_ec=SECP256k1,
    )
    P384 = CurveTypePlate(
        curve_name="P-384",
        algorithm_type=AlgorithmType.ES256K,
        openssl_name="secp384r1",
        curve_ec=NIST384p,
    )
    P521 = CurveTypePlate(
        curve_name="P-521",
        algorithm_type=AlgorithmType.NONE,
        openssl_name="secp521r1",
        curve_ec=NIST521p,
    )

    @classmethod
    def from_curve_name(cls, curve_name: str) -> CurveTypePlate:
        if not curve_name:
            raise ValueError("The attribute of 'curve_name' can not be None or emptied.")

        for member in cls.__members__.values():
            obj: CurveTypePlate = member.value
            if curve_name == obj.curve_name or curve_name == obj.openssl_name:
                return member.value

        raise ValueError(f"The curve name of '{curve_name}' is not supported.")


@dataclass
class ECDHKey:
    kty: str
    crv: str
    x: str
    y: str
    d: str = None
    kid: str = None

    def __eq__(self, target):
        return (
            self.kty == target.kty
            and self.crv == target.crv
            and self.x == target.x
            and self.y == target.y
            and self.d == target.d
            and self.kid == target.kid
        )

    def as_dict(self) -> dict:
        ecdh_key: dict = dataclasses.asdict(self)

        if not self.kid:
            del ecdh_key["kid"]
        if not self.d:
            del ecdh_key["d"]

        return ecdh_key

    def as_dict_without_kid(self) -> dict:
        ecdh_key: dict = dataclasses.asdict(self)

        del ecdh_key["kid"]
        if not self.d:
            del ecdh_key["d"]

        return ecdh_key

    def export_private_key(self, as_dict: bool = False) -> Union[dict, "ECDHKey"]:
        ecdh_key = dataclasses.asdict(self)
        del ecdh_key["kid"]

        return ecdh_key if as_dict else ECDHKey(**ecdh_key)

    def export_public_key(self, as_dict: bool = False) -> Union[dict, "ECDHKey"]:
        ecdh_key = dataclasses.asdict(self)
        del ecdh_key["d"]
        del ecdh_key["kid"]

        return ecdh_key if as_dict else ECDHKey(**ecdh_key)

    @staticmethod
    def generate_key(curve_name: str, kid: str = None) -> "ECDHKey":
        key: ecdsa.SigningKey = ecdsa.SigningKey.generate(
            curve=EcdhCurveType.from_curve_name(curve_name).curve_ec, hashfunc=sha256
        )
        jwk_json: dict = JWK.from_pem(key.to_pem()).export(as_dict=True)
        jwk_json["crv"] = EcdhCurveType.from_curve_name(jwk_json.get("crv")).curve_name
        if kid:
            jwk_json["kid"] = kid

        return ECDHKey(**jwk_json)

    def get_ec_public_key(self) -> ecdsa.VerifyingKey:
        x = int.from_bytes(EncodeType.BASE64URL.value.decode(self.x), "big")
        y = int.from_bytes(EncodeType.BASE64URL.value.decode(self.y), "big")
        ec_curve: Curve = EcdhCurveType.from_curve_name(self.crv).curve_ec
        point = ellipticcurve.Point(ec_curve.curve, x, y)

        return ecdsa.VerifyingKey.from_public_point(point, curve=ec_curve, hashfunc=sha256)

    def get_ec_private_key(self) -> ecdsa.SigningKey:
        key_json: str = json.dumps(dataclasses.asdict(self))
        pem = JWK.from_json(key_json).export_to_pem(private_key=True, password=None)
        return ecdsa.SigningKey.from_pem(pem, hashfunc=sha256)

    @staticmethod
    def load_key(file_path: str) -> "ECDHKey":
        with open(file_path, "rb") as file:
            keyfile_json = load_keyfile(file)
            return ECDHKey(**keyfile_json)
