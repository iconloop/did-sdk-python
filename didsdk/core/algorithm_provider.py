import secrets
from dataclasses import dataclass
from enum import Enum
from os import environ
from typing import Optional

from ecdsa.curves import Curve, NIST256p, NIST521p, SECP256k1

from didsdk.core.algorithm import Algorithm


@dataclass
class TypePlate:
    identifier: str
    signature_algorithm: str
    key_algorithm: str
    ecdsa_curve: Optional[Curve]


class AlgorithmType(Enum):
    RS256 = TypePlate(
        identifier="RsaVerificationKey2018", signature_algorithm="SHA256withRSA", key_algorithm="RSA", ecdsa_curve=None
    )
    ES256 = TypePlate(
        identifier="Secp256r1VerificationKey",
        signature_algorithm="SHA256withECDSA",
        key_algorithm="EC",
        ecdsa_curve=NIST256p,
    )
    ES256K = TypePlate(
        identifier="Secp256k1VerificationKey",
        signature_algorithm="SHA256withECDSA",
        key_algorithm="EC",
        ecdsa_curve=SECP256k1,
    )
    NONE = TypePlate(identifier="none", signature_algorithm="none", key_algorithm="none", ecdsa_curve=NIST521p)

    @classmethod
    def from_identifier(cls, identifier: str) -> TypePlate:
        if not identifier:
            raise ValueError("The attribute of 'identifier' can not be None or emptied.")

        for member in cls.__members__.values():
            obj: TypePlate = member.value
            if identifier == obj.identifier:
                return member

        raise ValueError(f"The identifier of '{identifier}' is not supported.")

    @classmethod
    def from_ecdsa_curve(cls, ecdsa_curve: str) -> "AlgorithmType":
        if not ecdsa_curve:
            raise ValueError("The attribute of 'ecdsa_curve' can not be None or emptied.")

        for member in cls.__members__.values():
            obj: TypePlate = member.value
            if ecdsa_curve == obj.ecdsa_curve:
                return member


class AlgorithmProvider:
    IS_ANDROID = -1
    MIN_BOUNCY_CASTLE_VERSION: float = 1.54
    PROVIDER: str = "BC"

    @staticmethod
    def create(type_: AlgorithmType) -> "Algorithm":
        if type_:
            if type_ == AlgorithmType.ES256K:
                from didsdk.core.es256k_algorithm import ES256KAlgorithm

                return ES256KAlgorithm()
            elif type_ == AlgorithmType.NONE:
                from didsdk.core.none_algorithm import NoneAlgorithm

                return NoneAlgorithm()
            else:
                raise ValueError(f"{type_.name} is not supported yet.")
        else:
            raise ValueError("Type cannot be null.")

    @staticmethod
    def generate_random_nonce(size: int) -> bytes:
        return secrets.token_bytes(size)

    @staticmethod
    def is_android_runtime():
        if AlgorithmProvider.IS_ANDROID == -1:
            AlgorithmProvider.IS_ANDROID = 1 if "ANDROID_BOOTLOGO" in environ else 0

        return AlgorithmProvider.IS_ANDROID == 1
