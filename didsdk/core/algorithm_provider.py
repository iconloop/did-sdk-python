from dataclasses import dataclass
from enum import Enum
from os import environ

from didsdk.core.algorithm import Algorithm
from didsdk.core.es256k_algorithm import ES256KAlgorithm
from didsdk.core.none_algorithm import NoneAlgorithm


@dataclass
class TypePlate:
    identifier: str
    signature_algorithm: str
    key_algorithm: str


class AlgorithmType(Enum):
    RS256 = TypePlate(identifier='RsaVerificationKey2018', signature_algorithm='SHA256withRSA', key_algorithm='RSA')
    ES256 = TypePlate(identifier='Secp256r1VerificationKey', signature_algorithm='SHA256withECDSA', key_algorithm='EC')
    ES256K = TypePlate(identifier='Secp256k1VerificationKey', signature_algorithm='SHA256withECDSA', key_algorithm='EC')
    NONE = TypePlate(identifier='none', signature_algorithm='none', key_algorithm='none')

    @classmethod
    def from_identifier(cls, identifier: str):
        if not identifier:
            raise ValueError("The attribute of 'identifier' can not be None or emptied.")

        for member in cls.__members__.values():
            obj: TypePlate = member.value
            if identifier == obj.identifier:
                return member

        raise ValueError(f"The identifier of '{identifier}' is not supported.")

    @classmethod
    def from_name(cls, name: str):
        return cls.__members__.get(name)


class AlgorithmProvider:
    IS_ANDROID = -1
    MIN_BOUNCY_CASTLE_VERSION: float = 1.54
    PROVIDER: str = 'BC'
    SECURE_RANDOM: 'SecureRandom' = None

    @staticmethod
    def create(type_: AlgorithmType) -> Algorithm:
        if type_:
            if type_ == AlgorithmType.ES256K:
                return ES256KAlgorithm()
            elif type_ == AlgorithmType.NONE:
                return NoneAlgorithm()
            else:
                raise ValueError(f'{type_.name} is not supported yet.')
        else:
            raise ValueError('Type cannot be null.')

    @staticmethod
    def is_android_runtime():
        if AlgorithmProvider.IS_ANDROID == -1:
            AlgorithmProvider.IS_ANDROID = 1 if 'ANDROID_BOOTLOGO' in environ else 0

        return AlgorithmProvider.IS_ANDROID == 1

    # TODO: check this part
    @staticmethod
    def ummmmmmm():
        if AlgorithmProvider.is_android_runtime():
            # LinuxSecureRandom()
            pass
