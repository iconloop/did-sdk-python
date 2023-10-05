import traceback
from dataclasses import dataclass

from coincurve import PrivateKey, PublicKey

from didsdk.core.algorithm import Algorithm
from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.exceptions import KeyPairException


@dataclass(frozen=True)
class KeyPair:
    public_key: PublicKey
    private_key: PrivateKey


class ES256KAlgorithm(Algorithm):
    def __init__(self):
        self._type = AlgorithmType.ES256K

    @property
    def type(self) -> AlgorithmType:
        return self._type

    def bytes_to_public_key(self, bytes_format: bytes) -> PublicKey:
        """Convert a bytes to the PublicKey object.

        :param bytes_format: a public key by type of bytes
        :return: a converted PublicKey object from bytes_format.
        """
        try:
            return PublicKey(bytes_format)
        except Exception:
            raise KeyPairException("Can not reconstruct the public key")

    def bytes_to_private_key(self, bytes_format: bytes) -> PrivateKey:
        """Convert a bytes to the PrivateKey object.

        :param bytes_format: a private key by type of bytes
        :return: a converted PrivateKey object from bytes_format.
        """
        try:
            return PrivateKey(bytes_format)
        except Exception:
            raise KeyPairException("Can not reconstruct the private key")

    def generate_key_pair(self) -> KeyPair:
        private_key = PrivateKey()
        return KeyPair(private_key=private_key, public_key=private_key.public_key)

    def public_key_to_bytes(self, public_key: PublicKey, compressed: bool = True):
        return public_key.format(compressed)

    def private_key_to_bytes(self, private_key: PrivateKey):
        return private_key.to_pem()

    def sign(self, private_key: PrivateKey, data: bytes) -> bytes:
        return private_key.sign_recoverable(data)

    def verify(self, public_key: PublicKey, data: bytes, signature: bytes) -> bool:
        try:
            return public_key == PublicKey.from_signature_and_message(signature, data)
        except Exception:
            traceback.print_exc()
            return False
