from coincurve import PrivateKey, PublicKey

from didsdk.core.algorithm import Algorithm
from didsdk.core.algorithm_provider import AlgorithmType


class NoneAlgorithm(Algorithm):
    def __init__(self):
        self._type = AlgorithmType.NONE

    @property
    def type(self) -> AlgorithmType:
        return self._type

    def bytes_to_public_key(self, bytes_format: bytes) -> None:
        return None

    def bytes_to_private_key(self, bytes_format: bytes) -> None:
        return None

    def generate_key_pair(self) -> None:
        return None

    def sign(self, private_key: PrivateKey, data: bytes) -> bytes:
        return bytes()

    def verify(self, public_key: PublicKey, data: bytes, signature: bytes) -> bool:
        return True

    def public_key_to_bytes(self, public_key: PublicKey):
        return bytes()

    def private_key_to_bytes(self, private_key: PrivateKey):
        return bytes()
