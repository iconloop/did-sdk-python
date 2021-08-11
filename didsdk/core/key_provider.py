from dataclasses import dataclass

from coincurve import PublicKey, PrivateKey

from didsdk.core.algorithm_provider import AlgorithmType, AlgorithmProvider


@dataclass(frozen=True)
class KeyProvider:
    key_id: str
    type: AlgorithmType
    public_key: PublicKey
    private_key: PrivateKey

    def __eq__(self, other):
        algorithm = AlgorithmProvider.create(self.type)
        return (self.key_id == other.key_id and
                self.type == other.type and
                algorithm.public_key_to_bytes(self.public_key) == algorithm.public_key_to_bytes(other.public_key) and
                algorithm.private_key_to_bytes(self.private_key) == algorithm.private_key_to_bytes(other.private_key))
