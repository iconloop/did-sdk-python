from coincurve import PublicKey, PrivateKey

from didsdk.core.algorithm_provider import AlgorithmType, AlgorithmProvider


class KeyProvider:
    def __init__(self, key_id: str, type_: AlgorithmType, public_key: PublicKey, private_key: PrivateKey):
        self._key_id: str = key_id
        self._type: AlgorithmType = type_
        self._public_key: PublicKey = public_key
        self._private_key: PrivateKey = private_key

    def __eq__(self, other):
        algorithm = AlgorithmProvider.create(self._type)
        return (self._key_id == other.key_id and
                self._type == other.type and
                algorithm.public_key_to_bytes(self._public_key) == algorithm.public_key_to_bytes(other.public_key) and
                algorithm.private_key_to_bytes(self._private_key) == algorithm.private_key_to_bytes(other.private_key))

    @property
    def key_id(self):
        return self._key_id

    @property
    def type(self):
        return self._type

    @property
    def public_key(self):
        return self._public_key

    @property
    def private_key(self):
        return self._private_key
