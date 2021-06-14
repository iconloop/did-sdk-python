from typing import List

from coincurve import PublicKey

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.document.encoding import EncodeType


class PublicKeyProperty:
    """This corresponds to the publicKeys property of the DIDs specification.
    https://w3c-ccg.github.io/did-spec/#public-keys
    """
    def __init__(self, id_: str, public_key: PublicKey, type_: List[str], encode_type: EncodeType, created: int, revoked: int):
        self._id: str = id_
        self._public_key: PublicKey = public_key
        self._type: List[str] = type_
        self._encode_type: EncodeType = encode_type
        self._created: int = created
        self._revoked: int = revoked

    @property
    def id(self) -> str:
        return self._id

    # TODO : essential
    @property
    def public_key(self) -> PublicKey:
        return self._public_key

    @property
    def type(self) -> List[str]:
        return self._type

    @property
    def encode_type(self) -> EncodeType:
        return self._encode_type

    @property
    def created(self) -> int:
        return self._created

    @property
    def revoked(self) -> int:
        return self._revoked

    # TODO : edit to use AlgorithmProvider instead direct Type object.
    @property
    def algorithm_type(self):
        return AlgorithmType.from_identifier(self._type[0])

    def is_revoked(self):
        return self._revoked > 0
