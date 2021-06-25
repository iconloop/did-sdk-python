from coincurve import PrivateKey

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.jwt.jwt import Jwt


class DidKeyHolder:
    """This class holds the private key corresponding to the publicKey registered in the DID Document.

    To find a privateKey that matches a publicKey registered in a block chain,
    It is responsible for signing Jwt with the privateKey you have.
    """
    def __init__(self, did: str, key_id: str, type_: AlgorithmType, private_key: PrivateKey):
        self._did: str = did
        self._key_id: str = key_id
        self._type: AlgorithmType = type_
        self._private_key: PrivateKey = private_key

    def __eq__(self, other: 'DidKeyHolder') -> bool:
        return (other
                and self._did == other.did
                and self._key_id == other.key_id
                and self._type == other.type
                and self._private_key.to_int() == other.private_key.to_int())

    @property
    def did(self) -> str:
        return self._did

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def type(self) -> AlgorithmType:
        return self._type

    @property
    def private_key(self) -> PrivateKey:
        return self._private_key

    def sign(self, jwt: Jwt) -> str:
        """Create a signature and encoded jwt

        :param jwt: a Jwt Object
        :return: the encoded jwt for the `jwt` param.
        """
        return jwt.sign(self._private_key)
