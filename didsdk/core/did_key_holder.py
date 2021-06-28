from dataclasses import dataclass

from coincurve import PrivateKey

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.jwt.jwt import Jwt


@dataclass(frozen=True)
class DidKeyHolder:
    """This class holds the private key corresponding to the publicKey registered in the DID Document.

    To find a privateKey that matches a publicKey registered in a block chain,
    It is responsible for signing Jwt with the privateKey you have.
    """

    did: str
    key_id: str
    type: AlgorithmType
    private_key: PrivateKey

    def __eq__(self, other: 'DidKeyHolder') -> bool:
        return (other
                and self.did == other.did
                and self.key_id == other.key_id
                and self.type == other.type
                and self.private_key.to_int() == other.private_key.to_int())

    @property
    def kid(self):
        return self.did + '#' + self.key_id

    def sign(self, jwt: Jwt) -> str:
        """Create a signature and encoded jwt

        :param jwt: a Jwt Object
        :return: the encoded jwt for the `jwt` param.
        """
        return jwt.sign(self.private_key)
