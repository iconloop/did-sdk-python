from dataclasses import dataclass
from typing import Any, Dict

from coincurve import PrivateKey
from eth_keyfile import create_keyfile_json, decode_keyfile_json

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

    def __eq__(self, other: "DidKeyHolder") -> bool:
        return (
            other
            and self.did == other.did
            and self.key_id == other.key_id
            and self.type == other.type
            and self.private_key.to_int() == other.private_key.to_int()
        )

    @property
    def kid(self):
        return self.did + "#" + self.key_id

    def sign(self, jwt: Jwt) -> str:
        """Create a signature and encoded jwt

        :param jwt: a Jwt Object
        :return: the encoded jwt for the `jwt` param.
        """
        return jwt.sign(self.private_key)

    @classmethod
    def from_dict(cls, key_holder: Dict[str, Any], password: str) -> "DidKeyHolder":
        private_key: bytes = decode_keyfile_json(key_holder, password)
        return DidKeyHolder(
            did=key_holder.get("did"),
            key_id=key_holder.get("keyId"),
            type=AlgorithmType[key_holder.get("type")],
            private_key=PrivateKey(private_key),
        )

    def to_dict(self, password: str) -> Dict[str, Any]:
        result: Dict[str, Any] = create_keyfile_json(
            self.private_key.secret,
            bytes(password, "utf-8"),
            iterations=16384,
            kdf="scrypt",
        )
        result.update({"did": self.did, "keyId": self.key_id, "type": self.type.name})
        return result
