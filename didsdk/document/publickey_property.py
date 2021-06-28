import json
from dataclasses import dataclass
from typing import List

from coincurve import PublicKey

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.document.encoding import EncodeType


@dataclass(frozen=True)
class PublicKeyProperty:
    """This corresponds to the publicKeys property of the DIDs specification.
    https://w3c-ccg.github.io/did-spec/#public-keys
    """
    id: str
    type: List[str]
    publicKey: PublicKey
    encodeType: EncodeType
    created: int = None
    revoked: int = None

    @property
    def algorithm_type(self):
        return AlgorithmType.from_identifier(self.type[0])

    def asdict(self):
        dict_object = {
            'id': self.id,
            'type': self.type,
            'publicKey': self.publicKey.format().hex(),
            'encodeType': self.encodeType.name,
        }

        if self.created:
            dict_object['created'] = self.created
        if self.revoked:
            dict_object['revoked'] = self.revoked

        return dict_object

    @classmethod
    def from_json(cls, json_str: str) -> 'PublicKeyProperty':
        dict_object = json.loads(json_str)
        dict_object['encodeType'] = EncodeType[dict_object['encodeType']]
        dict_object['publicKey'] = PublicKey(bytes.fromhex(dict_object['publicKey']))
        return cls(**dict_object)

    def is_revoked(self):
        return self.revoked and self.revoked > 0
