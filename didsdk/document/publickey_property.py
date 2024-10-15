import base64
import json
from dataclasses import dataclass
from typing import List, Union

from coincurve import PublicKey

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.core.property_name import PropertyName
from didsdk.document.encoding import EncodeType


@dataclass(frozen=True)
class PublicKeyProperty:
    """This corresponds to the publicKeys property of the DIDs specification.

    https://w3c-ccg.github.io/did-spec/#public-keys
    """

    id: str
    type: List[str]
    public_key: PublicKey
    encode_type: EncodeType
    created: Union[int, None] = None
    revoked: Union[int, None] = None

    @property
    def algorithm_type(self):
        return AlgorithmType.from_identifier(self.type[0])

    def _encode_base64_url(self, data: bytes, encoding: str = "UTF-8") -> str:
        return base64.urlsafe_b64encode(data).decode(encoding)

    def as_dict(self):
        pubkey_property = (
            PropertyName.KEY_DOCUMENT_PUBLICKEY_HEX
            if self.encode_type == EncodeType.HEX
            else PropertyName.KEY_DOCUMENT_PUBLICKEY_BASE64
        )

        dict_object = {
            "id": self.id,
            "type": self.type,
            pubkey_property: self.encode_type.value.encode(self.public_key.format(compressed=False)),
        }

        if self.created:
            dict_object["created"] = self.created
        if self.revoked:
            dict_object["revoked"] = self.revoked

        return dict_object

    @classmethod
    def from_json(cls, json_data: Union[str, dict]) -> "PublicKeyProperty":
        json_data = json.loads(json_data) if isinstance(json_data, str) else json_data
        if PropertyName.KEY_DOCUMENT_PUBLICKEY_HEX in json_data:
            encode_type = EncodeType.HEX
            public_key_data = json_data[PropertyName.KEY_DOCUMENT_PUBLICKEY_HEX]
        else:
            encode_type = EncodeType.BASE64
            public_key_data = json_data[PropertyName.KEY_DOCUMENT_PUBLICKEY_BASE64]

        created = json_data.get(PropertyName.KEY_DOCUMENT_PUBLICKEY_CREATED)
        revoked = json_data.get(PropertyName.KEY_DOCUMENT_PUBLICKEY_REVOKED)

        return cls(
            id=json_data[PropertyName.KEY_DOCUMENT_PUBLICKEY_ID],
            type=json_data[PropertyName.KEY_DOCUMENT_PUBLICKEY_TYPE],
            public_key=PublicKey(encode_type.value.decode(public_key_data)),
            encode_type=encode_type,
            created=created,
            revoked=revoked,
        )

    def is_revoked(self):
        return self.revoked and self.revoked > 0
