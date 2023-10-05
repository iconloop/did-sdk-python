import json
from typing import Dict, List, Union

from didsdk.core.property_name import PropertyName
from didsdk.document.authentication_property import AuthenticationProperty
from didsdk.document.publickey_property import PublicKeyProperty


class Document:
    """This corresponds to the Document object of the DIDs specification.

    https://w3c-ccg.github.io/did-spec/#did-documents
    """

    def __init__(
        self, id_: str, created: int, public_key: dict, authentication: list, version: str = None, updated: int = None
    ):
        self.version: str = version
        self.id: str = id_
        self.created: int = created
        self.updated: int = updated
        self.public_key: Dict[str, PublicKeyProperty] = public_key
        self.authentication: List[AuthenticationProperty] = authentication

    @staticmethod
    def deserialize(json_data: Union[str, dict]) -> "Document":
        json_data = json.loads(json_data) if isinstance(json_data, str) else json_data
        public_keys = {
            public_key[PropertyName.KEY_DOCUMENT_PUBLICKEY_ID]: PublicKeyProperty.from_json(public_key)
            for public_key in json_data[PropertyName.KEY_DOCUMENT_PUBLICKEY]
        }

        return Document(
            id_=json_data[PropertyName.KEY_DOCUMENT_ID],
            created=json_data["created"],
            public_key=public_keys,
            authentication=json_data["authentication"],
            version=json_data[PropertyName.KEY_VERSION],
            updated=PropertyName.KEY_DOCUMENT_UPDATED,
        )

    def get_public_key_property(self, key_id: str) -> PublicKeyProperty:
        return self.public_key.get(key_id)

    def serialize(self) -> str:
        public_key = [public_key_property.as_dict() for _, public_key_property in self.public_key.items()]
        dict_data = {
            PropertyName.KEY_DOCUMENT_ID: self.id,
            PropertyName.KEY_DOCUMENT_CREATED: self.created,
            PropertyName.KEY_DOCUMENT_PUBLICKEY: public_key,
            PropertyName.KEY_DOCUMENT_AUTHENTICATION: self.authentication,
        }

        if self.updated:
            dict_data[PropertyName.KEY_DOCUMENT_UPDATED] = self.updated
        if self.version:
            dict_data[PropertyName.KEY_VERSION] = self.version

        return json.dumps(dict_data)
