import json
from typing import Union

from didsdk.core.property_name import PropertyName
from didsdk.document.publickey_property import PublicKeyProperty


class Document:
    """This corresponds to the Document object of the DIDs specification.

    https://w3c-ccg.github.io/did-spec/#did-documents
    """

    def __init__(self, id_: str, created: int, public_key: dict, authentication: list,
                 version: str = None, updated: int = None):
        self._version: str = version
        self._id: str = id_
        self._created: int = created
        self._updated: int = updated
        self._public_key: dict = public_key
        self._authentication: list = authentication

    @property
    def authentication(self) -> list:
        return self._authentication

    @property
    def created(self) -> int:
        return self._created

    @property
    def id(self) -> str:
        return self._id

    @property
    def public_key(self) -> dict:
        return self._public_key

    @property
    def updated(self) -> int:
        return self._updated

    @property
    def version(self) -> str:
        return self._version

    @staticmethod
    def deserialize(json_data: Union[str, dict]) -> 'Document':
        json_data = json.loads(json_data) if isinstance(json_data, str) else json_data
        public_keys = {
            public_key[PropertyName.KEY_DOCUMENT_PUBLICKEY_ID]: PublicKeyProperty.from_json(public_key)
            for public_key in json_data[PropertyName.KEY_DOCUMENT_PUBLICKEY]
        }

        return Document(id_=json_data[PropertyName.KEY_DOCUMENT_ID],
                        created=json_data['created'],
                        public_key=public_keys,
                        authentication=json_data['authentication'],
                        version=json_data[PropertyName.KEY_VERSION],
                        updated=PropertyName.KEY_DOCUMENT_UPDATED)

    def get_public_key_property(self, key_id: str) -> PublicKeyProperty:
        return self._public_key.get(key_id)

    def serialize(self) -> str:
        public_key = [public_key_property.asdict() for _, public_key_property in self._public_key.items()]
        dict_data = {PropertyName.KEY_DOCUMENT_ID: self._id,
                     PropertyName.KEY_DOCUMENT_CREATED: self._created,
                     PropertyName.KEY_DOCUMENT_PUBLICKEY: public_key,
                     PropertyName.KEY_DOCUMENT_AUTHENTICATION: self._authentication}

        if self._updated:
            dict_data[PropertyName.KEY_DOCUMENT_UPDATED] = self._updated
        if self._version:
            dict_data[PropertyName.KEY_VERSION] = self._version

        return json.dumps(dict_data)
