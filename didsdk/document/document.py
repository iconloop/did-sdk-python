from didsdk.document.converters import Converters
from didsdk.document.publickey_property import PublicKeyProperty


class Document:
    """This corresponds to the Document object of the DIDs specification.
    https://w3c-ccg.github.io/did-spec/#did-documents
    """
    def __init__(self, version: str, id_: str, created: int, updated: int, public_key: dict, authentication: list):
        self._version: str = version
        self._id: str = id_
        self._created: int = created
        self._updated: int = updated
        self._public_key: dict = public_key
        self._authentication: list = authentication

    @property
    def version(self) -> str:
        return self._version

    @property
    def id(self) -> str:
        return self._id

    @property
    def created(self) -> int:
        return self._created

    @property
    def updated(self) -> int:
        return self._updated

    @property
    def public_key(self) -> dict:
        return self._public_key

    @property
    def authentication(self) -> list:
        return self._authentication

    # TODO : essential
    def get_public_key_property(self, key_id: str) -> PublicKeyProperty:
        return self._public_key[key_id]

    # TODO : essential (instead of fromJson())
    def deserialize(self, ):
        return Document()

    # TODO : essential (instead of toJson())
    def serialize(self) -> str:
        return Converters.toJson(self)
