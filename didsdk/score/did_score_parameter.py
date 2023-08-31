import json

from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.core.key_provider import KeyProvider
from didsdk.core.property_name import PropertyName
from didsdk.document.encoding import EncodeType
from didsdk.document.publickey_property import PublicKeyProperty
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.jwt import Jwt


class DidScoreParameter:
    """This class is used to create transaction parameters.

    The transaction parameters that call a score function that can use all the features of the DID document.
    """

    @staticmethod
    def _create_public_key_property(key_provider: KeyProvider, encode_type: EncodeType) -> PublicKeyProperty:
        return PublicKeyProperty(
            id=key_provider.key_id,
            type=[key_provider.type.value.identifier],
            public_key=key_provider.public_key,
            encode_type=encode_type,
        )

    @staticmethod
    def add_key(did_key_holder: DidKeyHolder, key_provider: KeyProvider, encode_type: EncodeType) -> Jwt:
        """Create a parameter for transaction that update the DID Document. (add publicKey)

        It's used for `didsdk.did_service.DidService.add_public_key()`.

        :param did_key_holder: the DidKeyHolder object to use for authentication.
        :param key_provider: the KeyProvider object to add.
        :param encode_type: the encode type
        :return: the Jwt object from parameters.
        """
        header = Header(alg=did_key_holder.type.name, kid=did_key_holder.kid)

        public_key_provider = DidScoreParameter._create_public_key_property(key_provider, encode_type)
        contents = {
            PropertyName.KEY_TX_UPDATE_METHOD: PropertyName.KEY_TX_UPDATE_METHOD_ADDKEY,
            PropertyName.KEY_TX_UPDATE_PARAM: {
                "id": did_key_holder.did,
                PropertyName.KEY_DOCUMENT_PUBLICKEY: public_key_provider.as_dict(),
            },
        }
        payload = Payload(contents=contents)

        return Jwt(header, payload)

    @staticmethod
    def create(key_provider: KeyProvider, encode_type: EncodeType) -> str:
        """Create a parameter set for transaction that creates the DID Document.

        It's used for `didsdk.did_service.DidService.create()`.

        :param key_provider: keyProvider the KeyProvider object
        :param encode_type:
        :return: the json string
        """
        public_key_property = DidScoreParameter._create_public_key_property(key_provider, encode_type)
        return json.dumps(public_key_property.as_dict())

    @staticmethod
    def revoke_key(did_key_holder: DidKeyHolder, revoke_key_id: str) -> Jwt:
        """Create a parameter for transaction that update the DID Document. (revoke publicKey)

        It's used for `didsdk.did_service.DidService.revoke_key()`.

        :param did_key_holder: the DidKeyHolder object to use for authentication.
        :param revoke_key_id: the id of the public key to revoke.
        :return: the Jwt object from parameters.
        """
        header = Header(alg=did_key_holder.type.name, kid=did_key_holder.kid)

        contents = {
            PropertyName.KEY_TX_UPDATE_METHOD: PropertyName.KEY_TX_UPDATE_METHOD_REVOKEKEY,
            PropertyName.KEY_TX_UPDATE_PARAM: {
                PropertyName.KEY_DOCUMENT_ID: did_key_holder.did,
                PropertyName.KEY_DOCUMENT_PUBLICKEY: revoke_key_id,
            },
        }
        payload = Payload(contents=contents)

        return Jwt(header, payload)
