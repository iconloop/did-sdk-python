from coincurve import PrivateKey, PublicKey

from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.core.key_provider import KeyProvider
from didsdk.document.encoding import EncodeType
from didsdk.document.publickey_property import PublicKeyProperty
from didsdk.jwt.jwt import Jwt
from didsdk.score.did_score_parameter import DidScoreParameter


class TestScoreParameter:
    KEYS_ES256K = {
        "public": "03efd114fdfc1840af7720dc18ab261ca1fc3069343b725343e9c6b7139d97326d",
        "private": "c51ae01c2721f1d60ba84be88932c736eee4dfc810387335b8c91d4539b5f2cc",
    }
    TEMP_DID = "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08"

    def test_create(self, key_id: str):
        # GIVEN the KeyProvider object
        type_ = AlgorithmType.ES256K
        algorithm = AlgorithmProvider.create(type_)
        private_key: PrivateKey = PrivateKey(bytes.fromhex(self.KEYS_ES256K["private"]))
        public_key: PublicKey = PublicKey(bytes.fromhex(self.KEYS_ES256K["public"]))
        key_provider = KeyProvider(key_id, type_, public_key, private_key)

        # WHEN create the parameter set from above data
        json_str = DidScoreParameter.create(key_provider, EncodeType.HEX)
        public_key_property = PublicKeyProperty.from_json(json_str)

        # THEN success to get same data by PublicKeyProperty object
        assert key_id == public_key_property.id
        assert type_ == public_key_property.algorithm_type
        assert algorithm.public_key_to_bytes(public_key) == algorithm.public_key_to_bytes(
            public_key_property.public_key
        )

    def test_add_key(self, key_id):
        # GIVEN the DidKeyHolder object
        auth_type = AlgorithmType.ES256K
        auth_private_key = PrivateKey(bytes.fromhex(self.KEYS_ES256K["private"]))
        did_holder_key = DidKeyHolder(did=self.TEMP_DID, key_id=key_id, private_key=auth_private_key, type=auth_type)

        # GIVEN the new KeyProvider object and DidScoreParameter object.
        new_type = AlgorithmType.ES256K
        new_private_key: PrivateKey = PrivateKey(bytes.fromhex(self.KEYS_ES256K["private"]))
        new_public_key: PublicKey = PublicKey(bytes.fromhex(self.KEYS_ES256K["public"]))
        new_key_provider = KeyProvider(key_id, new_type, new_public_key, new_private_key)

        # WHEN try to convert add_key method to Jwt object
        jwt: Jwt = DidScoreParameter.add_key(did_holder_key, new_key_provider, EncodeType.BASE64)

        # THEN success sign the Jwt object to add the key without any error
        did_holder_key.sign(jwt)

    def test_revoke_key(self, key_id):
        # GIVEN the DidKeyHolder object
        auth_type = AlgorithmType.ES256K
        auth_private_key = PrivateKey(bytes.fromhex(self.KEYS_ES256K["private"]))
        did_holder_key = DidKeyHolder(did=self.TEMP_DID, key_id=key_id, private_key=auth_private_key, type=auth_type)

        # GIVEN the key id to revoke
        revoke_key_id = "key2"
        # WHEN
        jwt: Jwt = DidScoreParameter.revoke_key(did_holder_key, revoke_key_id)

        # THEN success sign the Jwt object to revoke the key without any error
        did_holder_key.sign(jwt)
