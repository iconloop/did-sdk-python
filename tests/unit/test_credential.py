import time

import pytest
from coincurve import PrivateKey

from didsdk.credential import Credential, CredentialVersion
from didsdk.jwt.elements import Payload
from didsdk.jwt.jwt import Jwt


class TestCredential:
    @pytest.fixture
    def credential_v1(self, issuer_did, dids, vc_claim_for_v1) -> Credential:
        return Credential(
            algorithm=issuer_did.algorithm,
            key_id=issuer_did.key_id,
            did=issuer_did.did,
            target_did=dids["target_did"],
            version=CredentialVersion.v1_1,
            claim=vc_claim_for_v1,
        )

    @pytest.fixture
    def credential_v2(self, credentials) -> Credential:
        return credentials[0]

    @pytest.fixture
    def jwt_object_v1(self, credential_v1) -> Jwt:
        issued = int(time.time())
        expiration = issued * 2
        return credential_v1.as_jwt(issued, expiration)

    @pytest.fixture
    def jwt_object_v2(self, credential_v2) -> Jwt:
        issued = int(time.time())
        expiration = issued * 2
        return credential_v2.as_jwt(issued, expiration)

    @pytest.mark.parametrize("credential", ["credential_v1", "credential_v2"])
    def test_add_claim(self, credential, request):
        # GIVEN a credential object
        credential = request.getfixturevalue(credential)
        # WHEN try to add a claim
        type_ = "test_claim"
        value = "hello"
        credential.add_claim(type_, value)

        # THEN it contains the claim
        assert credential.claim.get(type_) == value

    @pytest.mark.parametrize("credential", ["credential_v1", "credential_v2"])
    def test_as_jwt(self, credential, request):
        # GIVEN a credential object, an issued time and an expiration
        credential = request.getfixturevalue(credential)
        issued = int(time.time())
        expiration = issued * 2

        # WHEN convert the credential to jwt
        jwt_object = credential.as_jwt(issued, expiration)

        # THEN success converting
        assert credential.did == jwt_object.payload.iss
        assert credential.key_id == jwt_object.header.kid.split("#")[1]
        assert issued == jwt_object.payload.iat
        assert expiration == jwt_object.payload.exp

    @pytest.mark.parametrize("jwt_object", ["jwt_object_v1", "jwt_object_v2"])
    def test_from_encoded_jwt(self, jwt_object, private_key: PrivateKey, request):
        # GIVEN a Jwt object and a private_key.
        jwt_object: Jwt = request.getfixturevalue(jwt_object)
        # WHEN try to convert it to a Credential object
        credential: Credential = Credential.from_encoded_jwt(jwt_object.sign(private_key))

        # THEN success converting
        self.check_assertion(credential, jwt_object)

    @pytest.mark.parametrize("jwt_object", ["jwt_object_v1", "jwt_object_v2"])
    def test_from_jwt(self, jwt_object, request):
        # GIVEN a Jwt object.
        jwt_object: Jwt = request.getfixturevalue(jwt_object)
        # WHEN try to convert it to a Credential object
        credential: Credential = Credential.from_jwt(jwt_object)

        # THEN success converting
        self.check_assertion(credential, jwt_object)

    def check_assertion(self, credential, jwt_object):
        payload: Payload = jwt_object.payload

        assert credential.did == payload.iss
        assert credential.target_did == payload.sub
        assert credential.algorithm == jwt_object.header.alg
        assert credential.key_id == jwt_object.header.kid.split("#")[1]
        if credential.version in [CredentialVersion.v1_0, CredentialVersion.v1_1]:
            assert credential.claim == payload.claim
        assert credential.jwt.payload.exp == payload.exp
        assert credential.nonce == payload.nonce
        assert credential.jti == payload.jti
        assert credential.version == payload.version
        assert credential.vc == payload.vc
