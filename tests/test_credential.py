import time

import pytest

from didsdk.credential import Credential


class TestCredential:
    @pytest.fixture
    def credential(self, issuer_did, dids):
        return Credential(issuer_did=issuer_did, target_did=dids['target_did'])

    def test_add_claim(self, credential):
        # GIVEN a credential object
        # WHEN try to add a claim
        type_ = 'test_claim'
        value = 'hello'
        credential.add_claim(type_, value)

        # THEN it contains the claim
        assert credential.claim.get(type_) == value

    def test_as_jwt(self, credential):
        # GIVEN a credential object, an issued time and an expiration
        issued = int(time.time()*1_000_000)
        expiration = issued * 2

        # WHEN convert the credential to jwt
        jwt_object = credential.as_jwt(issued, expiration)

        # THEN success converting
        assert credential.did == jwt_object.payload.iss
        assert credential.key_id == jwt_object.header.kid.split('#')[1]
        assert issued == jwt_object.payload.iat
        assert expiration == jwt_object.payload.exp

    def test_from_encoded_jwt(self, encoded_jwt, jwt_object):
        # GIVEN a Jwt object.
        # WHEN try to convert it to a Credential object
        credential = Credential.from_encoded_jwt(encoded_jwt)
        payload = jwt_object.payload

        # THEN success converting
        assert credential.did == payload.iss
        assert credential.target_did == payload.sub
        assert credential.algorithm == jwt_object.header.alg
        assert credential.key_id == jwt_object.header.kid.split('#')[1]
        assert credential.claim == payload.claim
        assert credential.nonce == payload.nonce
        assert credential.jti == payload.jti
        assert credential.get_types() == payload.type
        assert credential.version == payload.version

    def test_from_jwt(self, jwt_object):
        # GIVEN a Jwt object.
        # WHEN try to convert it to a Credential object
        credential = Credential.from_jwt(jwt_object)
        payload = jwt_object.payload

        # THEN success converting
        assert credential.did == payload.iss
        assert credential.target_did == payload.sub
        assert credential.algorithm == jwt_object.header.alg
        assert credential.key_id == jwt_object.header.kid.split('#')[1]
        assert credential.claim == payload.claim
        assert credential.nonce == payload.nonce
        assert credential.jti == payload.jti
        assert credential.get_types() == payload.type
        assert credential.version == payload.version
