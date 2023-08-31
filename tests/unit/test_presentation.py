import time

import pytest

from didsdk.credential import Credential, CredentialVersion
from didsdk.presentation import Presentation


class TestPresentation:
    @pytest.fixture
    def presentation(self, issuer_did):
        return Presentation(algorithm=issuer_did.algorithm, key_id=issuer_did.key_id, did=issuer_did.did)

    @pytest.fixture
    def presentation_v1_0(self, issuer_did):
        return Presentation(
            algorithm=issuer_did.algorithm, key_id=issuer_did.key_id, did=issuer_did.did, version=CredentialVersion.v1_0
        )

    @pytest.fixture
    def presentation_v1_1(self, issuer_did):
        return Presentation(
            algorithm=issuer_did.algorithm, key_id=issuer_did.key_id, did=issuer_did.did, version=CredentialVersion.v1_1
        )

    @pytest.fixture
    def credential_v1_0(self, issuer_did, dids, vc_claim_for_v1) -> Credential:
        return Credential(
            algorithm=issuer_did.algorithm,
            key_id=issuer_did.key_id,
            did=issuer_did.did,
            target_did=dids["target_did"],
            version=CredentialVersion.v1_0,
            claim=vc_claim_for_v1,
        )

    @pytest.fixture
    def credential_v1_1(self, issuer_did, dids, vc_claim_for_v1) -> Credential:
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

    def test_add_credential(self, presentation_v1_0, credential_v1_0, private_key, request):
        # GIVEN a presentation object and a credential object
        # WHEN try to add a credential
        issued = int(time.time())
        expiration = issued * 2
        presentation_v1_0.add_credential(credential_v1_0.as_jwt(issued, expiration).sign(private_key))
        types = presentation_v1_0.get_types()

        # THEN it contains claims of the credential
        for claim in credential_v1_0.claim:
            assert claim in types

    def test_as_jwt(self, presentation):
        # GIVEN a presentation object, an issued time and an expiration
        issued = int(time.time())
        expiration = issued * 2

        # WHEN convert the presentation to jwt
        jwt_object = presentation.as_jwt(issued, expiration)

        # THEN success converting
        assert presentation.did == jwt_object.payload.iss
        assert presentation.algorithm == jwt_object.header.alg
        assert presentation.key_id == jwt_object.header.kid.split("#")[1]
        assert issued == jwt_object.payload.iat
        assert expiration == jwt_object.payload.exp

    def test_from_encoded_jwt(self, encoded_jwt, jwt_object):
        # GIVEN a Jwt object.
        # WHEN try to convert it to a Presentation object
        presentation = Presentation.from_encoded_jwt(encoded_jwt)
        payload = jwt_object.payload

        # THEN success converting
        assert presentation.did == payload.iss
        assert presentation.algorithm == jwt_object.header.alg
        assert presentation.key_id == jwt_object.header.kid.split("#")[1]

        types = presentation.get_types()
        for encoded_credential in payload.credential:
            credential = Credential.from_encoded_jwt(encoded_credential)
            for type_ in credential.claim.keys():
                assert type_ in types

        assert presentation.nonce == payload.nonce
        assert presentation.jti == payload.jti
        assert presentation.version == payload.version

    def test_from_jwt(self, jwt_object):
        # GIVEN a Jwt object.
        # WHEN try to convert it to a Presentation object
        presentation = Presentation.from_jwt(jwt_object)
        payload = jwt_object.payload

        # THEN success converting
        assert presentation.did == payload.iss
        assert presentation.algorithm == jwt_object.header.alg
        assert presentation.key_id == jwt_object.header.kid.split("#")[1]

        types = presentation.get_types()
        for encoded_credential in payload.credential:
            credential = Credential.from_encoded_jwt(encoded_credential)
            for type_ in credential.claim.keys():
                assert type_ in types

        assert presentation.nonce == payload.nonce
        assert presentation.jti == payload.jti
        assert presentation.version == payload.version

    # TODO After knowing it's usage of the method `get_plain_params`.
    def test_get_plain_params(self):
        pass
