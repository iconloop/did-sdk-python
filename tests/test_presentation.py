import time

import pytest

from didsdk.credential import Credential, CredentialVersion
from didsdk.presentation import Presentation


class TestPresentation:
    @pytest.fixture
    def presentation(self, issuer_did):
        return Presentation(issuer_did=issuer_did)

    @pytest.fixture
    def credential_v1(self, issuer_did, dids, vc_claim) -> Credential:
        return Credential(issuer_did=issuer_did,
                          target_did=dids['target_did'],
                          version=CredentialVersion.v1_1,
                          claim=vc_claim)

    @pytest.fixture
    def credential_v2(self, credentials) -> Credential:
        return credentials[0]

    @pytest.mark.parametrize('credential', ['credential_v1', 'credential_v2'])
    def test_add_credential(self, presentation, credential, private_key, request):
        # GIVEN a presentation object and a credential object
        credential = request.getfixturevalue(credential)
        # WHEN try to add a credential
        issued = int(time.time() * 1_000_000)
        expiration = issued * 2
        presentation.add_credential(credential.as_jwt(issued, expiration).sign(private_key))
        types = presentation.get_types()

        # THEN it contains claims of the credential
        for claim in credential.claim:
            assert claim in types

    def test_as_jwt(self, presentation):
        # GIVEN a presentation object, an issued time and an expiration
        issued = int(time.time() * 1_000_000)
        expiration = issued * 2

        # WHEN convert the presentation to jwt
        jwt_object = presentation.as_jwt(issued, expiration)

        # THEN success converting
        assert presentation.did == jwt_object.payload.iss
        assert presentation.algorithm == jwt_object.header.alg
        assert presentation.key_id == jwt_object.header.kid.split('#')[1]
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
        assert presentation.key_id == jwt_object.header.kid.split('#')[1]

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
        assert presentation.key_id == jwt_object.header.kid.split('#')[1]

        types = presentation.get_types()
        for encoded_credential in payload.credential:
            credential = Credential.from_encoded_jwt(encoded_credential)
            for type_ in credential.claim.keys():
                assert type_ in types

        assert presentation.nonce == payload.nonce
        assert presentation.jti == payload.jti
        assert presentation.version == payload.version

    # TODO
    def test_get_plain_params(self):
        pass
