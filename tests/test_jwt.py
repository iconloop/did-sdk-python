import time

import pytest
from coincurve import PrivateKey

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.credential import Credential
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.jwt import Jwt, VerifyResult


class TestJwt:
    @pytest.fixture
    def private_key(self):
        return PrivateKey()

    @pytest.fixture
    def dids(self):
        return {
            "did": "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08",
            "target_did": "did:icon:1111961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08"
        }

    @pytest.fixture
    def claim(self):
        return {
            "name": {
                "claimValue": "홍길순",
                "salt": "a1341c4b0cbff6bee9118da10d6e85a5"
            },
            "birthDate": {
                "claimValue": "2000-01-01",
                "salt": "65341c4b0cbff6bee9118da10d6e85a5"
            },
            "gender": {
                "claimValue": "female",
                "salt": "12341c4b0cbff6bee9118da10d6e85a5",
                "displayValue": "여성"
            },
            "telco": {
                "claimValue": "SKT",
                "salt": "91341c4b0cbff6bee9118da10d6e85a5"
            },
            "phoneNumber": {
                "claimValue": "01031142962",
                "salt": "e2341c4b0cbff6bee9118da10d6e85a5",
                "displayValue": "010-3114-2962"
            },
            "connectingInformation": {
                "claimValue": "0000000000000000000000000000000000000000",
                "salt": "ff341c4b0cbff6bee9118da10d6e85a5"
            },
            "citizenship": {
                "claimValue": True,
                "salt": "f2341c4b0cbff6bee9118da10d6e85a5",
                "displayValue": "내국인"
            }
        }

    @pytest.fixture
    def header(self):
        return Header(alg=AlgorithmType.ES256K.name, kid='key1')

    @pytest.fixture
    def payload(self, dids, claim):
        contents = {
            Payload.ISSUER: dids['did'],
            Payload.ISSUED_AT: 1578445403,
            Payload.EXPIRATION: int(time.time() * 1_000_000) * 2,
            Payload.SUBJECT: dids['target_did'],
            Payload.CLAIM: claim,
            Payload.NONCE: 'b0f184df3f4e92ea9496d9a0aad259ae',
            Payload.JTI: '885c592008a5b95a8e348e56b92a2361',
            Payload.TYPE: [Credential.DEFAULT_TYPE] + list(claim.keys()),
            Payload.VERSION: '2.0'
        }
        return Payload(contents)

    @pytest.fixture
    def jwt_object(self, header, payload):
        return Jwt(header, payload)

    def test_encode_and_decode(self, jwt_object, private_key):
        # GIVEN create jwt object
        jwt_for_encoding = jwt_object

        # WHEN encode jwt and create Jwt object using output of jwt_for_encoding
        compact = jwt_for_encoding.compact()
        encoded_token = jwt_for_encoding.sign(private_key)
        jwt_from_encoded_token = Jwt.decode(encoded_token)

        # THEN get same data by decoding jwt with using above signature
        assert compact == jwt_from_encoded_token.compact()
        assert jwt_from_encoded_token.signature in encoded_token

    def test_verify(self, jwt_object, private_key):
        # GIVEN a Jwt object contains an encoded token
        encoded_token = jwt_object.sign(private_key)
        jwt_for_verify = Jwt.decode(encoded_token)

        # WHEN verify the jwt token with correct public key
        result = jwt_for_verify.verify(private_key.public_key)

        # THEN get success result
        assert VerifyResult(success=True) == result

    @pytest.mark.parametrize('contents', [
        {Payload.EXPIRATION: int(time.time() * 1_000_000) * 2},
        {Payload.EXPIRATION: int(time.time() * 1_000_000) / 2},
    ])
    def test_verify_expired(self, header, contents):
        now = int(time.time() * 1_000_000)

        # GIVEN a jwt object contains the expiration parameter
        payload = Payload(contents)
        jwt_object = Jwt(header, payload)

        # WHEN verify expiration
        # THEN get the same result of them
        # the gap between now and expiration
        # and the result after verifying expiration.
        assert (jwt_object.payload.exp > now) == jwt_object.verify_expired().success
