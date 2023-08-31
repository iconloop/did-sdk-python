import time

import pytest

from didsdk.document.encoding import Base64URLEncoder
from didsdk.jwt.elements import Payload
from didsdk.jwt.jwt import Jwt, VerifyResult


class TestJwt:
    def test_encode_and_decode(self, jwt_object, private_key):
        # GIVEN create jwt object
        jwt_for_encoding = jwt_object

        # WHEN encode jwt and create Jwt object using output of jwt_for_encoding
        compact = jwt_for_encoding.compact()
        encoded_token = jwt_for_encoding.sign(private_key)
        jwt_from_encoded_token = Jwt.decode(encoded_token)

        # THEN get same data by decoding jwt with using above signature
        assert compact == jwt_from_encoded_token.compact()
        assert jwt_from_encoded_token.signature in Base64URLEncoder.add_padding(encoded_token.split(".")[2])

    def test_verify(self, jwt_object, private_key):
        # GIVEN a Jwt object contains an encoded token
        encoded_token = jwt_object.sign(private_key)
        jwt_for_verify = Jwt.decode(encoded_token)

        # WHEN verify the jwt token with correct public key
        result = jwt_for_verify.verify(private_key.public_key)

        # THEN get success result
        assert VerifyResult(success=True) == result

    @pytest.mark.parametrize(
        "contents",
        [
            {Payload.EXPIRATION: int(time.time()) * 2},
            {Payload.EXPIRATION: int(time.time()) / 2},
        ],
    )
    def test_verify_expired(self, header, contents):
        now = int(time.time())

        # GIVEN a jwt object contains the expiration parameter
        payload = Payload(contents)
        jwt_object = Jwt(header, payload)

        # WHEN verify expiration
        # THEN get the same result of them
        # the gap between now and expiration
        # and the result after verifying expiration.
        assert (jwt_object.payload.exp > now) == jwt_object.verify_expired().success
