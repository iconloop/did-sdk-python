import time

import pytest

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.jwt.issuer_did import IssuerDid


class TestIssuerDid:
    @pytest.fixture
    def did_key_holder(self, dids, key_id, private_key) -> DidKeyHolder:
        return DidKeyHolder(dids["did"], key_id, AlgorithmType.ES256K, private_key)

    def test_as_jwt(self, dids, key_id):
        # GIVEN a issuer_did, an issued time and an expiration
        issuer_did = IssuerDid(dids["did"], AlgorithmType.ES256K.name, key_id)
        issued = int(time.time())
        expiration = issued * 2

        # WHEN convert issuer_did to jwt
        jwt_object = issuer_did.as_jwt(issued, expiration)

        # THEN success converting
        assert issuer_did.did == jwt_object.payload.iss
        assert issuer_did.algorithm == jwt_object.header.alg
        assert issuer_did.key_id == jwt_object.header.kid.split("#")[1]

    def test_from_did_key_holder(self, did_key_holder):
        # GIVEN a did key holder object
        # WHEN try to convert it to a IssuerDid object
        issuer_did = IssuerDid.from_did_key_holder(did_key_holder)

        # THEN success converting
        assert issuer_did.did == did_key_holder.did
        assert issuer_did.algorithm == did_key_holder.type.name
        assert issuer_did.key_id == did_key_holder.key_id

    def test_from_encoded_jwt(self, encoded_jwt, jwt_object):
        # GIVEN an encoded jwt.
        # WHEN try to convert it to a IssuerDid object
        issuer_did = IssuerDid.from_encoded_jwt(encoded_jwt)

        # THEN success converting
        assert issuer_did.did == jwt_object.payload.iss
        assert issuer_did.algorithm == jwt_object.header.alg
        assert issuer_did.key_id == jwt_object.header.kid.split("#")[1]

    def test_from_jwt(self, jwt_object):
        # GIVEN a Jwt object.
        # WHEN try to convert it to a IssuerDid object
        issuer_did = IssuerDid.from_jwt(jwt_object)

        # THEN success converting
        assert issuer_did.did == jwt_object.payload.iss
        assert issuer_did.algorithm == jwt_object.header.alg
        assert issuer_did.key_id == jwt_object.header.kid.split("#")[1]
