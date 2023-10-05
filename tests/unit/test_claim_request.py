import time

import pytest

from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.credential import CredentialVersion
from didsdk.document.encoding import EncodeType
from didsdk.jwe.ecdhkey import EcdhCurveType, ECDHKey
from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.jwt import Jwt, VerifyResult
from didsdk.protocol.claim_message_type import ClaimRequestType
from didsdk.protocol.claim_request import ClaimRequest
from didsdk.protocol.json_ld.json_ld_vcr import JsonLdVcr


class TestClaimRequest:
    @pytest.mark.parametrize(
        "claim_types, claim_values",
        [(["email"], ["abc@iconloop.com"]), (["email", "phone", "age"], ["abc@iconloop.com", "012-3456-7890", 18])],
        ids=["single", "multi"],
    )
    def test_credential_request_v_1_1(self, claim_types: list, claim_values: list):
        # GIVEN data for ClaimRequest
        algorithm = AlgorithmProvider.create(AlgorithmType.ES256K)
        key_provider = algorithm.generate_key_provider("test_credential_request_v1")
        owner_did = "did:icon:03:485e12f86bea2d16905e6ad4f657031c7a56280af3648b55"
        issuer_did = "did:icon:03:485e12f86bea2d16905e6ad4f657031c7a56280af3648b55"
        version = CredentialVersion.v1_0
        request_date = int(time.time())
        expired_date: int = request_date * 2
        claims: dict = {key: value for key, value in zip(claim_types, claim_values)}
        did_key_holder: DidKeyHolder = DidKeyHolder(
            key_id=key_provider.key_id, type=key_provider.type, private_key=key_provider.private_key, did=owner_did
        )

        # WHEN try to create jwt token of `REQ_CREDENTIAL` message.
        request: ClaimRequest = ClaimRequest.from_(
            type_=ClaimRequestType.REQ_CREDENTIAL,
            algorithm=did_key_holder.type,
            public_key_id=did_key_holder.key_id,
            did=did_key_holder.did,
            claims=claims,
            response_id=issuer_did,
            request_date=request_date,
            expired_date=expired_date,
            version=version,
        )
        signed_jwt: str = did_key_holder.sign(request.jwt)

        # THEN success to decode ClaimRequest object.
        decoded_request: ClaimRequest = ClaimRequest.from_jwt(Jwt.decode(signed_jwt))
        expected = request.jwt.payload.contents
        decoded_contents = decoded_request.jwt.payload.contents
        assert list(expected.keys()) == list(decoded_contents.keys())
        assert list(expected.values()) == list(decoded_contents.values())

        header: Header = request.jwt.header
        assert owner_did + "#" + did_key_holder.key_id == header.kid
        assert algorithm.type.name == header.alg

        payload: Payload = request.jwt.payload
        assert owner_did == payload.iss
        assert ClaimRequestType.REQ_CREDENTIAL.value == payload.type[0]
        assert list(claims.keys()) == list(decoded_request.claims.keys())
        assert list(claims.values()) == list(decoded_request.claims.values())
        assert request_date == payload.iat

    def test_credential_request_v_2_0(self):
        # GIVEN data for ClaimRequest.
        algorithm = AlgorithmProvider.create(AlgorithmType.ES256K)
        key_provider = algorithm.generate_key_provider("test_credential_request_v2")
        owner_did = "did:icon:03:a0da55dc3fb992aa93aefb1132778d724765b22a7ecbc087"
        issuer_did = "did:icon:03:485e12f86bea2d16905e6ad4f657031c7a56280af3648b55"
        request_date = int(time.time())
        expired_date: int = request_date * 2
        version = CredentialVersion.v2_0
        did_key_holder: DidKeyHolder = DidKeyHolder(
            key_id=key_provider.key_id, type=key_provider.type, private_key=key_provider.private_key, did=owner_did
        )
        holder_key = ECDHKey.generate_key(EcdhCurveType.P256K.value.curve_name)
        request_claim: dict = {
            "name": "엠마스톤",
            "birthDate": "2001-01-23",
            "residentRegistrationNumber": "010123-11112222",
            "driverLicenseNumber": "991029817171111",
            "serialNumber": "0961SP",
        }
        context: list = [
            "https://vc-test.zzeung.id/credentials/v1.json",
            "https://vc-test.zzeung.id/credentials/il/driver_license/kor/v1.json",
        ]
        id_: str = "https://www.zzeung.id/vcr/driver_license/123623"
        type_: list = ["IlDriverLicenseKorCredential"]
        json_ld_vcr: JsonLdVcr = JsonLdVcr(context=context, id_=id_, type_=type_, request_claim=request_claim)
        nonce: str = EncodeType.HEX.value.encode(AlgorithmProvider.generate_random_nonce(32))
        request_credential_public_key: EphemeralPublicKey = EphemeralPublicKey(kid="holderKey-1", epk=holder_key)

        # WHEN try to create jwt token of `REQ_CREDENTIAL` message.
        request: ClaimRequest = ClaimRequest.from_(
            type_=ClaimRequestType.REQ_CREDENTIAL,
            algorithm=did_key_holder.type,
            public_key_id=did_key_holder.key_id,
            did=did_key_holder.did,
            vcr=json_ld_vcr,
            response_id=issuer_did,
            public_key=request_credential_public_key,
            request_date=request_date,
            expired_date=expired_date,
            nonce=nonce,
            version=version,
        )
        message: str = did_key_holder.sign(request.jwt)

        # THEN success to decode ClaimRequest object.
        decoded_claim_request: ClaimRequest = ClaimRequest(jwt=Jwt.decode(message))
        assert request.type == decoded_claim_request.type
        assert request.request_id == decoded_claim_request.request_id
        assert request.response_id == decoded_claim_request.response_id
        assert request.nonce == decoded_claim_request.nonce
        assert request.public_key.kid == decoded_claim_request.public_key.kid
        assert request.public_key.epk == decoded_claim_request.public_key.epk

        decoded_vcr: JsonLdVcr = decoded_claim_request.vcr
        assert json_ld_vcr.context == decoded_vcr.context
        assert json_ld_vcr.id == decoded_vcr.id
        assert json_ld_vcr.type == decoded_vcr.type

        for key in request_claim.keys():
            assert request_claim.get(key) == decoded_vcr.get_request_claim(key)

    def test_presentation_request(self):
        # GIVEN data for ClaimRequest.
        algorithm = AlgorithmProvider.create(AlgorithmType.ES256K)
        key_provider = algorithm.generate_key_provider("test_presentation_request")
        owner_did = "did:icon:03:485e12f86bea2d16905e6ad4f657031c7a56280af3648b55"
        verifier_did = "did:icon:03:485e12f86bea2d16905e6ad4f657031c7a56280af3648b55"
        request_date = int(time.time())
        expired_date: int = request_date * 2
        request_claim: dict = {
            "name": "엠마스톤",
            "birthDate": "2001-01-23",
            "residentRegistrationNumber": "010123-11112222",
            "driverLicenseNumber": "991029817171111",
            "serialNumber": "0961SP",
        }
        context: list = [
            "https://vc-test.zzeung.id/credentials/v1.json",
            "https://vc-test.zzeung.id/credentials/il/driver_license/kor/v1.json",
        ]
        id_: str = "https://www.zzeung.id/vcr/driver_license/123623"
        type_: list = ["IlDriverLicenseKorCredential"]
        json_ld_vcr: JsonLdVcr = JsonLdVcr(context=context, id_=id_, type_=type_, request_claim=request_claim)
        version = CredentialVersion.v2_0
        did_key_holder: DidKeyHolder = DidKeyHolder(
            key_id=key_provider.key_id, type=key_provider.type, private_key=key_provider.private_key, did=verifier_did
        )

        # WHEN try to create jwt token of `REQ_PRESENTATION` message.
        request: ClaimRequest = ClaimRequest.from_(
            type_=ClaimRequestType.REQ_PRESENTATION,
            algorithm=did_key_holder.type,
            public_key_id=did_key_holder.key_id,
            did=did_key_holder.did,
            vcr=json_ld_vcr,
            response_id=owner_did,
            request_date=request_date,
            expired_date=expired_date,
            version=version,
        )
        message: str = did_key_holder.sign(request.jwt)

        # THEN success to decode ClaimRequest object.
        decoded_request: ClaimRequest = ClaimRequest(Jwt.decode(message))
        source_claims: dict = request.jwt.payload.contents
        decoded_claims: dict = decoded_request.jwt.payload.contents
        assert list(source_claims.values()) == list(decoded_claims.values())
        assert list(source_claims.keys()) == list(decoded_claims.keys())

        decoded_header: Header = decoded_request.jwt.header
        assert f"{verifier_did}#{did_key_holder.key_id}" == decoded_header.kid
        assert algorithm.type.name == decoded_header.alg

        decoded_payload: Payload = decoded_request.jwt.payload
        assert verifier_did == decoded_payload.iss
        assert owner_did == decoded_payload.aud
        # assert ClaimRequestType.REQ_PRESENTATION.value == decoded_payload.type
        assert ClaimRequestType.REQ_PRESENTATION.value == decoded_payload.type[0]
        assert request_date == decoded_payload.iat

        verify_result: VerifyResult = decoded_request.verify(key_provider.public_key)
        assert verify_result.success

    def test_revocation_request(self):
        # GIVEN data for ClaimRequest
        algorithm = AlgorithmProvider.create(AlgorithmType.ES256K)
        holder_did = "did:icon:03:a0da55dc3fb992aa93aefb1132778d724765b22a7ecbc087"
        holder_key_id = "holder"
        issuer_did = "did:icon:03:485e12f86bea2d16905e6ad4f657031c7a56280af3648b55"
        key_provider = algorithm.generate_key_provider(holder_key_id)
        holder_did_key_holder = DidKeyHolder(
            did=holder_did, key_id=holder_key_id, type=key_provider.type, private_key=key_provider.private_key
        )

        # WHEN try to create jwt token of `REQ_REVOCATION` message.
        revocation_sig = "sigForRevocation"
        claim_request: ClaimRequest = ClaimRequest.for_revocation(
            algorithm=holder_did_key_holder.type,
            public_key_id=holder_did_key_holder.key_id,
            did=holder_did_key_holder.did,
            version=CredentialVersion.v2_0,
            response_id=issuer_did,
            signature=revocation_sig,
        )
        jwt_token: str = claim_request.jwt.sign(key_provider.private_key)

        # THEN success to decode jwt token of `REQ_REVOCATION` message.
        jwt: Jwt = Jwt.decode(jwt_token)
        assert issuer_did == jwt.payload.aud
        assert holder_did == jwt.payload.iss
        assert [ClaimRequestType.REQ_REVOCATION.value] == jwt.payload.type
        assert revocation_sig == jwt.payload.signature
        assert jwt.verify(key_provider.public_key).success
