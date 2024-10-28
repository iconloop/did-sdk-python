from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.credential import CredentialVersion
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.jwt import Jwt
from didsdk.protocol.claim_message_type import ClaimRequestType
from didsdk.protocol.claim_response import ClaimResponse
from didsdk.protocol.response_result import ResponseResult


class TestClaimResponse:
    def test_revocation_response(self):
        # GIVEN data for ClaimResponse
        holder_did = "did:icon:03:a0da55dc3fb992aa93aefb1132778d724765b22a7ecbc087"
        issuer_did = "did:icon:03:485e12f86bea2d16905e6ad4f657031c7a56280af3648b55"
        issuer_key_id = "issuer"
        algorithm = AlgorithmProvider.create(AlgorithmType.ES256K)
        key_provider = algorithm.generate_key_provider(issuer_key_id)
        issuer_did_key_holder = DidKeyHolder(
            did=issuer_did, key_id=issuer_key_id, type=key_provider.type, private_key=key_provider.private_key
        )

        response_result: ResponseResult = ResponseResult(
            result=False, error_code="100", error_message="Not found Error"
        )

        header: Header = Header(alg=issuer_did_key_holder.type.name, kid=issuer_did_key_holder.kid)
        contents = {
            Payload.TYPE: [ClaimRequestType.REQ_REVOCATION.value],
            Payload.ISSUER: issuer_did_key_holder.did,
            Payload.AUDIENCE: holder_did,
            Payload.RESULT: response_result.result,
            Payload.ERROR_CODE: response_result.error_code,
            Payload.ERROR_MESSAGE: response_result.error_message,
            Payload.VERSION: CredentialVersion.v2_0,
        }
        payload: Payload = Payload(contents)
        claim_response: ClaimResponse = ClaimResponse(Jwt(header, payload))
        jwt_token: str = claim_response.jwt.sign(key_provider.private_key)

        # THEN success to decode jwt token of `REQ_REVOCATION` message.
        jwt: Jwt = Jwt.decode(jwt_token)
        assert issuer_did == jwt.payload.iss
        assert holder_did == jwt.payload.aud
        assert [ClaimRequestType.REQ_REVOCATION.value] == jwt.payload.type
        assert response_result == jwt.payload.get_response_result()
        assert jwt.verify(key_provider.public_key).success
