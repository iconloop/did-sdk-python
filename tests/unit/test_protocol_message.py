import time

import pytest

from didsdk.core.algorithm import Algorithm
from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.core.key_provider import KeyProvider
from didsdk.credential import CredentialVersion
from didsdk.document.encoding import EncodeType
from didsdk.jwe.ecdhkey import EcdhCurveType, ECDHKey
from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.protocol.claim_message_type import ClaimRequestType
from didsdk.protocol.claim_request import ClaimRequest
from didsdk.protocol.json_ld.json_ld_vcr import JsonLdVcr
from didsdk.protocol.protocol_message import ProtocolMessage, SignResult
from didsdk.protocol.protocol_type import ProtocolType


class TestProtocolMessage:
    @pytest.fixture
    def holder_key_id(self) -> str:
        return "holder"

    @pytest.fixture
    def algorithm(self) -> Algorithm:
        return AlgorithmProvider.create(AlgorithmType.ES256K)

    @pytest.fixture
    def holder_did(self) -> str:
        return "did:icon:03:a0da55dc3fb992aa93aefb1132778d724765b22a7ecbc087"

    @pytest.fixture
    def key_provider(self, algorithm: Algorithm, holder_key_id: str) -> KeyProvider:
        return algorithm.generate_key_provider(holder_key_id)

    @pytest.fixture
    def holder_did_key_holder_v_1_1(self, key_provider: KeyProvider, holder_did, holder_key_id) -> DidKeyHolder:
        # key_provider = algorithm.generate_key_provider(holder_key_id)
        return DidKeyHolder(
            did=holder_did, key_id=holder_key_id, type=key_provider.type, private_key=key_provider.private_key
        )

    @pytest.fixture
    def holder_did_key_holder_v_2_0(self, holder_did, holder_key_id, algorithm) -> DidKeyHolder:
        key_provider = algorithm.generate_key_provider(holder_key_id)
        owner_did = "did:icon:03:a0da55dc3fb992aa93aefb1132778d724765b22a7ecbc087"
        return DidKeyHolder(
            key_id=key_provider.key_id, type=key_provider.type, private_key=key_provider.private_key, did=owner_did
        )

    @pytest.fixture
    def revocation_sig(self) -> str:
        return "sigForRevocation"

    @pytest.fixture
    def revoke_claim_request_v_1_1(self, holder_did_key_holder_v_1_1, revocation_sig) -> ClaimRequest:
        issuer_did = "did:icon:03:485e12f86bea2d16905e6ad4f657031c7a56280af3648b55"
        return ClaimRequest.for_revocation(
            algorithm=holder_did_key_holder_v_1_1.type,
            public_key_id=holder_did_key_holder_v_1_1.key_id,
            did=holder_did_key_holder_v_1_1.did,
            version=CredentialVersion.v2_0,
            response_id=issuer_did,
            signature=revocation_sig,
        )

    @pytest.fixture
    def holder_ecdh_key(self) -> ECDHKey:
        return ECDHKey.generate_key(EcdhCurveType.P256K.value.curve_name, "holder_key")

    @pytest.fixture
    def request_credential_public_key(self, holder_ecdh_key) -> EphemeralPublicKey:
        # holder_ecdh_key = ECDHKey.generate_key(EcdhCurveType.P256K.value.curve_name)
        return EphemeralPublicKey(kid="holderKey-1", epk=holder_ecdh_key)

    @pytest.fixture
    def claim_request_v_2_0(self, holder_did_key_holder_v_2_0, request_credential_public_key) -> ClaimRequest:
        issuer_did = "did:icon:03:485e12f86bea2d16905e6ad4f657031c7a56280af3648b55"
        request_date = int(time.time())
        expired_date: int = request_date * 2
        version = CredentialVersion.v2_0
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

        return ClaimRequest.from_(
            type_=ClaimRequestType.REQ_CREDENTIAL,
            algorithm=holder_did_key_holder_v_2_0.type,
            public_key_id=holder_did_key_holder_v_2_0.key_id,
            did=holder_did_key_holder_v_2_0.did,
            vcr=json_ld_vcr,
            response_id=issuer_did,
            public_key=request_credential_public_key,
            request_date=request_date,
            expired_date=expired_date,
            nonce=nonce,
            version=version,
        )

    def test_create_for_revocation_request_v_1_1(
        self,
        key_provider: KeyProvider,
        holder_did: str,
        holder_did_key_holder_v_1_1: DidKeyHolder,
        revocation_sig: str,
        revoke_claim_request_v_1_1: ClaimRequest,
    ):
        # GIVEN a ClaimRequest object.
        holder_did_key_holder = holder_did_key_holder_v_1_1
        claim_request = revoke_claim_request_v_1_1

        # WHEN try to create a ProtocolMessage.
        protocol_message = ProtocolMessage(type_=ProtocolType.REQUEST_REVOCATION.value, claim_request=claim_request)
        sign_result: SignResult = protocol_message.sign_encrypt(holder_did_key_holder)
        assert sign_result.success

        # THEN success to decode the protocol message.
        protocol_message = ProtocolMessage.from_json(sign_result.result)
        decoded_claim_request: ClaimRequest = protocol_message.claim_request

        assert decoded_claim_request.jwt.verify(key_provider.public_key).success
        assert ClaimRequestType.REQ_REVOCATION.value in decoded_claim_request.type
        assert holder_did == decoded_claim_request.did
        assert revocation_sig == decoded_claim_request.signature

    def test_create_for_credential_v_2_0(
        self,
        holder_did_key_holder_v_2_0: DidKeyHolder,
        claim_request_v_2_0: ClaimRequest,
        holder_ecdh_key: ECDHKey,
        request_credential_public_key: EphemeralPublicKey,
    ):
        # GIVEN data for ClaimRequest.
        holder_did_key_holder = holder_did_key_holder_v_2_0
        claim_request = claim_request_v_2_0

        # WHEN try to create a ProtocolMessage.
        protocol_message = ProtocolMessage.for_request(
            protocol_type=ProtocolType.REQUEST_CREDENTIAL,
            claim_request=claim_request,
            request_public_key=request_credential_public_key,
        )
        sign_result: SignResult = protocol_message.sign_encrypt(holder_did_key_holder, holder_ecdh_key)
        assert sign_result.success

        # THEN success to decode the protocol message.
        _protocol_message: ProtocolMessage = ProtocolMessage.from_json(sign_result.result)
        _protocol_message.decrypt_jwe(holder_ecdh_key)
        decoded_claim_request: ClaimRequest = _protocol_message.claim_request

        assert decoded_claim_request.jwt.verify(holder_did_key_holder.private_key.public_key).success
        assert ClaimRequestType.REQ_CREDENTIAL.value in decoded_claim_request.type
        assert claim_request.nonce in decoded_claim_request.nonce
        assert claim_request.request_id in decoded_claim_request.request_id
        assert claim_request.response_id in decoded_claim_request.response_id
        assert claim_request.public_key.epk == decoded_claim_request.public_key.epk
        assert holder_did_key_holder.did == decoded_claim_request.did
        for key, claim in decoded_claim_request.vcr.node.items():
            assert claim == claim_request.vcr.node[key]
