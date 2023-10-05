import time

from coincurve import PrivateKey
from loguru import logger

from didsdk.core.algorithm import Algorithm
from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.credential import CredentialVersion
from didsdk.document.encoding import EncodeType
from didsdk.jwe.ecdhkey import EcdhCurveType, ECDHKey
from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.protocol.claim_request import ClaimRequest
from didsdk.protocol.json_ld.json_ld_vpr import JsonLdVpr
from didsdk.protocol.json_ld.vpr_condition import Operator, VprCondition
from didsdk.protocol.protocol_message import ProtocolMessage, SignResult
from didsdk.protocol.protocol_type import ProtocolType


class TestVprCondition:
    def test_create_vpr_using_condition(self):
        # GIVEN a VprCondition object
        condition: VprCondition = VprCondition.from_simple_condition(
            condition_id="uuid-requisite-0000-1111-2222",
            context="http://54.180.16.76/score/credentials/passport/kor/v1.json",
            issuer=["did:icon:3601:ad60496c344ca053e3f380de52a64d9ab238fcbbba6722c5"],
            credential_type="PassportKorCredential",
            property_=["nationality", "givenName", "familyName", "birthDate"],
        )

        # WHEN try to create a JsonLdVpr object using the condition
        vpr: JsonLdVpr = JsonLdVpr.from_(
            context=["http://54.180.16.76/score/credentials/v1.json"],
            id_="https://www.iconloop.com/vpr/passport/123623",
            url="https://saramin.com/v1/presentation-response",
            purpose="adult authentication",
            verifier="did:icon:01:SARAMINoooooicHVN8vwZtY9YmjY",
            condition=condition,
        )

        # THEN success to get node from the vpr object
        logger.debug(vpr.node)

    def test_compound_vpr(self):
        # GIVEN some data to create some compound VprCondition objects
        algorithm: Algorithm = AlgorithmProvider.create(AlgorithmType.ES256K)
        issuer_private_key: PrivateKey = algorithm.bytes_to_private_key(
            EncodeType.HEX.value.decode("3ffdd9a59ff8e79fff5be5052357f6528c20bbeab51b919c4af4ad56c9aa4544")
        )
        holder_did = "did:icon:3601:65abded7953c1875f74708707d20b09bea2bbc64abbc02cc"
        issuer_did = "did:icon:3601:d3144b611ac997a3242f2c2b782fff2364b74f6e32af0bc2"
        issuer_key_id = "BankIssuer"
        issuer_did_key_holder: DidKeyHolder = DidKeyHolder(
            did=issuer_did, key_id=issuer_key_id, type=AlgorithmType.ES256K, private_key=issuer_private_key
        )
        verifier_ecdh_key: ECDHKey = ECDHKey.generate_key(EcdhCurveType.P256K.value.curve_name)

        condition_1_1: VprCondition = VprCondition.from_simple_condition(
            condition_id="uuid-requisite-0000-1111-2222",
            context="http://54.180.16.76/score/credentials/mobile_authentication/kor/v1.json",
            issuer=["did:icon:01:iconloop......"],
            credential_type="MobileAuthenticationKorCredential",
            property_=["name", "birthDate", "telco"],
        )
        condition_1_2: VprCondition = VprCondition.from_simple_condition(
            condition_id="uuid-requisite-0000-1111-2222-3333",
            context="http://54.180.16.76/score/credentials/financial_id/v1.json",
            issuer=["did:icon:01:shinhan-bank...."],
            credential_type="FinancialIdCredential",
            property_=["residentRegistrationNumber", "idCardType"],
        )
        condition_2: VprCondition = VprCondition.from_simple_condition(
            condition_id="uuid-requisite-0000-1111-2222-3333-4444",
            context="http://54.180.16.76/score/credentials/passport/kor/v1.json",
            issuer=["did:icon:01:iconloop......"],
            credential_type="PassportKorCredential",
            property_=["nationality", "givenName", "familyName", "birthDate"],
        )

        # WHEN try to create some compound VprCondition objects
        compound_and_condition: VprCondition = VprCondition.from_compound_condition(
            operator=Operator.AND.value, condition_list=[condition_1_1, condition_1_2]
        )
        compound_or_condition: VprCondition = VprCondition.from_compound_condition(
            operator=Operator.OR.value, condition_list=[condition_2, compound_and_condition]
        )

        vpr: JsonLdVpr = JsonLdVpr.from_(
            context=["http://54.180.16.76/score/credentials/v1.json"],
            id_="eedeec15-c364-4e4c-b7a7-871413e412f9",
            url="https://saramin.com/v1/presentation-response",
            purpose="adult authentication",
            verifier="did:icon:01:SARAMINoooooicHVN8vwZtY9YmjY",
            condition=compound_or_condition,
        )

        nonce: str = EncodeType.HEX.value.encode(AlgorithmProvider.generate_random_nonce(32))
        presentation_request_public_key: EphemeralPublicKey = EphemeralPublicKey(
            kid="verifierKey-1", epk=verifier_ecdh_key
        )
        presentation_request: ClaimRequest = ClaimRequest.for_presentation(
            algorithm=issuer_did_key_holder.type,
            did=issuer_did_key_holder.did,
            public_key_id=issuer_did_key_holder.key_id,
            response_id=holder_did,
            request_date=int(time.time()),
            nonce=nonce,
            public_key=presentation_request_public_key,
            version=CredentialVersion.v2_0,
            vpr=vpr,
        )

        protocol_message: ProtocolMessage = ProtocolMessage.for_request(
            protocol_type=ProtocolType.REQUEST_PRESENTATION, claim_request=presentation_request
        )

        sign_result: SignResult = protocol_message.sign_encrypt(issuer_did_key_holder)

        # THEN success to get result as success
        assert sign_result.success
        logger.debug(f"{sign_result.result}")
