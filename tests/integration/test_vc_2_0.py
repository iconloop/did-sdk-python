import time
from typing import Dict, List

from coincurve import PrivateKey

from didsdk.core.algorithm import Algorithm
from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.credential import Credential, CredentialVersion
from didsdk.document.encoding import EncodeType
from didsdk.jwe.ecdhkey import EcdhCurveType, ECDHKey
from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.presentation import Presentation
from didsdk.protocol.claim_message_type import ClaimRequestType, ClaimResponseType
from didsdk.protocol.claim_request import ClaimRequest
from didsdk.protocol.claim_response import ClaimResponse
from didsdk.protocol.json_ld.claim import Claim
from didsdk.protocol.json_ld.display_layout import DisplayLayout
from didsdk.protocol.json_ld.info_param import InfoParam
from didsdk.protocol.json_ld.json_ld_param import JsonLdParam
from didsdk.protocol.json_ld.json_ld_vcr import JsonLdVcr
from didsdk.protocol.json_ld.json_ld_vp import JsonLdVp
from didsdk.protocol.json_ld.json_ld_vpr import JsonLdVpr
from didsdk.protocol.json_ld.revocation_service import RevocationService
from didsdk.protocol.json_ld.vp_criteria import VpCriteria
from didsdk.protocol.json_ld.vpr_condition import VprCondition
from didsdk.protocol.protocol_message import ProtocolMessage, SignResult
from didsdk.protocol.protocol_type import ProtocolType


class TestVC_2_0:
    def test_did_full_sdk(self):
        """Icon did sdk full test

        Flow
        1. Holder ---(RequestCredential)--->>> Issuer
        2. Holder <<<---(Credential)--- Issuer
        3. Holder <<<---(RequestPresentation)--- Verifier
        4. Holder ---(Presentation)--->>> Verifier
        :return:
        """
        # GIVEN keys and data of participants
        holder_ecdh_key: ECDHKey = ECDHKey.generate_key(EcdhCurveType.P256K.value.curve_name, "k1")
        issuer_ecdh_key: ECDHKey = ECDHKey.generate_key(EcdhCurveType.P256K.value.curve_name, "k2")
        verifier_ecdh_key: ECDHKey = ECDHKey.generate_key(EcdhCurveType.P256K.value.curve_name, "k3")

        algorithm: Algorithm = AlgorithmProvider.create(AlgorithmType.ES256K)
        holder_private_key: PrivateKey = algorithm.bytes_to_private_key(
            EncodeType.HEX.value.decode("8523a4145e347f6eb88e094c7eb8b860915c3b7a121cf1016d841fb20c6cb76e")
        )
        issuer_private_key: PrivateKey = algorithm.bytes_to_private_key(
            EncodeType.HEX.value.decode("3ffdd9a59ff8e79fff5be5052357f6528c20bbeab51b919c4af4ad56c9aa4544")
        )
        verifier_private_key: PrivateKey = algorithm.bytes_to_private_key(
            EncodeType.HEX.value.decode("5759800b84abb50eb8c5ecb63e42f887fda706fc51021ba7257e38e1771f52ba")
        )

        holder_did = "did:icon:3601:65abded7953c1875f74708707d20b09bea2bbc64abbc02cc"
        holder_key_id = "ICONIssuer"
        issuer_did = "did:icon:3601:d3144b611ac997a3242f2c2b782fff2364b74f6e32af0bc2"
        issuer_key_id = "BankIssuer"
        verifier_did = "did:icon:3601:ad60496c344ca053e3f380de52a64d9ab238fcbbba6722c5"
        verifier_key_id = "YanoljaVerifier"

        holder_did_key_holder: DidKeyHolder = DidKeyHolder(
            did=holder_did,
            key_id=holder_key_id,
            type=AlgorithmType.ES256K,
            private_key=holder_private_key,
        )
        issuer_did_key_holder: DidKeyHolder = DidKeyHolder(
            did=issuer_did,
            key_id=issuer_key_id,
            type=AlgorithmType.ES256K,
            private_key=issuer_private_key,
        )
        verifier_did_key_holder: DidKeyHolder = DidKeyHolder(
            did=verifier_did,
            key_id=verifier_key_id,
            type=AlgorithmType.ES256K,
            private_key=verifier_private_key,
        )

        did_init_nonce: str = EncodeType.HEX.value.encode(AlgorithmProvider.generate_random_nonce(32))
        did_init_public_key: EphemeralPublicKey = EphemeralPublicKey(
            kid="issuerKey-1", epk=issuer_ecdh_key.export_public_key()
        )

        ############
        # DID_INIT #
        ############
        # GIVEN a ClaimRequest for DID_INIT
        did_init_request: ClaimRequest = ClaimRequest.for_did(
            type_=ClaimRequestType.DID_INIT,
            algorithm=issuer_did_key_holder.type,
            public_key_id=issuer_did_key_holder.key_id,
            response_id="did:icon:1111961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08",
            did=issuer_did_key_holder.did,
            public_key=did_init_public_key,
            nonce=did_init_nonce,
            version=CredentialVersion.v2_0,
        )

        # GIVEN a ProtocolMessage for DID_INIT
        did_init_pm: ProtocolMessage = ProtocolMessage.for_request(
            ProtocolType.DID_INIT, claim_request=did_init_request
        )

        # WHEN try to sign to DID_INIT request message
        did_init_sign_result: SignResult = did_init_pm.sign_encrypt(issuer_did_key_holder)

        # THEN success to get success result.
        assert did_init_sign_result.success
        # logger.debug(f'DID_INIT SIGN RESULT: {json.dumps(did_init_sign_result.result, indent=4)}')

        # WHEN try to verify the ProtocolMessage for DID_INIT by holder
        decrypted_did_init_pm: ProtocolMessage = ProtocolMessage.from_json(did_init_sign_result.result)
        decrypted_did_init_request: ClaimRequest = decrypted_did_init_pm.claim_request

        # THEN success to get claims of request.
        # logger.debug(f'decrypted contents for DID_INIT claim request: '
        #              f'{json.dumps(decrypted_did_init_request.jwt.payload.contents, indent=4)}')

        ############
        # DID_AUTH #
        ############
        # GIVEN a DID_AUTH ClaimResponse
        did_auth_public_key: EphemeralPublicKey = EphemeralPublicKey(
            kid="holderKey-1", epk=holder_ecdh_key.export_public_key()
        )
        did_auth_response: ClaimResponse = ClaimResponse.from_(
            type_=ClaimResponseType.DID_AUTH,
            algorithm=holder_did_key_holder.type,
            public_key_id=holder_did_key_holder.key_id,
            did=holder_did_key_holder.did,
            response_id=decrypted_did_init_request.did,
            public_key=did_auth_public_key,
            nonce=decrypted_did_init_request.nonce,
            version=CredentialVersion.v2_0,
        )

        did_auth_pm: ProtocolMessage = ProtocolMessage.for_response(
            protocol_type=ProtocolType.DID_AUTH,
            request_public_key=decrypted_did_init_request.public_key,
            claim_response=did_auth_response,
        )

        # WHEN try to sign to DID_AUTH request message
        did_auth_sign_result: SignResult = did_auth_pm.sign_encrypt(
            did_key_holder=holder_did_key_holder, ecdh_key=holder_ecdh_key
        )

        # THEN success to get success result.
        assert did_auth_sign_result.success
        # logger.debug(f'DID_AUTH SIGN RESULT: {json.dumps(did_auth_sign_result.result, indent=4)}')

        # WHEN try to verify the ProtocolMessage for DID_AUTH by issuer
        decrypted_did_auth_pm: ProtocolMessage = ProtocolMessage.from_json(did_auth_sign_result.result)
        decrypted_did_auth_pm.decrypt_jwe(issuer_ecdh_key)
        # decrypted_did_auth_response: ClaimResponse = decrypted_did_auth_pm.claim_response

        # THEN success to get claims of request.
        # logger.debug(f'decrypted contents for DID_AUTH claim request: '
        #              f'{json.dumps(decrypted_did_auth_response.jwt.payload.contents, indent=4)}')

        ##################
        # REQ_CREDENTIAL #
        ##################
        # GIVEN a ClaimRequest
        nonce = EncodeType.HEX.value.encode(AlgorithmProvider.generate_random_nonce(32))
        request_date = int(time.time())
        credential_request_public_key: EphemeralPublicKey = EphemeralPublicKey(
            kid="holderKey-1", epk=holder_ecdh_key.export_public_key()
        )
        request_claim: dict = {
            "name": {"claimValue": "홍길순", "salt": "a1341c4b0cbff6bee9118da10d6e85a5"},
            "birthDate": {
                "claimValue": "2000-01-01",
                "salt": "65341c4b0cbff6bee9118da10d6e85a5",
            },
            "gender": {
                "claimValue": "female",
                "salt": "12341c4b0cbff6bee9118da10d6e85a5",
                "displayValue": "여성",
            },
            "telco": {"claimValue": "SKT", "salt": "91341c4b0cbff6bee9118da10d6e85a5"},
            "phoneNumber": {
                "claimValue": "01031142962",
                "salt": "e2341c4b0cbff6bee9118da10d6e85a5",
                "displayValue": "010-3114-2962",
            },
            "connectingInformation": {
                "claimValue": "0000000000000000000000000000000000000000",
                "salt": "ff341c4b0cbff6bee9118da10d6e85a5",
            },
            "citizenship": {
                "claimValue": True,
                "salt": "f2341c4b0cbff6bee9118da10d6e85a5",
                "displayValue": "내국인",
            },
            "bank": "신한은행",
            "accountNumber": "3333012392919393",
        }
        context: list = [
            "http://54.180.16.76/score/credentials/v1.json",
            "http://54.180.16.76/score/credentials/financial_id/v1.json",
        ]
        id_: str = "https://www.iconloop.com/credential/financialId/12360"
        vc_type: list = ["FinancialIdCredential"]
        json_ld_vcr: JsonLdVcr = JsonLdVcr(context=context, id_=id_, type_=vc_type, request_claim=request_claim)
        credential_request: ClaimRequest = ClaimRequest.from_(
            type_=ClaimRequestType.REQ_CREDENTIAL,
            algorithm=holder_did_key_holder.type,
            public_key_id=holder_did_key_holder.key_id,
            did=holder_did_key_holder.did,
            response_id=issuer_did,
            public_key=credential_request_public_key,
            vcr=json_ld_vcr,
            request_date=request_date,
            expired_date=request_date * 2,
            nonce=nonce,
            version=CredentialVersion.v2_0,
        )

        credential_request_pm: ProtocolMessage = ProtocolMessage.for_request(
            protocol_type=ProtocolType.REQUEST_CREDENTIAL,
            claim_request=credential_request,
            request_public_key=decrypted_did_init_request.public_key,
        )

        # WHEN try to sign to REQ_CREDENTIAL request message
        credential_request_sign_result: SignResult = credential_request_pm.sign_encrypt(
            did_key_holder=holder_did_key_holder, ecdh_key=holder_ecdh_key
        )

        # THEN success to get success result.
        assert credential_request_sign_result.success
        # logger.debug(f'REQ_CREDENTIAL SIGN RESULT: {json.dumps(credential_request_sign_result.result, indent=4)}')

        # WHEN try to verify the ProtocolMessage for REQ_CREDENTIAL by issuer
        decrypted_credential_request_pm: ProtocolMessage = ProtocolMessage.from_json(
            credential_request_sign_result.result
        )
        decrypted_credential_request_pm.decrypt_jwe(issuer_ecdh_key)
        decrypted_credential_request: ClaimRequest = decrypted_credential_request_pm.claim_request

        # THEN success to get claims of request.
        # logger.debug(f'decrypted contents for REQ_CREDENTIAL claim request: '
        #              f'{json.dumps(decrypted_credential_request.jwt.payload.contents, indent=4)}')

        ###################################
        # REQ_CREDENTIAL & RES_CREDENTIAL #
        ###################################
        # GIVEN credential parameters
        vc_claim: dict = {
            "name": Claim("홍길순"),
            "birthDate": Claim("2000-01-01", salt="65341c4b0cbff6bee9118da10d6e85a5"),
            "gender": Claim("female", salt="12341c4b0cbff6bee9118da10d6e85a5", display_value="여성"),
            "telco": Claim("SKT", salt="91341c4b0cbff6bee9118da10d6e85a5"),
            "phoneNumber": Claim(
                "01031142962",
                salt="e2341c4b0cbff6bee9118da10d6e85a5",
                display_value="010-3114-2962",
            ),
            "connectingInformation": Claim(
                "0000000000000000000000000000000000000000",
                salt="ff341c4b0cbff6bee9118da10d6e85a5",
            ),
            "citizenship": Claim(True, salt="f2341c4b0cbff6bee9118da10d6e85a5", display_value="내국인"),
            "bank": Claim("신한은행"),
            "accountNumber": Claim("3333012392919393"),
        }

        description_info_param: InfoParam = InfoParam.for_text_view(
            name="동의내역", content="아래 내용에 대해 위임동의를 했습니다.\n * 헐액형\n * 나이\n * 몸무게"
        )
        consent_url_info_param: InfoParam = InfoParam.for_web_view(name="위임 이력 페이지", url="https://example.com/")
        consent_image_info_param: InfoParam = InfoParam.for_image_view(name="", data_uri="data:image:png:f0zkel.....")
        info_param: Dict[str, InfoParam] = {
            "description": description_info_param,
            "consentUrl": consent_url_info_param,
            "consentImage": consent_image_info_param,
        }

        id_card_layout_list: Dict[str, List[str]] = {"idCardGroup": ["name", "birthDate", "phoneNumber"]}
        account_layout_list: Dict[str, List[str]] = {"accountGroup": ["bank", "accountNumber"]}
        display_layout: DisplayLayout = DisplayLayout([id_card_layout_list, account_layout_list])

        credential_param: JsonLdParam = JsonLdParam.from_(
            display_layout=display_layout,
            info=info_param,
            context=context,
            type_=[vc_type],
            claim=vc_claim,
            proof_type="hash",
            hash_algorithm="SHA-256",
        )

        revocation_service = RevocationService(
            id_="https://www.ubplus.com/kangwondo/revoke/consent/vc",
            type_="SimpleRevocationService",
            short_description="revocationShortDescription",
        )
        # GIVEN a Credential
        credential = Credential(
            algorithm=issuer_did_key_holder.type.name,
            key_id=issuer_did_key_holder.key_id,
            did=issuer_did_key_holder.did,
            target_did=decrypted_credential_request.did,
            param=credential_param,
            nonce=decrypted_credential_request.nonce,
            id_="https://www.iconloop.com/credential/financialId/12360",
            refresh_id="testId",
            refresh_type="testType",
            revocation_service=revocation_service,
            version=CredentialVersion.v2_0,
        )

        issued: int = int(time.time())
        expiration: int = issued + (credential.EXP_DURATION * 1000)
        credential_response_pm: ProtocolMessage = ProtocolMessage.for_credential(
            protocol_type=ProtocolType.RESPONSE_CREDENTIAL,
            credential=credential,
            request_public_key=decrypted_credential_request.public_key,
            issued=issued,
            expiration=expiration,
        )

        # WHEN try to sign to RESPONSE_CREDENTIAL request message
        credential_response_sign_result: SignResult = credential_response_pm.sign_encrypt(
            did_key_holder=issuer_did_key_holder, ecdh_key=issuer_ecdh_key
        )

        # THEN success to get success result.
        assert credential_response_sign_result.success
        # logger.debug(f'RESPONSE_CREDENTIAL SIGN RESULT: '
        #              f'{json.dumps(credential_response_sign_result.result, indent=4)}')

        # WHEN try to verify the ProtocolMessage for RESPONSE_CREDENTIAL response by holder
        decrypted_credential_pm: ProtocolMessage = ProtocolMessage.from_json(credential_response_sign_result.result)
        decrypted_credential_pm.decrypt_jwe(holder_ecdh_key)
        # decrypted_credential: Credential = decrypted_credential_pm.credential

        # THEN success to get contents of response.
        # logger.debug(f'Hashed Claim: '
        #              f'{json.dumps(decrypted_credential.jwt.payload.as_dict(), indent=4)}')
        # logger.debug(f'Plain Claim: '
        #              f'{decrypted_credential_pm.ld_param.claims}')
        # logger.debug(f'Display layout: '
        #              f'{json.dumps(decrypted_credential_pm.ld_param.display_layout, indent=4)}')

        ####################
        # REQ_PRESENTATION #
        ####################
        # GIVEN REQUEST_PRESENTATION parameeters
        nonce = EncodeType.HEX.value.encode(AlgorithmProvider.generate_random_nonce(32))
        presentation_request_public_key: EphemeralPublicKey = EphemeralPublicKey(
            kid="verifierKey-1", epk=verifier_ecdh_key.export_public_key()
        )
        require_property: List[str] = ["name", "residentRegistrationNumberFirst7"]
        condition: VprCondition = VprCondition.from_simple_condition(
            context="http://54.180.16.76/score/credentials/financial_id/v1.json",
            condition_id="uuid-requisite-0000-1111-2222",
            issuer=[issuer_did],
            credential_type="FinancialIdCredential",
            property_=require_property,
        )

        vpr: JsonLdVpr = JsonLdVpr.from_(
            context=["http://54.180.16.76/score/credentials/v1.json"],
            id_="test",
            url='"https://saramin.com/v1/presentation-response"',
            purpose="adult authentication",
            verifier=verifier_did,
            condition=condition,
        )

        request_date = int(time.time())
        expired_date = request_date * 2
        presentation_request: ClaimRequest = ClaimRequest.for_presentation(
            algorithm=verifier_did_key_holder.type,
            public_key_id=verifier_did_key_holder.key_id,
            did=verifier_did_key_holder.did,
            response_id=holder_did,
            public_key=presentation_request_public_key,
            vpr=vpr,
            nonce=nonce,
            version=CredentialVersion.v2_0,
            request_date=request_date,
            expired_date=expired_date,
        )

        presentation_request_pm: ProtocolMessage = ProtocolMessage.for_request(
            protocol_type=ProtocolType.REQUEST_PRESENTATION,
            claim_request=presentation_request,
        )

        # WHEN try to sign to REQUEST_PRESENTATION request message
        presentation_request_sign_result: SignResult = presentation_request_pm.sign_encrypt(
            did_key_holder=verifier_did_key_holder
        )

        # THEN success to get success result.
        assert presentation_request_sign_result.success
        # logger.debug(f'REQUEST_PRESENTATION SIGN RESULT: '
        #              f'{json.dumps(presentation_request_sign_result.result, indent=4)}')

        # WHEN try to verify the ProtocolMessage for REQUEST_PRESENTATION by holder
        decrypted_presentation_request_pm: ProtocolMessage = ProtocolMessage.from_json(
            presentation_request_sign_result.result
        )
        decrypted_presentation_request: ClaimRequest = decrypted_presentation_request_pm.claim_request

        # THEN success to get claims of request.
        # logger.debug(f'decrypted contents for REQ_CREDENTIAL claim request: '
        #              f'{decrypted_presentation_request.jwt.payload.contents}')

        ###################################
        # RESPONSE_PROTECTED_PRESENTATION #
        ###################################
        # GIVEN parameters for RES_PRESENTATION
        criteria: VpCriteria = VpCriteria(
            condition_id="uuid-requisite-0000-1111-2222",
            vc=decrypted_credential_pm.message,
            param=decrypted_credential_pm.ld_param,
        )

        vp: JsonLdVp = JsonLdVp.from_(
            context="http://54.180.16.76/score/credentials/v1.json",
            id_="https://www.iconloop.com/vp/qnfdkqkd/123623",
            type_=["PresentationResponse"],
            presenter=holder_did,
            criteria=criteria,
        )

        presentation: Presentation = Presentation.from_(
            algorithm=holder_did_key_holder.type,
            key_id=holder_did_key_holder.key_id,
            did=holder_did_key_holder.did,
            nonce=decrypted_presentation_request.nonce,
            version=CredentialVersion.v2_0,
            vp=vp,
        )

        request_date: int = int(time.time())
        presentation_pm: ProtocolMessage = ProtocolMessage.for_presentation(
            ProtocolType.RESPONSE_PROTECTED_PRESENTATION,
            presentation=presentation,
            request_public_key=decrypted_presentation_request.public_key,
            issued=request_date,
            expiration=request_date + (Credential.EXP_DURATION * 1000),
        )

        # WHEN try to sign to RESPONSE_PROTECTED_PRESENTATION request message
        presentation_request_sign_result: SignResult = presentation_pm.sign_encrypt(
            did_key_holder=holder_did_key_holder, ecdh_key=holder_ecdh_key
        )

        # THEN success to get success result.
        assert presentation_request_sign_result.success
        # logger.debug(f'RESPONSE_PROTECTED_PRESENTATION SIGN RESULT: '
        #              f'{json.dumps(presentation_request_sign_result.result, indent=4)}')

        # WHEN try to verify the ProtocolMessage for RESPONSE_PROTECTED_PRESENTATION by verifier
        decrypted_presentation_request_pm: ProtocolMessage = ProtocolMessage.from_json(
            presentation_request_sign_result.result
        )
        decrypted_presentation_request_pm.decrypt_jwe(verifier_ecdh_key)
        # decrypted_presentation_request: Presentation = decrypted_presentation_request_pm.presentation

        # THEN success to get claims of request.
        # logger.debug(f'decrypted contents for REQ_CREDENTIAL claim request: '
        #              f'{decrypted_presentation_request.jwt.payload.contents}')
