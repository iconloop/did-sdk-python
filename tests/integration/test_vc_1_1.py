import copy
import json
import time
from typing import List

from coincurve import PrivateKey
from iconsdk.wallet.wallet import KeyWallet

from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.credential import Credential, CredentialVersion
from didsdk.document.encoding import EncodeType
from didsdk.jwe.ecdhkey import EcdhCurveType, ECDHKey
from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.presentation import Presentation
from didsdk.protocol.base_claim import BaseClaim
from didsdk.protocol.base_vc import BaseVc
from didsdk.protocol.claim_message_type import ClaimRequestType
from didsdk.protocol.claim_request import ClaimRequest
from didsdk.protocol.hash_attribute import HashedAttribute
from didsdk.protocol.protocol_message import ProtocolMessage, SignResult
from didsdk.protocol.protocol_type import ProtocolType


class TestVC_1_1:
    def test_did_full_sdk(self):
        # GIVEN some data for test
        holder_ecdh_key: ECDHKey = ECDHKey.generate_key(EcdhCurveType.P256K.value.curve_name, "k1")
        issuer_ecdh_key: ECDHKey = ECDHKey.generate_key(EcdhCurveType.P256K.value.curve_name, "k2")
        verifier_ecdh_key: ECDHKey = ECDHKey.generate_key(EcdhCurveType.P256K.value.curve_name, "k3")

        holder_wallet: KeyWallet = KeyWallet.create()
        issuer_wallet: KeyWallet = KeyWallet.create()

        holder_private_key: PrivateKey = PrivateKey.from_hex(holder_wallet.get_private_key())
        issuer_private_key: PrivateKey = PrivateKey.from_hex(issuer_wallet.get_private_key())

        holder_did = "did:icon:3601:65abded7953c1875f74708707d20b09bea2bbc64abbc02cc"
        holder_key_id = "ICONIssuer"
        issuer_did = "did:icon:3601:d3144b611ac997a3242f2c2b782fff2364b74f6e32af0bc2"
        issuer_key_id = "TestIssuer"

        holder_did_key_holder: DidKeyHolder = DidKeyHolder(
            did=holder_did, key_id=holder_key_id, type=AlgorithmType.ES256K, private_key=holder_private_key
        )
        issuer_did_key_holder: DidKeyHolder = DidKeyHolder(
            did=issuer_did, key_id=issuer_key_id, type=AlgorithmType.ES256K, private_key=issuer_private_key
        )

        ######################
        # REQUEST_CREDENTIAL #
        ######################
        # GIVEN some data to create a credential request
        claims: dict = {"email": "aaa@iconloop.com", "phone": "010-1234-5678", "idn": 123}

        nonce: str = EncodeType.HEX.value.encode(AlgorithmProvider.generate_random_nonce(32))
        request_public_key: EphemeralPublicKey = EphemeralPublicKey(
            kid="holder_key_1", epk=holder_ecdh_key.export_public_key()
        )
        credential_request: ClaimRequest = ClaimRequest.from_(
            type_=ClaimRequestType.REQ_CREDENTIAL,
            algorithm=holder_did_key_holder.type,
            public_key_id=holder_did_key_holder.key_id,
            did=holder_did_key_holder.did,
            response_id=issuer_did,
            nonce=nonce,
            public_key=request_public_key,
            claims=copy.deepcopy(claims),
            version=CredentialVersion.v1_1,
        )

        protocol_message: ProtocolMessage = ProtocolMessage.for_request(
            protocol_type=ProtocolType.REQUEST_CREDENTIAL, claim_request=credential_request
        )
        # WHEN try to encrypt a ProtocolMessage by did-key-holder of holder
        sign_result: SignResult = protocol_message.sign_encrypt(holder_did_key_holder)
        # THEN success to get data as success
        assert sign_result.success

        # WHEN try to decrypt a ProtocolMessage
        decrypted_protocol_message: ProtocolMessage = ProtocolMessage.from_json(sign_result.result)
        decrypted_claims: dict = decrypted_protocol_message.claim_request.claims
        # THEN success to get same data with source
        for key, value in claims.items():
            assert decrypted_claims[key] == value

        #################################
        # RESPONSE_PROTECTED_CREDENTIAL #
        #################################
        # GIVEN some data to create a response of protected credential
        base_claim: BaseClaim = BaseClaim(
            attribute_type=BaseClaim.HASH_TYPE, algorithm=HashedAttribute.DEFAULT_ALG, values=credential_request.claims
        )

        credential: Credential = Credential(
            algorithm=issuer_did_key_holder.type.name,
            key_id=issuer_did_key_holder.key_id,
            did=issuer_did_key_holder.did,
            nonce=credential_request.nonce,
            target_did=holder_did,
            base_claim=base_claim,
            version=CredentialVersion.v1_1,
        )

        issued: int = int(time.time())
        duration: int = credential.duration * 1000
        expiration: int = issued + duration
        protocol_message = ProtocolMessage.for_credential(
            protocol_type=ProtocolType.RESPONSE_PROTECTED_CREDENTIAL,
            credential=credential,
            request_public_key=request_public_key,
            issued=issued,
            expiration=expiration,
        )

        # WHEN try to encrypt a ProtocolMessage by keys of issuer
        sign_result = protocol_message.sign_encrypt(issuer_did_key_holder, issuer_ecdh_key)
        # THEN success to get data as success
        assert sign_result.success

        # WHEN try to decrypt a ProtocolMessage by holder
        decrypted_credential_pm = ProtocolMessage.from_json(sign_result.result)
        decrypted_credential_pm.decrypt_jwe(holder_ecdh_key)
        decrypted_claims: dict = decrypted_credential_pm.base_param.value
        # THEN success to get same data with source
        for key, value in claims.items():
            assert decrypted_claims[key] == value

        ########################
        # REQUEST_PRESENTATION #
        ########################
        # GIVEN some data to create request presentation
        nonce = EncodeType.HEX.value.encode(AlgorithmProvider.generate_random_nonce(32))
        request_public_key = EphemeralPublicKey(kid="verifier_key_1", epk=verifier_ecdh_key.export_public_key())

        request_date: int = int(time.time())
        expiration: int = request_date + duration
        presentation_request: ClaimRequest = ClaimRequest.for_presentation(
            algorithm=issuer_did_key_holder.type,
            public_key_id=issuer_did_key_holder.key_id,
            did=issuer_did_key_holder.did,
            response_id=holder_did,
            nonce=nonce,
            public_key=request_public_key,
            request_date=issued,
            expired_date=expiration,
            version=CredentialVersion.v1_1,
        )

        protocol_message = ProtocolMessage.for_request(
            ProtocolType.REQUEST_PRESENTATION, claim_request=presentation_request
        )

        # WHEN try to encrypt a ProtocolMessage by keys of issuer
        sign_result = protocol_message.sign_encrypt(None)
        # THEN success to get data as success
        assert sign_result.success

        # WHEN try to decrypt a ProtocolMessage
        decrypted_protocol_message = ProtocolMessage.from_json(sign_result.result)
        decrypted_presentation_request: ClaimRequest = decrypted_protocol_message.claim_request
        # THEN success to verify
        assert decrypted_presentation_request.jwt.verify()
        assert decrypted_presentation_request.verify_result_time()

        ###################################
        # RESPONSE_PROTECTED_PRESENTATION #
        ###################################
        # GIVEN some data to create create presentation
        vc_types: List[str] = ["email", "phone"]
        base_vc: BaseVc = BaseVc(
            vc=decrypted_credential_pm.message, vc_type=vc_types, param=decrypted_credential_pm.base_param
        )

        presentation: Presentation = Presentation.from_(
            algorithm=holder_did_key_holder.type,
            key_id=holder_did_key_holder.key_id,
            did=holder_did_key_holder.did,
            nonce=nonce,
            version=CredentialVersion.v1_1,
        )
        presentation.add_credential(json.dumps(base_vc.as_dict()))

        protocol_message = ProtocolMessage.for_presentation(
            ProtocolType.RESPONSE_PROTECTED_PRESENTATION,
            presentation=presentation,
            request_public_key=request_public_key,
        )

        # WHEN try to encrypt a ProtocolMessage by keys of holder
        sign_result = protocol_message.sign_encrypt(holder_did_key_holder, holder_ecdh_key)
        # THEN success to get data as success
        assert sign_result.success

        # WHEN try to decrypt a ProtocolMessage by holder
        decrypted_protocol_message: ProtocolMessage = ProtocolMessage.from_json(sign_result.result)
        decrypted_protocol_message.decrypt_jwe(verifier_ecdh_key)
        decrypted_presentation: Presentation = decrypted_protocol_message.presentation

        # THEN success to get same data with source
        decrypted_base_vc: BaseVc = decrypted_presentation.base_vcs[0]
        assert decrypted_base_vc.is_valid()
