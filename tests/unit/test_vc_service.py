import pytest
from coincurve import PrivateKey
from iconsdk.wallet.wallet import KeyWallet

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.core.key_provider import KeyProvider
from didsdk.core.property_name import PropertyName
from didsdk.credential import Credential, CredentialVersion
from didsdk.did_service import DidService
from didsdk.document.document import Document
from didsdk.document.encoding import EncodeType
from didsdk.protocol.json_ld.claim import Claim
from didsdk.protocol.json_ld.json_ld_param import JsonLdParam
from didsdk.protocol.json_ld.json_ld_vc import JsonLdVc
from didsdk.score.did_score_parameter import DidScoreParameter
from didsdk.vc_service import VCService


class TestVCService:
    KEY_ID = "python-sdk-key"
    CREDENTIAL_ROOT_URI = "http://parametaw.com/credentials/"
    SERVICE = "sdk-test"

    @pytest.mark.vcr
    @pytest.fixture
    async def holder_did(self, did_service_testnet: DidService, test_wallet, holder_private_key_hex):
        algorithm_type = AlgorithmType.ES256K
        did_private_key = PrivateKey(bytes.fromhex(holder_private_key_hex))
        key_provider = KeyProvider(self.KEY_ID, algorithm_type, did_private_key.public_key, did_private_key)

        params = DidScoreParameter.create(key_provider, EncodeType.BASE64)
        document: Document = await did_service_testnet.create(test_wallet, params)
        return document.id

    @pytest.mark.vcr
    @pytest.fixture
    async def issuer_did(self, did_service_testnet: DidService, test_wallet, issuer_private_key_hex):
        algorithm_type = AlgorithmType.ES256K
        did_private_key = PrivateKey(bytes.fromhex(issuer_private_key_hex))
        key_provider = KeyProvider(self.KEY_ID, algorithm_type, did_private_key.public_key, did_private_key)

        params = DidScoreParameter.create(key_provider, EncodeType.BASE64)
        document: Document = await did_service_testnet.create(test_wallet, params)
        return document.id

    def credential(self, holder_did, issuer_did, credential_type: str, nonce: str) -> Credential:
        id_: str = f"{self.CREDENTIAL_ROOT_URI}{self.SERVICE}/vc/{credential_type}/{holder_did}"
        claims = {"userName": Claim("Alice")}
        ld_params: JsonLdParam = JsonLdParam.from_(
            claims,
            context=[f"{self.CREDENTIAL_ROOT_URI}v1.json", f"{self.CREDENTIAL_ROOT_URI}{self.SERVICE}/v1.json"],
            type_=[credential_type],
        )
        vc: JsonLdVc = JsonLdVc.from_(ld_params, id_=id_, credential_subject_id=holder_did)
        return Credential(
            algorithm=PropertyName.ALGO_KEY_ECDSAK,
            key_id=self.KEY_ID,
            did=issuer_did,
            nonce=nonce,
            vc=vc,
            version=CredentialVersion.v2_0,
            target_did=holder_did,
            param=ld_params,
            id_=id_,
        )

    def credentials(self, holder_did, issuer_did) -> list:
        nonce_1 = "0" * 31 + "1"
        nonce_2 = "0" * 31 + "2"
        type_nonce_data = (("SdkCredential1", nonce_1), ("SdkCredential2", nonce_2))
        return [
            self.credential(holder_did, issuer_did, type_nonce_pair[0], type_nonce_pair[1])
            for type_nonce_pair in type_nonce_data
        ]

    @pytest.mark.vcr
    async def test_register_and_revoke(
        self,
        vc_service_testnet: VCService,
        test_wallet: KeyWallet,
        issuer_did: str,
        holder_did: str,
        issuer_private_key_hex: str,
    ):
        issuer_private_key: PrivateKey = PrivateKey(bytes.fromhex(issuer_private_key_hex))
        credential = self.credential(holder_did, issuer_did, "SdkCredential", "0" * 31 + "1")
        credential_jwt = credential.as_jwt(1, 2)
        signed_credential = credential_jwt.sign(issuer_private_key)

        # register credential
        tx_result = await vc_service_testnet.register(test_wallet, signed_credential, issuer_private_key)
        assert tx_result["status"] == 1

        # revoke credential
        tx_result = await vc_service_testnet.revoke(test_wallet, signed_credential, issuer_did, issuer_private_key)
        assert tx_result["status"] == 1

    @pytest.mark.vcr
    async def test_register_list(
        self,
        vc_service_testnet: VCService,
        test_wallet: KeyWallet,
        issuer_did: str,
        holder_did: str,
        issuer_private_key_hex: str,
    ):
        issuer_private_key: PrivateKey = PrivateKey(bytes.fromhex(issuer_private_key_hex))
        credentials = self.credentials(holder_did, issuer_did)
        credential_jwts = [credential.as_jwt(1, 2) for credential in credentials]
        signed_credentials = [credential_jwt.sign(issuer_private_key) for credential_jwt in credential_jwts]

        # register credential
        tx_result = await vc_service_testnet.register_list(test_wallet, signed_credentials, issuer_private_key)
        assert tx_result["status"] == 1
