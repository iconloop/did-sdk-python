import time
from typing import List

import pytest
from coincurve import PrivateKey
from iconsdk.wallet.wallet import KeyWallet

from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
from didsdk.credential import Credential, CredentialVersion
from didsdk.did_service import DidService
from didsdk.document.encoding import EncodeType
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.issuer_did import IssuerDid
from didsdk.jwt.jwt import Jwt
from didsdk.protocol.base_claim import BaseClaim
from didsdk.protocol.hash_attribute import HashAlgorithmType, HashedAttribute
from didsdk.protocol.json_ld.claim import Claim
from didsdk.protocol.json_ld.display_layout import DisplayLayout
from didsdk.protocol.json_ld.info_param import InfoParam
from didsdk.protocol.json_ld.json_ld_param import JsonLdParam
from didsdk.protocol.json_ld.revocation_service import RevocationService
from didsdk.vc_service import VCService
from tests.utils.icon_service_factory import IconServiceFactory


@pytest.fixture
def private_key() -> PrivateKey:
    return PrivateKey()


@pytest.fixture
def dids() -> dict:
    return {
        "did": "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08",
        "target_did": "did:icon:1111961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08",
    }


@pytest.fixture
def key_id() -> str:
    return "key1"


@pytest.fixture
def claim() -> dict:
    return {
        "name": {"claimValue": "홍길순", "salt": "a1341c4b0cbff6bee9118da10d6e85a5"},
        "birthDate": {"claimValue": "2000-01-01", "salt": "65341c4b0cbff6bee9118da10d6e85a5"},
        "gender": {"claimValue": "female", "salt": "12341c4b0cbff6bee9118da10d6e85a5", "displayValue": "여성"},
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
        "citizenship": {"claimValue": True, "salt": "f2341c4b0cbff6bee9118da10d6e85a5", "displayValue": "내국인"},
    }


@pytest.fixture
def vc_claim() -> dict:
    return {
        "name": Claim("홍길순"),
        "birthDate": Claim("2000-01-01", salt="65341c4b0cbff6bee9118da10d6e85a5"),
        "gender": Claim("female", salt="12341c4b0cbff6bee9118da10d6e85a5", display_value="여성"),
        "telco": Claim("SKT", salt="91341c4b0cbff6bee9118da10d6e85a5"),
        "phoneNumber": Claim("01031142962", salt="e2341c4b0cbff6bee9118da10d6e85a5", display_value="010-3114-2962"),
        "connectingInformation": Claim(
            "0000000000000000000000000000000000000000", salt="ff341c4b0cbff6bee9118da10d6e85a5"
        ),
        "citizenship": Claim(True, salt="f2341c4b0cbff6bee9118da10d6e85a5", display_value="내국인"),
        "bank": Claim("신한은행"),
        "accountNumber": Claim("3333012392919393"),
    }


@pytest.fixture
def vc_claim_for_v1(claim) -> dict:
    return {
        BaseClaim.ATTRIBUTE_TYPE: BaseClaim.HASH_TYPE,
        BaseClaim.ATTRIBUTE: {"alg": HashedAttribute.DEFAULT_ALG, "value": claim},
    }


def create_json_ld_param(vc_claim: dict) -> JsonLdParam:
    description_info_param = InfoParam(name="동의내역", content="아래 내용에 대해 위임 동의 합니다. 어쩌고 저쩌고 ~")
    consent_url_info_param = InfoParam(name="위임 이력 페이지", url="https://example.com/")
    consent_image_info_param = InfoParam(name="동의서", data_uri="data:image:png:f0zkel....")
    expected_info_param = {
        "description": description_info_param,
        "consentUrl": consent_url_info_param,
        "consentImage": consent_image_info_param,
    }
    info_layout = DisplayLayout(expected_info_param)
    id_card_layout = DisplayLayout({"idCardGroup": ["name", "birthDate", "phoneNumber"]})
    account_layout = DisplayLayout({"accountGroup": ["bank", "accountNumber"]})
    expected_display_layout = DisplayLayout([id_card_layout, account_layout, info_layout])
    expected_context: list = [
        "http://zzeung.id/score/credentials/v1.json",
        "http://zzeung.id/score/credentials/financial_id/v1.json",
    ]
    vc_type = "PdsTestCredential"
    return JsonLdParam.from_(
        vc_claim,
        display_layout=expected_display_layout,
        info=expected_info_param,
        context=expected_context,
        type_=[vc_type],
        proof_type=HashedAttribute.ATTR_TYPE,
        hash_algorithm=HashAlgorithmType.sha256.value,
    )


def create_credential(
    issuer_did: IssuerDid, target_did: str, param: JsonLdParam, nonce: str, revocation_service: RevocationService
) -> Credential:
    return Credential(
        algorithm=issuer_did.algorithm,
        key_id=issuer_did.key_id,
        did=issuer_did.did,
        target_did=target_did,
        param=param,
        nonce=nonce,
        id_="https://www.iconloop.com/credential/financialId/12360",
        refresh_id="refreshId",
        refresh_type="refreshType",
        revocation_service=revocation_service,
        version=CredentialVersion.v2_0,
    )


@pytest.fixture
def credentials(issuer_did: IssuerDid, dids: dict, vc_claim: dict) -> List[Credential]:
    claim_a = {"age": "18", "level": "eighteen"}
    nonce = EncodeType.HEX.value.encode(AlgorithmProvider.generate_random_nonce(32))
    revocation_service = RevocationService(
        id_="http://example.com", type_="SimpleRevocationService", short_description="revocationShortDescription"
    )
    vc_claim["broofContents"] = Claim(claim_a)
    param: JsonLdParam = create_json_ld_param(vc_claim)
    credential_a = create_credential(issuer_did, dids["target_did"], param, nonce, revocation_service)

    claim_b = {"tall": "165"}
    vc_claim["broofContents"] = Claim(claim_b)
    param: JsonLdParam = create_json_ld_param(vc_claim)
    credential_b = create_credential(issuer_did, dids["target_did"], param, nonce, revocation_service)

    claim_c = {"character": "niniz"}
    vc_claim["broofContents"] = Claim(claim_c)
    param: JsonLdParam = create_json_ld_param(vc_claim)
    credential_c = create_credential(issuer_did, dids["target_did"], param, nonce, revocation_service)

    return [credential_a, credential_b, credential_c]


@pytest.fixture
def credentials_as_jwt(credentials: List[Credential]) -> List[Jwt]:
    issued = int(time.time())
    expiration = issued * 2

    return [credential.as_jwt(issued, expiration) for credential in credentials]


@pytest.fixture
def encrypted_credentials(credentials_as_jwt: List[Jwt], private_key: PrivateKey) -> List[str]:
    return [credential.sign(private_key) for credential in credentials_as_jwt]


@pytest.fixture
def header(dids: dict, key_id: str) -> Header:
    return Header(alg=AlgorithmType.ES256K.name, kid=f"{dids['did']}#{key_id}")


@pytest.fixture
def payload(dids: dict, claim: dict, encrypted_credentials: List[str], private_key: PrivateKey) -> Payload:
    contents = {
        Payload.ISSUER: dids["did"],
        Payload.ISSUED_AT: 1578445403,
        Payload.EXPIRATION: int(time.time()) * 2,
        Payload.CREDENTIAL: encrypted_credentials,
        Payload.SUBJECT: dids["target_did"],
        Payload.CLAIM: claim,
        Payload.NONCE: "b0f184df3f4e92ea9496d9a0aad259ae",
        Payload.JTI: "885c592008a5b95a8e348e56b92a2361",
        Payload.TYPE: [Credential.DEFAULT_TYPE] + list(claim.keys()),
        Payload.VERSION: CredentialVersion.v1_0,
    }
    return Payload(contents)


@pytest.fixture
def jwt_object(header: Header, payload: Payload) -> Jwt:
    return Jwt(header, payload)


@pytest.fixture
def encoded_jwt(jwt_object: Jwt, private_key: PrivateKey) -> str:
    return jwt_object.sign(private_key)


@pytest.fixture
def issuer_did(dids: dict, key_id: str) -> IssuerDid:
    return IssuerDid(did=dids["did"], algorithm=AlgorithmType.ES256K.name, key_id=key_id)


@pytest.fixture
def did_service_local() -> DidService:
    return DidService(
        IconServiceFactory.create_local(), network_id=2, score_address="cx26484cf9cb42b6eebbf537fbfe6b7df3f86c5079"
    )


@pytest.fixture
def did_service_testnet() -> DidService:
    return DidService(
        IconServiceFactory.create_testnet(), network_id=2, score_address="cxdd0cb8465b15e2971272c1ecf05691198552f770"
    )


@pytest.fixture
def vc_service_testnet() -> VCService:
    return VCService(
        IconServiceFactory.create_testnet(), network_id=2, score_address="cxeb26d9ecbfcf5fea0c2dcaf2f843d5ae93cbe84d"
    )


@pytest.fixture
def test_wallet_keys() -> dict:
    return {
        "private": "4252c4abbdb595c08ff042f1af78b019c49792b881c9730cde832815570cf8d7",
        "public": "02bfc63dd13b7f9ed08f7804470b2a10d039583e2de21a92c8ff4bc0f0e29e4506",
    }


@pytest.fixture
def test_wallet(test_wallet_keys) -> KeyWallet:
    return KeyWallet.load(bytes.fromhex(test_wallet_keys["private"]))


@pytest.fixture
def issuer_private_key_hex() -> str:
    return "774ab7549c0200c12cdb295ab26949c52e74dac6c6bdd110f921b1852c221634"


@pytest.fixture
def holder_private_key_hex() -> str:
    return "bceaac9756da7a2fa3b46446f36ba7037e5a37da5f9302572dd4938e170b82e1"


@pytest.fixture
def vcr_config():
    return {
        "record_mode": "once",
    }


@pytest.fixture(scope="session", autouse=True)
def anyio_backend():
    return "asyncio"
