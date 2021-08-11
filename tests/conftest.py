import pytest
import time
from coincurve import PrivateKey

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.credential import Credential
from didsdk.did_service import DidService
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.issuer_did import IssuerDid
from didsdk.jwt.jwt import Jwt
from tests.utils.icon_service_factory import IconServiceFactory


@pytest.fixture
def private_key() -> PrivateKey:
    return PrivateKey()


@pytest.fixture
def dids() -> dict:
    return {
        "did": "did:icon:0000961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08",
        "target_did": "did:icon:1111961b6cd64253fb28c9b0d3d224be5f9b18d49f01da390f08"
    }


@pytest.fixture
def key_id() -> str:
    return 'key1'


@pytest.fixture
def claim() -> dict:
    return {
        "name": {
            "claimValue": "홍길순",
            "salt": "a1341c4b0cbff6bee9118da10d6e85a5"
        },
        "birthDate": {
            "claimValue": "2000-01-01",
            "salt": "65341c4b0cbff6bee9118da10d6e85a5"
        },
        "gender": {
            "claimValue": "female",
            "salt": "12341c4b0cbff6bee9118da10d6e85a5",
            "displayValue": "여성"
        },
        "telco": {
            "claimValue": "SKT",
            "salt": "91341c4b0cbff6bee9118da10d6e85a5"
        },
        "phoneNumber": {
            "claimValue": "01031142962",
            "salt": "e2341c4b0cbff6bee9118da10d6e85a5",
            "displayValue": "010-3114-2962"
        },
        "connectingInformation": {
            "claimValue": "0000000000000000000000000000000000000000",
            "salt": "ff341c4b0cbff6bee9118da10d6e85a5"
        },
        "citizenship": {
            "claimValue": True,
            "salt": "f2341c4b0cbff6bee9118da10d6e85a5",
            "displayValue": "내국인"
        }
    }


@pytest.fixture
def credentials(issuer_did, dids, private_key):
    claim_a = {
        'age': '18',
        'level': 'eighteen'
    }
    credential_a = Credential(issuer_did, target_did=dids['target_did'], claim=claim_a)
    claim_b = {
        'tall': '165'
    }
    credential_b = Credential(issuer_did, target_did=dids['target_did'], claim=claim_b)
    claim_c = {
        'character': 'niniz'
    }
    credential_c = Credential(issuer_did, target_did=dids['target_did'], claim=claim_c)
    issued = int(time.time() * 1_000_000)
    expiration = issued * 2
    return [credential_a.as_jwt(issued, expiration).sign(private_key),
            credential_b.as_jwt(issued, expiration).sign(private_key),
            credential_c.as_jwt(issued, expiration).sign(private_key)]


@pytest.fixture
def header(dids, key_id) -> Header:
    return Header(alg=AlgorithmType.ES256K.name, kid=f"{dids['did']}#{key_id}")


@pytest.fixture
def payload(dids, claim, credentials) -> Payload:
    contents = {
        Payload.ISSUER: dids['did'],
        Payload.ISSUED_AT: 1578445403,
        Payload.EXPIRATION: int(time.time() * 1_000_000) * 2,
        Payload.CREDENTIAL: credentials,
        Payload.SUBJECT: dids['target_did'],
        Payload.CLAIM: claim,
        Payload.NONCE: 'b0f184df3f4e92ea9496d9a0aad259ae',
        Payload.JTI: '885c592008a5b95a8e348e56b92a2361',
        Payload.TYPE: [Credential.DEFAULT_TYPE] + list(claim.keys()),
        Payload.VERSION: '2.0'
    }
    return Payload(contents)


@pytest.fixture
def jwt_object(header, payload) -> Jwt:
    return Jwt(header, payload)


@pytest.fixture
def encoded_jwt(jwt_object, private_key) -> str:
    return jwt_object.sign(private_key)


@pytest.fixture
def issuer_did(dids, key_id) -> IssuerDid:
    return IssuerDid(did=dids['did'], algorithm=AlgorithmType.ES256K.name, key_id=key_id)


@pytest.fixture
def did_service_local() -> DidService:
    return DidService(IconServiceFactory.create_local(),
                      network_id=2,
                      score_address='cx26484cf9cb42b6eebbf537fbfe6b7df3f86c5079')


@pytest.fixture
def did_service_testnet() -> DidService:
    return DidService(IconServiceFactory.create_testnet(),
                      network_id=3,
                      score_address='cxa18595c0b6b9c99f5ac5b6f12e136d9d2f221f4c')


@pytest.fixture
def test_wallet_keys() -> dict:
    return {
        'private': '4252c4abbdb595c08ff042f1af78b019c49792b881c9730cde832815570cf8d7',
        'public': '02bfc63dd13b7f9ed08f7804470b2a10d039583e2de21a92c8ff4bc0f0e29e4506'
    }
