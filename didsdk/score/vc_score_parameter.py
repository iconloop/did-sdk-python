import time
from datetime import datetime, timedelta

from coincurve import PrivateKey
from didsdk.jwt.jwt import Jwt, Payload
from didsdk.protocol.protocol_message import Credential

def _sign_credential(credential: Credential, private_key: PrivateKey, issued_timestamp: int=0, expiration_timestamp: int=0) -> str:
    if issued_timestamp and expiration_timestamp:
        credential_jwt = credential.as_jwt(issued_timestamp, expiration_timestamp)
        return credential_jwt.sign(private_key)
    issued: datetime = datetime.now()
    expiry_date: datetime = issued + timedelta(days=30)
    issued_timestamp, expiration_timestamp = int(issued.timestamp()), int(expiry_date.timestamp())
    credential_jwt: Jwt = credential.as_jwt(issued_timestamp, expiration_timestamp)
    return credential_jwt.sign(private_key)


def register_jwt(credential: Credential, private_key: PrivateKey, issued_timestamp: int=0, expiration_timestamp: int=0) -> str:
    signed_credential = _sign_credential(credential, private_key, issued_timestamp, expiration_timestamp)
    credential_jwt: Jwt = Jwt.decode(signed_credential)
    payload: Payload = credential_jwt.payload
    credential_payload: dict = payload.as_dict()
    payload = Payload(
        {
            "type": "REGIST",
            "issuerDid": credential_payload["iss"],
            "sig": credential_jwt.signature,
            "issueDate": credential_payload["iat"],
            "revokeDate": 0,
            "expiryDate": credential_payload["exp"],
        }
    )
    jwt: Jwt = Jwt(credential_jwt.header, payload)
    return jwt.sign(private_key)


def revoke_jwt(credential: str, did: str, private_key: PrivateKey) -> str:
    credential_jwt: Jwt = Jwt.decode(credential)
    payload = Payload(
        {
            "type": "REVOKE",
            "sig": credential_jwt.signature,
            "issuerDid": did,
            "revokeDate": int(time.time()),
        }
    )
    jwt: Jwt = Jwt(credential_jwt.header, payload)
    return jwt.sign(private_key)
