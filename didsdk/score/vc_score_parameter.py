import time

from coincurve import PrivateKey

from didsdk.jwt.jwt import Jwt, Payload


def register_jwt(credential: str, private_key: PrivateKey) -> str:
    credential_jwt: Jwt = Jwt.decode(credential)
    payload: Payload = credential_jwt.payload
    credential_payload: dict = payload.as_dict()
    payload = Payload(
        {
            "issuerDid": credential_payload["iss"],
            "sig": credential_jwt.signature,
            "issueDate": credential_payload["iat"],
            "expiryDate": credential_payload["exp"],
        }
    )
    jwt: Jwt = Jwt(credential_jwt.header, payload)
    return jwt.sign(private_key)


def revoke_jwt(credential: str, did: str, private_key: PrivateKey) -> str:
    credential_jwt: Jwt = Jwt.decode(credential)
    payload = Payload(
        {
            "sig": credential_jwt.signature,
            "issuerDid": did,
            "revokeDate": int(time.time()),
        }
    )
    jwt: Jwt = Jwt(credential_jwt.header, payload)
    return jwt.sign(private_key)
