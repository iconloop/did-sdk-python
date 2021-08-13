from typing import List

from coincurve import PublicKey

from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.jwt.jwt import Jwt, VerifyResult
from didsdk.protocol.response_result import ResponseResult

DID_AUTH = "DID_AUTH"
CREDENTIAL_RESULT = "CREDENTIAL_RESULT"
RES_REVOCATION = "RES_REVOCATION"


class ClaimResponse:
    """Credential response.
    """
    def __init__(self, jwt: Jwt):
        self.jwt: Jwt = jwt

    @property
    def algorithm(self) -> str:
        return self.jwt.header.alg

    @property
    def did(self) -> str:
        return self.jwt.header.kid.split('#')[0]

    @property
    def key_id(self) -> str:
        return self.jwt.header.kid

    @property
    def kid(self) -> str:
        return self.jwt.header.kid.split('#')[1]

    @property
    def message(self) -> str:
        return self.jwt.payload.get('message')

    @property
    def nonce(self) -> str:
        return self.jwt.payload.nonce

    @property
    def public_key(self) -> EphemeralPublicKey:
        return self.jwt.payload.public_key

    @property
    def request_id(self) -> str:
        return self.jwt.payload.iss

    @property
    def response_date(self) -> int:
        return self.jwt.payload.iat

    @property
    def response_id(self) -> str:
        return self.jwt.payload.aud

    @property
    def response_result(self) -> ResponseResult:
        return self.jwt.payload.get_response_result()

    @property
    def ret_code(self) -> int:
        return self.jwt.payload.get('retCode')

    @property
    def type(self) -> List[str]:
        return self.jwt.payload.type

    @property
    def version(self) -> str:
        return self.jwt.payload.version

    def verify_result_time(self, valid_micro_second: int) -> VerifyResult:
        return self.jwt.verify_iat(valid_micro_second)

    def verify(self, public_key: PublicKey) -> VerifyResult:
        return self.jwt.verify(public_key)
