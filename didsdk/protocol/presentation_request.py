from typing import Any, Dict, List

from coincurve import PublicKey

from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.jwt.jwt import Jwt, VerifyResult

DEFAULT_TYPE_POSITION = 0
REQ_CREDENTIAL = "REQ_CREDENTIAL"
REQ_PRESENTATION = "REQ_PRESENTATION"

REQUEST_CLAIM = "requestClaim"


class PresentationRequest:
    """Presentation request."""

    def __init__(self, jwt: Jwt):
        self.jwt: Jwt = jwt

    @property
    def algorithm(self) -> str:
        return self.jwt.header.alg

    @property
    def claims(self) -> Dict[str, Any]:
        return self.jwt.payload.get(REQUEST_CLAIM)

    @property
    def claim_types(self) -> List[str]:
        types = list(self.jwt.payload.type)
        del types[DEFAULT_TYPE_POSITION]
        return types

    @property
    def compact(self) -> str:
        return self.jwt.compact()

    @property
    def did(self) -> str:
        return self.jwt.header.kid.split("#")[0]

    @property
    def key_id(self) -> str:
        return self.jwt.header.kid

    @property
    def kid(self) -> str:
        return self.jwt.header.kid.split("#")[1]

    @property
    def nonce(self) -> str:
        return self.jwt.payload.nonce

    @property
    def public_key(self) -> EphemeralPublicKey:
        return self.jwt.payload.public_key

    @property
    def request_date(self) -> int:
        return self.jwt.payload.iat

    @property
    def request_id(self) -> str:
        return self.jwt.payload.iss

    @property
    def response_id(self) -> str:
        return self.jwt.payload.aud

    @property
    def signature(self) -> str:
        return self.jwt.payload.signature

    @property
    def type(self) -> List[str]:
        return self.jwt.payload.type

    @property
    def vc_id(self) -> str:
        return self.jwt.payload.vc_id

    @property
    def version(self) -> str:
        return self.jwt.payload.version

    def verify_result_time(self, valid_second: int) -> VerifyResult:
        return self.jwt.verify_iat(valid_second)

    def verify(self, public_key: PublicKey):
        return self.jwt.verify(public_key)
