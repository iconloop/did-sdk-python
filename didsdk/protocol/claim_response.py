import dataclasses
import time
from typing import List

from coincurve import PublicKey

from didsdk.core.algorithm_provider import AlgorithmType
from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.jwt.elements import Header, Payload
from didsdk.jwt.jwt import Jwt, VerifyResult
from didsdk.protocol.claim_message_type import ClaimResponseType
from didsdk.protocol.response_result import ResponseResult


class ClaimResponse:
    """Credential response."""

    def __init__(self, jwt: Jwt):
        self.jwt: Jwt = jwt

    @property
    def algorithm(self) -> str:
        return self.jwt.header.alg

    @property
    def did(self) -> str:
        return self.jwt.header.kid.split("#")[0]

    @property
    def key_id(self) -> str:
        return self.jwt.header.kid.split("#")[1]

    @property
    def kid(self) -> str:
        return self.jwt.header.kid

    @property
    def message(self) -> str:
        return self.jwt.payload.get("message")

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
        return self.jwt.payload.get("retCode")

    @property
    def type(self) -> List[str]:
        return self.jwt.payload.type

    @property
    def version(self) -> str:
        return self.jwt.payload.version

    def verify_result_time(self, valid_second: int) -> VerifyResult:
        return self.jwt.verify_iat(valid_second)

    def verify(self, public_key: PublicKey) -> VerifyResult:
        return self.jwt.verify(public_key)

    @classmethod
    def from_(
        cls,
        type_: ClaimResponseType,
        response_id: str,
        did: str,
        algorithm: AlgorithmType,
        public_key_id: str,
        version: str = None,
        kid: str = None,
        public_key: EphemeralPublicKey = None,
        jti: str = None,
        nonce: str = None,
        response_date: int = None,
        encoded_token: List[str] = None,
        result_code: int = None,
        message: str = None,
        response_result: ResponseResult = None,
    ):
        if not version:
            raise ValueError("version cannot be None.")
        if not response_id:
            raise ValueError("responseId cannot be None.")

        if algorithm != AlgorithmType.NONE:
            if not did:
                raise ValueError("did cannot be None.")
            if not algorithm:
                raise ValueError("algorithm cannot be None.")
            if not public_key_id:
                raise ValueError("publicKeyId cannot be None.")
            if not kid:
                kid = did + "#" + public_key_id
        else:
            raise ValueError("None algorithm is not supported.")

        if not response_date:
            response_date = int(time.time())

        header: Header = Header(alg=algorithm.name, kid=kid)
        contents = {
            Payload.ISSUER: did,
            Payload.AUDIENCE: response_id,
            Payload.ISSUED_AT: response_date,
            Payload.TYPE: [type_.value],
        }
        if public_key:
            contents.update({Payload.PUBLIC_KEY: public_key.as_dict()})
        if nonce:
            contents.update({Payload.NONCE: nonce})
        if jti:
            contents.update({Payload.JTI: jti})
        if version:
            contents.update({Payload.VERSION: version})
        if result_code:
            contents.update({Payload.ERROR_CODE: result_code})
        if message:
            contents.update({Payload.ERROR_MESSAGE: message})
        if response_result:
            contents[Payload.RESULT] = dataclasses.asdict(response_result)

        payload = Payload(contents=contents)
        return cls(Jwt(header=header, payload=payload, encoded_token=encoded_token))

    @classmethod
    def from_jwt(cls, jwt):
        header: Header = jwt.header
        payload: Payload = jwt.payload

        if not payload.version:
            raise ValueError("version cannot be None.")
        if not payload.type:
            raise ValueError("claimTypes cannot be None.")

        algorithm: AlgorithmType = AlgorithmType[header.alg]
        kid = header.kid
        if not algorithm:
            raise ValueError("algorithm cannot be None.")
        if algorithm != AlgorithmType.NONE and not kid:
            raise ValueError("kid cannot be None.")

        return cls(jwt)
