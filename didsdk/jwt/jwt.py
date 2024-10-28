import json
import time
from typing import List

from coincurve import PrivateKey, PublicKey

from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
from didsdk.document.encoding import Base64URLEncoder
from didsdk.exceptions import JwtException
from didsdk.jwt.elements import Header, Payload


class VerifyResult:
    def __init__(self, success: bool, fail_message: str = None):
        self._success = success
        self._fail_message = fail_message

    def __eq__(self, other):
        return self._success == other.success and self._fail_message == other.fail_message

    @property
    def success(self):
        return self._success

    @property
    def fail_message(self):
        return self._fail_message


class Jwt:
    def __init__(self, header: Header, payload: Payload, encoded_token: List[str] = None):
        self._header: Header = header
        self._payload: Payload = payload
        self._encoded_token: List[str] = encoded_token

    @property
    def encoded_token(self) -> List[str]:
        return self._encoded_token

    @property
    def header(self) -> Header:
        return self._header

    @property
    def payload(self) -> Payload:
        return self._payload

    @property
    def signature(self) -> str:
        return self._encoded_token[2] if self._encoded_token and len(self._encoded_token) == 3 else None

    def _encode(self, encoding: str = "UTF-8") -> str:
        header = Base64URLEncoder.encode((json.dumps(self._header.as_dict()).encode(encoding)))
        payload = Base64URLEncoder.encode(json.dumps(self._payload.as_dict()).encode(encoding))
        return f"{header}.{payload}"

    def compact(self, encoding: str = "UTF-8") -> str:
        return self._encode(encoding) + "."

    @staticmethod
    def decode(jwt: str, encoding: str = "UTF-8") -> "Jwt":
        try:
            encoded_tokens = jwt.split(".")
            if len(encoded_tokens) not in [2, 3]:
                raise ValueError("JWT strings must contain exactly 2 period characters.")
        except ValueError as e:
            raise JwtException(e)

        decoded_header: bytes = Base64URLEncoder.decode(encoded_tokens[0])
        decoded_payload: bytes = Base64URLEncoder.decode(encoded_tokens[1])
        return Jwt(
            header=Header(**json.loads(decoded_header.decode(encoding))),
            payload=Payload(json.loads(decoded_payload.decode(encoding))),
            encoded_token=encoded_tokens,
        )

    def sign(self, private_key: PrivateKey, encoding: str = "UTF-8") -> str:
        content = self._encode(encoding)
        algorithm = AlgorithmProvider.create(AlgorithmType[self._header.alg])
        signature: bytes = algorithm.sign(private_key, content.encode(encoding))
        self._encoded_token = f"{content}.{Base64URLEncoder.encode(signature)}"
        return self._encoded_token

    def verify(self, public_key: PublicKey = None, encoding: str = "UTF-8") -> VerifyResult:
        if not public_key:
            return self.verify_expired()

        if not self._encoded_token or len(self._encoded_token) != 3:
            raise JwtException("A signature is required for verify.")

        content = ".".join(self._encoded_token[0:2])
        signature = Base64URLEncoder.decode(self._encoded_token[2])
        algorithm = AlgorithmProvider.create(AlgorithmType[self._header.alg])
        if algorithm.verify(public_key, content.encode(encoding), signature):
            return self.verify_expired()
        else:
            return VerifyResult(success=False, fail_message="JWT signature does not match.")

    def verify_iat(self, valid_second: int = None) -> VerifyResult:
        # default 10 seconds.
        if not valid_second:
            valid_second = 10

        now = int(time.time())
        iat = self.payload.iat

        if not iat:
            return VerifyResult(success=False, fail_message="'iat' is None.")
        else:
            if (now + valid_second) - iat < 0:
                return VerifyResult(success=False, fail_message="Invalid 'iat'.")
            elif now - iat > valid_second:
                return VerifyResult(success=False, fail_message=f"Invalid 'iat'. It's over ({valid_second} seconds).")

        return VerifyResult(success=True)

    def verify_expired(self) -> VerifyResult:
        now = int(time.time())
        exp = self._payload.exp

        # TODO: Temporary fix to avoid checking empty exp validation for `Zzeung` mobile app.
        # if not exp:
        #     for type_ in self._payload.type:
        #         if type_ in [ClaimRequestType.REQ_REVOCATION.value, ClaimRequestType.DID_AUTH.value]:
        #             return VerifyResult(success=True)
        #     return VerifyResult(success=False, fail_message="exp is None.")
        # elif exp - now <= 0:
        #     return VerifyResult(success=False, fail_message="The expiration date has expired.")

        if exp and exp - now <= 0:
            return VerifyResult(success=False, fail_message="The expiration date has expired.")

        return VerifyResult(success=True)
