import dataclasses

import base64
import json
import time
from coincurve import PublicKey, PrivateKey
from typing import List

from didsdk.core.algorithm_provider import AlgorithmProvider, AlgorithmType
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

    def _encode(self, encoding: str = 'UTF-8') -> str:
        header = self._encode_base64_url(json.dumps(dataclasses.asdict(self._header)).encode(encoding))
        payload = self._encode_base64_url(json.dumps(self._payload.asdict()).encode(encoding))
        return f'{header}.{payload}'

    def _encode_base64_url(self, data: bytes, encoding: str = 'UTF-8') -> str:
        return base64.urlsafe_b64encode(data).decode(encoding).rstrip("=")

    @staticmethod
    def add_padding(data: str) -> str:
        padding = 4 - (len(data) % 4)
        data += ("=" * padding)
        return data

    def compact(self, encoding: str = 'UTF-8') -> str:
        return self._encode(encoding) + '.'

    @staticmethod
    def decode(jwt: str, encoding: str = 'UTF-8') -> 'Jwt':
        try:
            encoded_tokens = jwt.split('.')
            if len(encoded_tokens) not in [2, 3]:
                raise ValueError('JWT strings must contain exactly 2 period characters.')
        except ValueError as e:
            raise JwtException(e)

        decoded_header: bytes = Jwt.decode_base64_url(encoded_tokens[0])
        decoded_payload: bytes = Jwt.decode_base64_url(encoded_tokens[1])
        return Jwt(header=Header(**json.loads(decoded_header.decode(encoding))),
                   payload=Payload(json.loads(decoded_payload.decode(encoding))),
                   encoded_token=encoded_tokens)

    @staticmethod
    def decode_base64_url(data: str) -> bytes:
        return base64.urlsafe_b64decode(Jwt.add_padding(data).encode('utf-8'))

    def get_signature(self) -> str:
        return self._encoded_token[2] if self._encoded_token and len(self._encoded_token) == 3 else None

    def sign(self, private_key: PrivateKey, encoding: str = 'UTF-8') -> str:
        content = self._encode(encoding)
        algorithm = AlgorithmProvider.create(AlgorithmType.from_name(self._header.alg))
        signature: bytes = algorithm.sign(private_key, content.encode(encoding))
        return f'{content}.{self._encode_base64_url(signature)}'

    def verify(self, public_key: PublicKey, encoding: str = 'UTF-8') -> VerifyResult:
        if not self._encoded_token or len(self._encoded_token) != 3:
            raise JwtException('A signature is required for verify.')

        content = '.'.join(self._encoded_token[0:2])
        signature = self.decode_base64_url(self._encoded_token[2])
        algorithm = AlgorithmProvider.create(AlgorithmType.from_name(self._header.alg))
        if algorithm.verify(public_key, content.encode(encoding), signature):
            return self.verify_expired()
        else:
            return VerifyResult(success=False, fail_message="JWT signature does not match.")

    def verify_expired(self) -> VerifyResult:
        now = int(time.time() * 1_000_000)
        exp = self._payload.exp
        if exp and exp - now <= 0:
            return VerifyResult(success=False, fail_message="The expiration date has expired.")

        return VerifyResult(success=True)
