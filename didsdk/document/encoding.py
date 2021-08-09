from enum import Enum

import abc
import base64


class Encoder(abc.ABC):
    @classmethod
    def encode(cls, data):
        raise NotImplementedError

    @classmethod
    def decode(cls, data):
        raise NotImplementedError


class HexEncoder(Encoder):
    @classmethod
    def encode(cls, data: bytes) -> str:
        return data.hex()

    @classmethod
    def decode(cls, data: str) -> bytes:
        return bytes.fromhex(data)


class Base64Encoder(Encoder):
    @classmethod
    def encode(cls, data: bytes, encoding: str = 'UTF-8') -> str:
        return base64.b64encode(data).decode(encoding)

    @classmethod
    def decode(cls, data: str) -> bytes:
        return base64.b64decode(data)


class Base64URLEncoder(Encoder):
    @classmethod
    def encode(cls, data: bytes, encoding: str = 'UTF-8') -> str:
        return base64.urlsafe_b64encode(data).decode(encoding).rstrip("=")

    @classmethod
    def decode(cls, data: str, encoding: str = 'UTF-8') -> bytes:
        return base64.urlsafe_b64decode(cls.add_padding(data).encode(encoding))

    @classmethod
    def add_padding(cls, data: str) -> str:
        padding = 4 - (len(data) % 4)
        data += ("=" * padding)
        return data


class EncodeType(Enum):
    HEX = HexEncoder()
    BASE64 = Base64Encoder()
    BASE64URL = Base64URLEncoder()
