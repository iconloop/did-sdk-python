import abc
import base64
from enum import Enum


class Encoder(abc.ABC):
    @staticmethod
    def encode(data):
        raise NotImplementedError

    @staticmethod
    def decode(data):
        raise NotImplementedError


class HexEncoder(Encoder):
    @staticmethod
    def encode(data: bytes) -> str:
        return data.hex()

    @staticmethod
    def decode(data: str) -> bytes:
        return bytes.fromhex(data)


class Base64Encoder(Encoder):
    @staticmethod
    def encode(data: bytes, encoding: str = "UTF-8") -> str:
        return base64.b64encode(data).decode(encoding)

    @staticmethod
    def decode(data: str) -> bytes:
        return base64.b64decode(data)


class Base64URLEncoder(Encoder):
    @staticmethod
    def encode(data: bytes, encoding: str = "UTF-8") -> str:
        return base64.urlsafe_b64encode(data).decode(encoding).rstrip("=")

    @staticmethod
    def decode(data: str, encoding: str = "UTF-8") -> bytes:
        return base64.urlsafe_b64decode(Base64URLEncoder.add_padding(data).encode(encoding))

    @staticmethod
    def add_padding(data: str) -> str:
        padding = 4 - (len(data) % 4)
        data += "=" * padding
        return data


class EncodeType(Enum):
    HEX = HexEncoder()
    BASE64 = Base64Encoder()
    BASE64URL = Base64URLEncoder()
