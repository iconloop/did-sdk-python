import abc
import base64
from enum import Enum


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


class EncodeType(Enum):
    HEX = HexEncoder()
    BASE64 = Base64Encoder()
