from dataclasses import dataclass
from typing import List

from didsdk.exceptions import JwtException


@dataclass(frozen=True)
class Header:
    alg: str
    kid: str


class Payload:
    AUDIENCE = "aud"
    CLAIM = "claim"
    CREDENTIAL = "credential"
    EXPIRATION = "exp"
    ISSUER = "iss"
    ISSUED_AT = "iat"
    JTI = "jti"
    NONCE = "nonce"
    SUBJECT = "sub"
    TYPE = "type"
    VERSION = "version"

    def __init__(self, contents: dict = None):
        self._contents: dict = contents if contents else dict()
        self._time_claim_keys: set = {self.EXPIRATION, self.ISSUED_AT}

    def __eq__(self, other) -> bool:
        return self._contents == other.contents

    @property
    def contents(self) -> dict:
        return self._contents

    @property
    def aud(self) -> str:
        return self._contents[self.AUDIENCE]

    @property
    def claim(self) -> dict:
        return self._contents[self.CLAIM]

    @property
    def credential(self) -> List[str]:
        return self._contents[self.CREDENTIAL]

    @property
    def exp(self) -> int:
        return self._contents[self.EXPIRATION]

    @property
    def iat(self) -> int:
        return self._contents[self.ISSUED_AT]

    @property
    def iss(self) -> str:
        return self._contents[self.ISSUER]

    @property
    def jti(self) -> str:
        return self._contents[self.JTI]

    @property
    def nonce(self) -> str:
        return self._contents[self.NONCE]

    @property
    def sub(self) -> str:
        return self._contents[self.SUBJECT]

    @property
    def type(self) -> List[str]:
        return self._contents[self.TYPE]

    @property
    def version(self) -> str:
        return self._contents[self.VERSION]

    def _to_timestamp(self, value):
        if isinstance(value, int):
            return value

        if isinstance(value, str):
            return int(value)

        raise JwtException(f"'{type(value)}' can not be type of timestamp.")

    def add_time_claim_key(self, key: str):
        self._time_claim_keys.add(key)

    def add_time_claim_key_set(self, keys: set):
        self._time_claim_keys.add(keys)

    def is_time_claim(self, name: str):
        return name in self._time_claim_keys

    def to_json_format(self) -> dict:
        return self._contents

    def put(self, name: str, value):
        if value is None:
            if name in self._contents:
                del self._contents[name]
            return

        if self.is_time_claim(name):
            value = self._to_timestamp(value)

        self._contents[name] = value

    def put_all(self, data: dict):
        for name, value in data:
            self.put(name, value)
