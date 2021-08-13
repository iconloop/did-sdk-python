from dataclasses import dataclass
from typing import List, Optional

from didsdk.exceptions import JwtException
from didsdk.jwe.ecdhkey import ECDHKey
from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.protocol.json_ld.json_ld_vc import JsonLdVc
from didsdk.protocol.json_ld.json_ld_vcr import JsonLdVcr
from didsdk.protocol.json_ld.json_ld_vp import JsonLdVp
from didsdk.protocol.json_ld.json_ld_vpr import JsonLdVpr
from didsdk.protocol.response_result import ResponseResult


class HeaderAlgorithmType:
    JWE_ALGO_ECDH_ES = "ECDH-ES"
    JWE_ALGO_A128GCM = "A128GCM"


@dataclass(frozen=True)
class Header:
    alg: str
    kid: str

    # 1.1 jwe
    enc: str
    epk: ECDHKey

    def is_valid_encryption_method(self):
        return self.alg == HeaderAlgorithmType.JWE_ALGO_A128GCM

    def is_valid_jwe_algorithm(self):
        return self.alg == HeaderAlgorithmType.JWE_ALGO_ECDH_ES


class Payload:
    AUDIENCE = "aud"
    CLAIM = "claim"
    CREDENTIAL = "credential"
    EXPIRATION = "exp"
    ISSUER = "iss"
    ISSUED_AT = "iat"
    JTI = "jti"
    NONCE = "nonce"
    PUBLIC_KEY = "publicKey"
    SUBJECT = "sub"
    TYPE = "type"
    VC_ID = "vcId"
    VERSION = "version"
    # 2.0
    VC = "vc"
    VCR = "vcr"
    VP = "vp"
    VPR = "vpr"
    # revocation
    ERROR_CODE = "errorCode"
    ERROR_MESSAGE = "errorMessage"
    RESULT = "result"
    SIGNATURE = "sig"

    def __init__(self, contents: dict = None):
        self._contents: dict = contents if contents else dict()
        self._time_claim_keys: set = {self.EXPIRATION, self.ISSUED_AT}

    def __eq__(self, other) -> bool:
        return self._contents == other.contents

    @property
    def aud(self) -> str:
        return self._contents[self.AUDIENCE]

    @property
    def contents(self) -> dict:
        return self._contents

    @property
    def claim(self) -> dict:
        return self._contents[self.CLAIM]

    @property
    def credential(self) -> List[str]:
        return self._contents[self.CREDENTIAL]

    @property
    def error_code(self) -> str:
        return self._contents[self.ERROR_CODE]

    @property
    def error_message(self) -> str:
        return self._contents[self.ERROR_MESSAGE]

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

    # for v1.1
    @property
    def public_key(self) -> Optional[EphemeralPublicKey]:
        key = self._contents[self.PUBLIC_KEY]
        return EphemeralPublicKey(**key) if key else None

    @property
    def result(self) -> bool:
        return self._contents[self.RESULT]

    @property
    def signature(self) -> str:
        return self._contents[self.SIGNATURE]

    @property
    def sub(self) -> str:
        return self._contents[self.SUBJECT]

    @property
    def type(self) -> List[str]:
        return self._contents[self.TYPE]

    @property
    def version(self) -> str:
        return self._contents[self.VERSION]

    @property
    def vc_id(self) -> str:
        return self._contents[self.VC_ID]

    # for v2.0
    @property
    def vc(self) -> Optional[JsonLdVc]:
        vc = self._contents[self.VC]
        return JsonLdVc(vc) if vc else None

    @property
    def vcr(self) -> Optional[JsonLdVcr]:
        vcr = self._contents[self.VCR]
        return JsonLdVc(vcr) if vcr else None

    @property
    def vp(self) -> Optional[JsonLdVp]:
        vp = self._contents[self.VP]
        return JsonLdVp(vp) if vp else None

    @property
    def vpr(self) -> Optional[JsonLdVp]:
        vpr = self._contents[self.VPR]
        return JsonLdVpr.from_json(vpr) if vpr else None

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

    def asdict(self) -> dict:
        return self._contents

    def get(self, key: str):
        if key in self._contents and self.is_time_claim(key):
            return self._to_timestamp(self._contents[key])
        return self._contents.get(key)

    def get_response_result(self) -> ResponseResult:
        return ResponseResult(self.error_code, self.error_message, self.result)

    def is_time_claim(self, name: str):
        return name in self._time_claim_keys

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
