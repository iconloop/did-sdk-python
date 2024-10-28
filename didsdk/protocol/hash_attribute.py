import hashlib
import json
from enum import Enum
from typing import Dict, List, Optional

from didsdk.core.algorithm_provider import AlgorithmProvider
from didsdk.document.encoding import Base64URLEncoder, EncodeType
from didsdk.protocol.base_param import BaseParam
from didsdk.protocol.claim_attribute import ClaimAttribute
from didsdk.protocol.json_ld import json_ld_util
from didsdk.protocol.json_ld.claim import Claim


class HashAlgorithmType(Enum):
    sha256 = "SHA-256"


class HashedAttribute(ClaimAttribute):
    _ATTR_VALUE = "value"
    _ATTR_HASH = "alg"
    ATTR_TYPE = "hash"
    DEFAULT_ALG = HashAlgorithmType.sha256.name

    def __init__(self, alg: str, values: Dict[str, str], is_decrypted=False):
        self.alg: str = alg
        self.base_param: Optional[BaseParam] = None
        self.hashed_values: Dict[str, str] = values
        self._digest = hashlib.new(self.DEFAULT_ALG)

        if not is_decrypted:
            self.hashed_values = {}
            # set hashed_values and base_param
            self._hash_values(values)

    def _encode_value(self, value, encoding: str = "utf-8") -> bytes:
        if isinstance(value, Claim):
            return json.dumps(value.as_dict()).encode(encoding)
        else:
            return json_ld_util.as_bytes(value)

    def _get_digest(self, value: bytes, nonce: bytes):
        if self._digest is None:
            self._digest = hashlib.new(self.alg)

        self._digest.update(value)
        self._digest.update(nonce)

        return self._digest.digest()

    def _hash_values(self, values, encoding: str = "utf-8"):
        plain_values = {}
        nonces = {}
        for key, value in values.items():
            nonce = EncodeType.HEX.value.encode(AlgorithmProvider.generate_random_nonce(32))
            encoded_nonce = nonce.encode(encoding)
            digested = self._get_digest(self._encode_value(value, encoding), encoded_nonce)
            self.hashed_values[key] = Base64URLEncoder.encode(digested)
            plain_values[key] = value
            nonces[key] = nonce

        self.base_param = BaseParam(value=plain_values, nonce=nonces)

    @classmethod
    def from_json(cls, json_data: Dict, is_decrypted=False) -> "HashedAttribute":
        return HashedAttribute(
            alg=json_data.get(cls._ATTR_HASH), values=json_data.get(cls._ATTR_VALUE), is_decrypted=is_decrypted
        )

    def get_type(self) -> str:
        return self.ATTR_TYPE

    def get_claim_types(self) -> List[str]:
        return list(self.hashed_values.keys())

    def verify(self, base_param: BaseParam, encoding="utf-8") -> bool:
        for key, value in base_param.value.items():
            nonce = base_param.nonce.get(key).encode(encoding)
            digested = self._get_digest(self._encode_value(value, encoding), nonce)
            origin = Base64URLEncoder.decode(self.hashed_values.get(key))
            if origin != digested:
                return False

        return True
