import hashlib
import json
from typing import Dict, Any, Optional, List

from didsdk.core.property_name import PropertyName
from didsdk.document.encoding import Base64URLEncoder
from didsdk.protocol.base_claim import BaseClaim
from didsdk.protocol.hash_attribute import HashedAttribute
from didsdk.protocol.json_ld.base_json_ld import BaseJsonLd
from didsdk.protocol.json_ld.claim import Claim
from didsdk.protocol.json_ld.display_layout import DisplayLayout
from didsdk.protocol.json_ld.info_param import InfoParam
from didsdk.protocol.json_ld.json_ld_util import get_random_nonce


class JsonLdParam(BaseJsonLd):
    def __init__(self, param: Dict[str, Any] = None):
        super().__init__(param)

        self.credential_params: Optional[Dict[str, Any]] = None
        self.hash_values: Optional[Dict[str, str]] = None
        self.claims: Optional[Dict[str, Claim]] = None
        self.display_layout: Optional[DisplayLayout] = None
        self.info: Optional[Dict[str, InfoParam]] = None
        self._digest = HashedAttribute.DEFAULT_ALG

        if param:
            self.credential_params = self.get_term(PropertyName.JL_CREDENTIAL_PARAM)
            self.hash_values = {}
            self.claims = self._set_claims()
            self.display_layout = self.credential_params.get(PropertyName.JL_DISPLAY_LAYOUT)
            self.info = self.credential_params.get(PropertyName.JL_INFO)

            algorithm = self.credential_params.get(PropertyName.JL_HASH_ALGORITHM)
            if algorithm:
                self._digest = hashlib.new(algorithm)

    def _get_digest(self, value: bytes, nonce: bytes) -> bytes:
        self._digest.update(value)
        self._digest.update(nonce)

        return self._digest.digest()

    def _set_claims(self) -> Dict[str, Claim]:
        claims = self.credential_params.get(PropertyName.JL_CLAIM)
        if not claims:
            raise ValueError('Claim cannot be empty.')

        return {key: Claim(**claims.get(key)) for key in claims}

    def from_(self, claim: Optional[Dict[str, Claim]],
              context=None,
              display_layout: Optional[DisplayLayout] = None,
              hash_algorithm: str = None,
              info: Optional[Dict[str, InfoParam]] = None,
              proof_type: Optional[str] = None,
              type_=None, encoding='utf-8') -> 'JsonLdParam':
        if not claim:
            raise ValueError('Claim cannot be empty.')

        types: List[str] = type_ if type_ else type_[PropertyName.JL_AT_TYPE]
        if PropertyName.JL_TYPE_CREDENTIAL_PARAM not in types:
            types.insert(0, PropertyName.JL_TYPE_CREDENTIAL_PARAM)
        param: Dict[str, Any] = {
            PropertyName.JL_CONTEXT: context,
            PropertyName.JL_TYPE: types
        }

        hash_algorithm = hash_algorithm or HashedAttribute.DEFAULT_ALG
        self._digest = hashlib.new(hash_algorithm)
        self.hash_values = {}
        self.claims = {}
        for key, value in claim.items():
            nonce = get_random_nonce(32)
            claim: Claim = Claim(claim_value=value.claim_value, salt=nonce, display_value=value.display_value)
            digested = self._get_digest(claim.claim_value.encode(encoding), nonce.encode(encoding))
            self.hash_values[key] = Base64URLEncoder.encode(digested)
            self.claims[key] = claim

        self.info = info
        self.display_layout = display_layout
        self.credential_params = {
            PropertyName.JL_CLAIM: self.claims,
            PropertyName.JL_DISPLAY_LAYOUT: (self.display_layout.get_display() if self.display_layout.is_string
                                             else self.display_layout.get_object_display()),
            PropertyName.JL_HASH_ALGORITHM: hash_algorithm,
            PropertyName.JL_INFO: self.info,
            PropertyName.JL_PROOF_TYPE: proof_type or BaseClaim.HASH_TYPE
        }

        param[PropertyName.JL_CREDENTIAL_PARAM] = self.credential_params
        self.set_node(param)

        return self

    @classmethod
    def from_encoded_param(cls, encoded_param: str):
        params = json.loads(Base64URLEncoder.decode(encoded_param))
        return cls(params)

    def verify_param(self, params: Dict[str, str], encoding='utf-8') -> bool:
        for key, claim in self.claims.items():
            digest = self._get_digest(value=claim.claim_value.encode(encoding), nonce=claim.salt.encode(encoding))
            origin = Base64URLEncoder.decode(params.get(key))
            if digest != origin:
                return False
        return True
