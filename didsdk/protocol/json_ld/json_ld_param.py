import hashlib
import json
from typing import Any, Dict, List, Optional

from loguru import logger

from didsdk.core.property_name import PropertyName
from didsdk.document.encoding import Base64URLEncoder
from didsdk.protocol.base_claim import BaseClaim
from didsdk.protocol.hash_attribute import HashAlgorithmType, HashedAttribute
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
        self._algorithm_name = HashedAttribute.DEFAULT_ALG

        if param:
            self.credential_params = self.get_term(PropertyName.JL_CREDENTIAL_PARAM)
            self.hash_values = {}
            self.claims = self._set_claims()
            self.display_layout = self.credential_params.get(PropertyName.JL_DISPLAY_LAYOUT)
            self.info = self.credential_params.get(PropertyName.JL_INFO)

            hash_algorithm = self.credential_params.get(PropertyName.JL_HASH_ALGORITHM)
            if hash_algorithm:
                self._algorithm_name = HashAlgorithmType(hash_algorithm).name

    def _get_digest(self, value: bytes, nonce: bytes) -> bytes:
        digest = hashlib.new(self._algorithm_name)
        digest.update(value)
        digest.update(nonce)

        return digest.digest()

    def _set_claims(self) -> Dict[str, Claim]:
        claims: dict = self.credential_params.get(PropertyName.JL_CLAIM)
        if not claims:
            raise ValueError("Claim cannot be empty.")
        return {key: Claim.from_json(value) for key, value in claims.items()}

    @classmethod
    def from_(
        cls,
        claim: Optional[Dict[str, Claim]],
        display_layout: Optional[DisplayLayout] = None,
        context=None,
        hash_algorithm: str = None,
        info: Optional[Dict[str, InfoParam]] = None,
        proof_type: Optional[str] = None,
        type_=None,
        encoding="utf-8",
    ) -> "JsonLdParam":
        if not claim:
            raise ValueError("Claim cannot be empty.")

        param_object = cls()
        types: List[str] = type_ if type_ else type_[PropertyName.JL_AT_TYPE]
        if PropertyName.JL_TYPE_CREDENTIAL_PARAM not in types:
            types.insert(0, PropertyName.JL_TYPE_CREDENTIAL_PARAM)
        param: Dict[str, Any] = {PropertyName.JL_TYPE: types}

        if context:
            param[PropertyName.JL_CONTEXT] = context

        hash_algorithm: HashAlgorithmType = (
            HashAlgorithmType(hash_algorithm) if hash_algorithm else HashAlgorithmType.sha256
        )
        param_object._digest = hashlib.new(hash_algorithm.name or HashedAttribute.DEFAULT_ALG)
        param_object.hash_values = {}
        param_object.claims = {}
        for key, value in claim.items():
            nonce = get_random_nonce(32)
            claim: Claim = Claim(claim_value=value.claim_value, salt=nonce, display_value=value.display_value)
            digested = param_object._get_digest(claim.claim_value_as_bytes(encoding), nonce.encode(encoding))
            param_object.hash_values[key] = Base64URLEncoder.encode(digested)
            param_object.claims[key] = claim

        param_object.credential_params = {
            PropertyName.JL_CLAIM: {key: value.as_dict() for key, value in param_object.claims.items()},
            PropertyName.JL_HASH_ALGORITHM: hash_algorithm.value,
            PropertyName.JL_PROOF_TYPE: proof_type or BaseClaim.HASH_TYPE,
        }

        if display_layout:
            param_object.display_layout = display_layout
            param_object.credential_params[PropertyName.JL_DISPLAY_LAYOUT] = (
                param_object.display_layout.get_display()
                if param_object.display_layout.is_string
                else param_object.display_layout.get_object_display()
            )

        if info:
            param_object.info = info
            param_object.credential_params[PropertyName.JL_INFO] = {
                key: value.as_dict() for key, value in param_object.info.items()
            }
        param[PropertyName.JL_CREDENTIAL_PARAM] = param_object.credential_params
        param_object.set_node(param)

        return param_object

    @classmethod
    def from_encoded_param(cls, encoded_param: str):
        params = json.loads(Base64URLEncoder.decode(encoded_param))
        return cls(params)

    def verify_param(self, params: Dict[str, str], encoding="utf-8") -> bool:
        logger.debug(f"params: {params}")
        for key, claim in self.claims.items():
            digest = self._get_digest(value=claim.claim_value.encode(encoding), nonce=claim.salt.encode(encoding))
            origin = Base64URLEncoder.decode(params.get(key))
            if digest != origin:
                logger.debug(f"key: {key}, value: {claim.claim_value}, salt: {claim.salt}")
                logger.debug(f"origin: {origin}")
                logger.debug(f"digest: {digest}")
                return False

        return True
