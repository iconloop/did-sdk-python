import copy
from typing import Any, Dict, List

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld.base_json_ld import BaseJsonLd
from didsdk.protocol.json_ld.json_ld_param import JsonLdParam
from didsdk.protocol.json_ld.revocation_service import RevocationService


class JsonLdVc(BaseJsonLd):
    def __init__(self, vc: Dict[str, Any] = None):
        super().__init__(vc)

        self.credential_subject: Dict[str, str] = self.node.get(PropertyName.JL_CREDENTIAL_SUBJECT) if vc else {}
        self._refresh: Dict[str, str] = self.node.get(PropertyName.JL_REFRESH_SERVICE) if vc else {}
        self.revocation: RevocationService = self.node.get(PropertyName.JL_REVOCATION_SERVICE) if vc else None

    def __eq__(self, other):
        return self.node == other.node

    @property
    def crypto_algorithm(self) -> str:
        return self.node.get(PropertyName.JL_CRYPTO_ALGORITHM)

    @property
    def crypto_type(self) -> str:
        return self.node.get(PropertyName.JL_CRYPTO_TYPE)

    @property
    def refresh_id(self) -> str:
        return self._refresh.get("id")

    @property
    def refresh_type(self) -> str:
        return self._refresh.get("type")

    def as_dict(self) -> dict:
        if PropertyName.JL_REVOCATION_SERVICE in self.node:
            json_node = copy.deepcopy(self.node)
            json_node[PropertyName.JL_REVOCATION_SERVICE] = self.node[PropertyName.JL_REVOCATION_SERVICE].as_dict()
            return json_node
        return super().as_dict()

    @classmethod
    def from_(
        cls,
        param: JsonLdParam,
        credential_subject_id: str = None,
        id_: str = None,
        refresh_id: str = None,
        refresh_type: str = None,
        revocation_service: RevocationService = None,
        terms_of_use: List[Dict[str, str]] = None,
    ) -> "JsonLdVc":
        vc_object = cls()

        if not param:
            raise ValueError("param cannot be empty.")

        types: List[str] = param.get_term(PropertyName.JL_TYPE)[:]
        types.remove(PropertyName.JL_TYPE_CREDENTIAL_PARAM)
        types.insert(0, PropertyName.JL_TYPE_VERIFIABLE_CREDENTIAL)

        credential_params = param.credential_params
        vc = dict()
        vc.update(
            {
                PropertyName.JL_CONTEXT: param.get_term(PropertyName.JL_CONTEXT),
                PropertyName.JL_TYPE: types,
                PropertyName.JL_ID: id_,
                PropertyName.JL_CRYPTO_TYPE: credential_params.get(PropertyName.JL_PROOF_TYPE),
                PropertyName.JL_CRYPTO_ALGORITHM: credential_params.get(PropertyName.JL_HASH_ALGORITHM),
            }
        )

        param.hash_values["id"] = credential_subject_id if credential_subject_id else id_
        vc[PropertyName.JL_CREDENTIAL_SUBJECT] = param.hash_values
        if refresh_id and refresh_type:
            vc[PropertyName.JL_REFRESH_SERVICE] = {"id": refresh_id, "type": refresh_type}

        if revocation_service:
            vc[PropertyName.JL_REVOCATION_SERVICE] = revocation_service

        if terms_of_use:
            vc[PropertyName.JL_TERMS_OF_USE] = terms_of_use

        vc_object.set_node(vc)

        return vc_object
