from typing import Any, Dict, Optional

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld.json_ld_param import JsonLdParam


class VpCriteria:
    def __init__(self, vc: str = None, param: JsonLdParam = None, condition_id: str = None):
        if not (vc or param or condition_id):
            raise ValueError("Anyone of the values(vc, param and condition_id) cannot be None.")

        self.criteria: Dict[str, Optional[Any]] = {
            PropertyName.JL_CONDITION_ID: condition_id,
            PropertyName.JL_VERIFIABLE_CREDENTIAL: vc,
            PropertyName.JL_VERIFIABLE_CREDENTIAL_PARAM: param.node,
        }
        self.param: JsonLdParam = param

    def get_condition_id(self) -> str:
        return self.criteria[PropertyName.JL_VERIFIABLE_CREDENTIAL]

    def get_vc(self) -> str:
        return self.criteria[PropertyName.JL_VERIFIABLE_CREDENTIAL]

    @classmethod
    def from_json(cls, json_data: Dict) -> "VpCriteria":
        return cls(
            vc=json_data[PropertyName.JL_VERIFIABLE_CREDENTIAL],
            param=JsonLdParam(json_data[PropertyName.JL_VERIFIABLE_CREDENTIAL_PARAM]),
            condition_id=json_data.get(PropertyName.JL_CONDITION_ID),
        )

    def verify_param(self) -> bool:
        from didsdk.credential import Credential

        credential: Credential = Credential.from_encoded_jwt(self.get_vc())
        return self.param.verify_param(credential.vc.credential_subject)
