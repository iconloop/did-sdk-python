import json
from enum import Enum
from typing import Any, Dict, List

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld.base_json_ld import BaseJsonLd


class Operator(Enum):
    AND = "and"
    OR = "or"


class VprCondition(BaseJsonLd):
    def __init__(self, condition: Dict[str, Any]):
        super().__init__(condition)

        if (PropertyName.JL_OPERATOR in condition) and (PropertyName.JL_CONDITION in condition):
            elements: List = condition.get(PropertyName.JL_CONDITION)
            if not isinstance(elements, list):
                raise ValueError('"condition" must be a type of list.')

            self.condition_list: List[dict] = []
            for element in elements:
                if isinstance(element, dict):
                    self.condition_list.append(element)
                else:
                    self.condition_list.append(json.loads(element))

    def get_condition_id(self) -> str:
        return None if self.is_compound() else self.get_term(PropertyName.JL_CONDITION_ID)

    def get_credential_type(self) -> str:
        return None if self.is_compound() else self.get_term(PropertyName.JL_CREDENTIAL_TYPE)

    def get_issuers(self) -> List[str]:
        return None if self.is_compound() else self.get_term(PropertyName.JL_ISSUER)

    def get_operator(self) -> str:
        return self.get_term(PropertyName.JL_OPERATOR) if self.is_compound() else None

    def get_property(self) -> List[str]:
        return None if self.is_compound() else self.node.get(PropertyName.JL_PROPERTY)

    @classmethod
    def from_simple_condition(
        cls, context, condition_id: str, credential_type: str, property_, issuer=None, type_=None
    ) -> "VprCondition":
        if not (context and credential_type and property_):
            raise ValueError("[context, credential_type, property_] values cannot be None.")

        type_ = ["SimpleCondition"] + type_ if type_ else ["SimpleCondition"]

        condition = {
            PropertyName.JL_AT_TYPE: type_,
            PropertyName.JL_CONDITION_ID: condition_id,
            PropertyName.JL_CONTEXT: context,
            PropertyName.JL_CREDENTIAL_TYPE: credential_type,
            PropertyName.JL_PROPERTY: property_,
        }

        if issuer:
            condition[PropertyName.JL_ISSUER] = issuer

        return cls(condition)

    @classmethod
    def from_compound_condition(cls, operator: str, condition_list: List["VprCondition"], type_=None) -> "VprCondition":
        if not (operator and condition_list):
            raise ValueError("[operator, condition_list] values cannot be None.")
        if len(condition_list) < 2:
            raise ValueError('"condition" requires elements at least 2.')

        condition_list: List[dict] = [condition.node for condition in condition_list]
        condition = {
            PropertyName.JL_AT_TYPE: type_,
            PropertyName.JL_OPERATOR: operator,
            PropertyName.JL_CONDITION: condition_list,
        }
        return cls(condition)

    def is_compound(self) -> bool:
        return True if self.condition_list else False
