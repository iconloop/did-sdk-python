from typing import Any, Dict, Optional

from didsdk.exceptions import AttributeException
from didsdk.protocol.base_param import BaseParam
from didsdk.protocol.claim_attribute import ClaimAttribute
from didsdk.protocol.hash_attribute import HashedAttribute


class BaseClaim:
    ATTRIBUTE_TYPE = "attrType"
    ATTRIBUTE = "attr"
    HASH_TYPE = HashedAttribute.ATTR_TYPE

    def __init__(
        self, attribute_type: str, attribute: "ClaimAttribute" = None, algorithm: str = None, values: Dict = None
    ):
        if attribute_type == self.HASH_TYPE:
            self.attribute_type: str = attribute_type
        else:
            raise ValueError(f'"Unsupported Attribute Type({attribute_type})')

        if attribute:
            self.attribute = attribute
        elif algorithm:
            self.attribute = HashedAttribute(alg=algorithm, values=values)
        else:
            raise AttributeException("BaseClaim must need one of ClaimAttribute and algorithm.")

    def to_json(self) -> Dict[str, Any]:
        return {
            self.ATTRIBUTE_TYPE: self.attribute_type,
            self.ATTRIBUTE: {"alg": self.attribute.alg, "value": self.attribute.hashed_values},
        }

    @classmethod
    def from_json(cls, json_data: Dict):
        attribute_type: str = str(json_data.get(cls.ATTRIBUTE_TYPE))
        attribute: Optional["ClaimAttribute"] = None
        attr_object: Dict = json_data.get(cls.ATTRIBUTE)

        if attribute_type == cls.HASH_TYPE:
            attribute = HashedAttribute.from_json(attr_object, True)
        else:
            raise AttributeException(f"Unsupported Attribute Type({attribute_type})")

        return BaseClaim(attribute_type, attribute)

    def verify(self, base_param: BaseParam):
        return self.attribute.verify(base_param)
