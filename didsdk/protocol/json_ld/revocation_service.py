from enum import Enum
from typing import Dict, List

import validators


class RevocationServiceType(Enum):
    SIMPLE = "SimpleRevocationService"
    MANUAL = "ManualRevocationService"

    @classmethod
    def names(cls) -> List[str]:
        return [member.name for member in cls]

    @classmethod
    def values(cls) -> List[str]:
        return [member.value for member in cls]


class RevocationService:
    def __init__(self, id_: str, type_: str, short_description: str):
        if not (id_ and type_ and short_description):
            raise ValueError("[id_, type_] values cannot be blank.")
        if type_ not in RevocationServiceType.values():
            raise ValueError('type must be on of ["SimpleRevocationService", "ManualRevocationService"] values.')
        if not validators.url(id_):
            raise ValueError("Invalid id. The ID format is the correct in URL format.")

        self.id_ = id_
        self.type_ = type_
        self.short_description = short_description

    def __eq__(self, other: "RevocationService") -> bool:
        if self is other:
            return True

        if other is None or self.__class__ != other.__class__:
            return False

        return self.id_ == other.id_ and self.type_ == other.type_ and self.short_description == other.short_description

    def as_dict(self) -> Dict[str, str]:
        return {"id": self.id_, "type": self.type_, "shortDescription": self.short_description}
