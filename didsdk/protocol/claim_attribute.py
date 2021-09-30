import abc
from typing import List

from didsdk.protocol.base_param import BaseParam


class ClaimAttribute(abc.ABC):
    def get_type(self) -> str:
        raise NotImplementedError

    def get_claim_types(self) -> List[str]:
        raise NotImplementedError

    def verify(self, param: BaseParam) -> bool:
        raise NotImplementedError
