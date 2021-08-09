from dataclasses import dataclass
from typing import List

from didsdk.credential import Credential
from didsdk.protocol.base_param import BaseParam

BASE_VC_TYPE = "vcType"
BASE_VC = "vc"
BASE_PARAM = "param"


@dataclass
class BaseVc:
    vc_type: List[str]
    vc: str
    param: BaseParam
    credential: Credential = None

    def is_valid(self):
        if not self.credential:
            self.credential = Credential.from_encoded_jwt(self.vc)

        return self.credential.base_claim.verify(self.param)
