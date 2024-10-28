import dataclasses
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

    def as_dict(self) -> dict:
        return {BASE_VC_TYPE: self.vc_type, BASE_VC: self.vc, BASE_PARAM: dataclasses.asdict(self.param)}

    @classmethod
    def from_json(cls, json_data: dict) -> "BaseVc":
        param: BaseParam = BaseParam(**json_data[BASE_PARAM])
        return cls(vc_type=json_data[BASE_VC_TYPE], vc=json_data[BASE_VC], param=param)

    def is_valid(self):
        if not self.credential:
            self.credential = Credential.from_encoded_jwt(self.vc)

        return self.credential.base_claim.verify(self.param)
