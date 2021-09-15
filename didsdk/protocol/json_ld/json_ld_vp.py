from typing import Dict, Any, List, Optional

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld.base_json_ld import BaseJsonLd
from didsdk.protocol.json_ld.vp_criteria import VpCriteria


class JsonLdVp(BaseJsonLd):
    def __init__(self, vp: Dict[str, Any]):
        super().__init__(vp)
        self.fulfilledCriteria: Optional[List[VpCriteria]] = None

    @classmethod
    def from_(cls, context, id_: str, type_, presenter: str, criteria_list: List[VpCriteria]) -> 'JsonLdVp':
        if not (id_ or criteria_list):
            raise ValueError('[id_, criteria_list] values cannot be None.')

        vp = dict()
        vp.update({
            PropertyName.JL_CONTEXT: context,
            PropertyName.JL_ID: id_,
            PropertyName.JL_TYPE: type_,
            PropertyName.JL_PRESENTER: presenter,
            PropertyName.JL_FULFILLED_CRITERIA: ([criteria_list[0].criteria] if len(criteria_list) == 1
                                                 else [criteria.criteria for criteria in criteria_list])
        })

        json_ld_vp = cls(vp)
        json_ld_vp.fulfilledCriteria = criteria_list
        return json_ld_vp
