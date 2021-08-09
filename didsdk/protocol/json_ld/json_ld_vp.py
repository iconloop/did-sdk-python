from typing import Dict, Any, List, Optional

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld.base_json_ld import BaseJsonLd
from didsdk.protocol.json_ld.vp_criteria import VpCriteria


class JsonLdVp(BaseJsonLd):
    def __init__(self, vp: Dict[str, Any]):
        super().__init__(vp)
        self.fulfilledCriteria: List[VpCriteria] = self._set_fulfilled_criteria()

    def _set_fulfilled_criteria(self) -> List[VpCriteria]:
        elements: Optional[List, Dict] = self.node.get(PropertyName.JL_FULFILLED_CRITERIA)
        criteria_list = []
        if isinstance(elements, list):
            criteria_list = [VpCriteria(**element) for element in elements]
        else:
            criteria_list.append(VpCriteria(**elements))

        return criteria_list
    
    @classmethod
    def from_(cls, context, id_: str, type_, presenter: str, criteria_list: List[VpCriteria]) -> 'JsonLdVp':
        if not (id_ or criteria_list):
            raise ValueError('[id_, criteria_list] values cannot be None.')

        vp = dict()
        vp.update({
            PropertyName.JL_CONTEXT: context,
            PropertyName.JL_ID: id_,
            PropertyName.JL_TYPE: type_,
            PropertyName.JL_PRESENTER: presenter
        })

        vp[PropertyName.JL_FULFILLED_CRITERIA] = (criteria_list[0] if len(criteria_list) == 1
                                                  else [criteria.criteria for criteria in criteria_list])

        return cls(vp)
