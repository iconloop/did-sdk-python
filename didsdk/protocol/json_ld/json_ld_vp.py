from typing import Any, Dict, Optional

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld.base_json_ld import BaseJsonLd
from didsdk.protocol.json_ld.vp_criteria import VpCriteria


class JsonLdVp(BaseJsonLd):
    def __init__(self, vp: Dict[str, Any]):
        super().__init__(vp)
        self.fulfilledCriteria: Optional[VpCriteria] = VpCriteria.from_json(vp.get("fulfilledCriteria")) if vp else None

    # TODO: Temporary fix for `Zzeung` mobile app. fulfilledCriteria type List -> Single object(none list).
    # def __init__(self, vp: Dict[str, Any]):
    #     super().__init__(vp)
    #     self.fulfilledCriteria: Optional[List[VpCriteria]] = (
    #         self._set_fulfilled_criteria(vp.get('fulfilledCriteria')) if vp else None)
    #
    # def _set_fulfilled_criteria(self, criteria_list: list) -> Optional[List[VpCriteria]]:
    #     result: List[VpCriteria] = []
    #     for criteria in criteria_list:
    #         result.append(VpCriteria.from_json(criteria))
    #
    #     return result

    @classmethod
    def from_(cls, context, id_: str, type_, criteria: VpCriteria, presenter: str = None) -> "JsonLdVp":
        if not (id_ or criteria):
            raise ValueError("[id_, criteria] values cannot be None.")

        vp = {
            PropertyName.JL_CONTEXT: context,
            PropertyName.JL_ID: id_,
            PropertyName.JL_TYPE: type_,
            PropertyName.JL_FULFILLED_CRITERIA: criteria.criteria,
        }

        if presenter:
            vp[PropertyName.JL_PRESENTER] = presenter

        json_ld_vp = cls(vp)
        json_ld_vp.fulfilledCriteria = criteria
        return json_ld_vp

    # TODO: Temporary fix for `Zzeung` mobile app. fulfilledCriteria type List -> Single object(none list).
    # @classmethod
    # def from_(cls, context, id_: str, type_, criteria_list: List[VpCriteria], presenter: str = None) -> 'JsonLdVp':
    #     if not (id_ or criteria_list):
    #         raise ValueError('[id_, criteria_list] values cannot be None.')
    #
    #     vp = {
    #         PropertyName.JL_CONTEXT: context,
    #         PropertyName.JL_ID: id_,
    #         PropertyName.JL_TYPE: type_,
    #         PropertyName.JL_FULFILLED_CRITERIA: ([criteria_list[0].criteria] if len(criteria_list) == 1
    #                                              else [criteria.criteria for criteria in criteria_list])
    #     }
    #
    #     if presenter:
    #         vp[PropertyName.JL_PRESENTER] = presenter
    #
    #     json_ld_vp = cls(vp)
    #     json_ld_vp.fulfilledCriteria = criteria_list
    #     return json_ld_vp
