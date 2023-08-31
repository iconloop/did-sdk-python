from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld.base_json_ld import BaseJsonLd
from didsdk.protocol.json_ld.vpr_condition import VprCondition


@dataclass
class PR:
    purpose: str
    condition: Optional[Dict[str, Any]]
    verifier: str = None
    purpose_label: str = None

    def as_dict(self) -> Dict[str, Any]:
        pr: dict = {PropertyName.JL_PURPOSE: self.purpose, PropertyName.JL_CONDITION: self.condition}

        if self.verifier:
            pr[PropertyName.JL_VERIFIER] = self.verifier
        if self.purpose_label:
            pr[PropertyName.JL_PURPOSE_LABEL] = self.purpose_label

        return pr


@dataclass
class VPR:
    context: Any
    id: str
    presentation_url: str
    pr: PR
    type: List[str] = field(default_factory=lambda: ["PresentationRequest"])

    def as_dict(self) -> Dict[str, Any]:
        return {
            PropertyName.JL_CONTEXT: self.context,
            PropertyName.JL_ID: self.id,
            PropertyName.JL_AT_TYPE: self.type,
            PropertyName.JL_PRESENTATION_URL: self.presentation_url,
            PropertyName.JL_PRESENTATION_REQUEST: self.pr.as_dict(),
        }


class JsonLdVpr(BaseJsonLd):
    def __init__(self, pr: PR, condition: VprCondition):
        super().__init__()

        self.pr: PR = pr
        self.condition: VprCondition = condition

    @classmethod
    def from_(
        cls,
        context: list,
        id_: str,
        purpose: str,
        condition: VprCondition,
        verifier: str = None,
        url: str = None,
        purpose_label: str = None,
    ) -> "JsonLdVpr":
        if not (context and id_ and purpose and condition):
            raise ValueError("Any value of [context, id, purpose, condition] cannot be None.")

        pr: PR = PR(purpose=purpose, purpose_label=purpose_label, verifier=verifier, condition=condition.node)
        vpr = {
            PropertyName.JL_CONTEXT: context,
            PropertyName.JL_ID: id_,
            PropertyName.JL_AT_TYPE: ["PresentationRequest"],
            PropertyName.JL_PRESENTATION_REQUEST: pr.as_dict(),
        }

        if url:
            vpr[PropertyName.JL_PRESENTATION_URL] = url

        json_ld_vpr: JsonLdVpr = cls(pr, condition)
        json_ld_vpr.set_node(vpr)

        return json_ld_vpr

    @classmethod
    def from_json(cls, vpr: Dict[str, Any]) -> "JsonLdVpr":
        pr: Dict[str, Any] = vpr.get(PropertyName.JL_PRESENTATION_REQUEST)
        condition: VprCondition = VprCondition(pr.get(PropertyName.JL_CONDITION))
        pr_object: PR = PR(
            purpose=pr.get(PropertyName.JL_PURPOSE),
            purpose_label=pr.get(PropertyName.JL_PURPOSE_LABEL),
            verifier=pr.get(PropertyName.JL_VERIFIER),
            condition=condition.node,
        )

        json_ld_vpr = cls(pr=pr_object, condition=condition)
        json_ld_vpr.set_node(vpr)

        return json_ld_vpr

    @classmethod
    def from_vpr(cls, vpr: VPR, condition: VprCondition) -> "JsonLdVpr":
        json_ld_vpr = cls(pr=vpr.pr, condition=condition)
        json_ld_vpr.set_node(vpr.as_dict())

        return json_ld_vpr
