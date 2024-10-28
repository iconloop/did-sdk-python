from typing import Any, Dict, List

import pytest

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld.json_ld_vpr import PR, VPR, JsonLdVpr
from didsdk.protocol.json_ld.vpr_condition import VprCondition


class TestJsonLdVpr:
    @pytest.fixture
    def condition(self) -> VprCondition:
        return VprCondition.from_simple_condition(
            credential_type="MobileAuthenticationKorCredential",
            condition_id="uuid-requisite-0000-1111-2222",
            issuer=["did:icon:01:c07bbcf24b7d9c7a1202e8ed0a64d17eee956aa48561bc9"],
            context=["https://vc-test.zzeung.id/credentials/mobile_authentication/kor/v1.json"],
            property_=["name", "gender", "telco", "phoneNumber", "connectingInformation", "birthDate"],
        )

    @pytest.fixture
    def context(self) -> List[str]:
        return ["https://vc-test.zzeung.id/credentials/v1.json"]

    @pytest.fixture
    def id_(self) -> str:
        return "https://ivtest-test.zzeung.id/driver/v1/vcp/vcr/12345"

    @pytest.fixture
    def url(self) -> str:
        return "https://ivtest-test.zzeung.id/driver/v1/vcp/vp"

    @pytest.fixture
    def purpose(self) -> str:
        return "fill-in"

    @pytest.fixture
    def purpose_label(self) -> str:
        return "purpose_label"

    @pytest.fixture
    def verifier(self) -> str:
        return "did:icon:01:b7d31981bfe8600b44e1be05af9bed1a60458d23e827c6c5"

    @pytest.fixture
    def pr(self, condition: VprCondition, purpose: str, purpose_label: str, verifier: str) -> PR:
        return PR(purpose=purpose, purpose_label=purpose_label, verifier=verifier, condition=condition.as_dict())

    @pytest.fixture
    def vpr(self, context: List[str], id_: str, url: str, pr: PR) -> VPR:
        return VPR(context, id_, url, pr)

    def test_create(self, condition: VprCondition, context: List[str], id_: str, url: str, purpose: str, verifier: str):
        # GIVEN a VprCondition and properties for JsonLdVpr object
        # WHEN try to create JsonLdVpr object
        json_ld_vpr: JsonLdVpr = JsonLdVpr.from_(
            context=context, id_=id_, url=url, purpose=purpose, verifier=verifier, condition=condition
        )

        # THEN success to get above properties from JsonLdVpr
        assert json_ld_vpr.get_term(PropertyName.JL_CONTEXT) == context
        assert json_ld_vpr.get_term(PropertyName.JL_ID) == id_
        assert json_ld_vpr.get_term(PropertyName.JL_PRESENTATION_URL) == url

        pr: Dict[str, Any] = json_ld_vpr.get_term(PropertyName.JL_PRESENTATION_REQUEST)
        assert pr.get(PropertyName.JL_PURPOSE) == purpose
        assert pr.get(PropertyName.JL_PURPOSE_LABEL) is None
        assert pr.get(PropertyName.JL_VERIFIER) == verifier

        pr_condition: dict[str, Any] = pr.get(PropertyName.JL_CONDITION)
        assert pr_condition.get(PropertyName.JL_CONTEXT) == condition.context
        assert pr_condition.get(PropertyName.JL_ID) == condition.id
        assert pr_condition.get(PropertyName.JL_AT_TYPE) == condition.type
        assert pr_condition.get(PropertyName.JL_CONDITION_ID) == condition.get_term(PropertyName.JL_CONDITION_ID)
        assert pr_condition.get(PropertyName.JL_ISSUER) == condition.get_term(PropertyName.JL_ISSUER)
        assert pr_condition.get(PropertyName.JL_CREDENTIAL_TYPE) == condition.get_term(PropertyName.JL_CREDENTIAL_TYPE)
        assert pr_condition.get(PropertyName.JL_PROPERTY) == condition.get_term(PropertyName.JL_PROPERTY)

        vpr_condition: VprCondition = json_ld_vpr.condition
        assert vpr_condition.get_term(PropertyName.JL_CONTEXT) == condition.context
        assert vpr_condition.get_term(PropertyName.JL_ID) == condition.id
        assert vpr_condition.get_term(PropertyName.JL_AT_TYPE) == condition.type
        assert vpr_condition.get_term(PropertyName.JL_CONDITION_ID) == condition.get_term(PropertyName.JL_CONDITION_ID)
        assert vpr_condition.get_term(PropertyName.JL_ISSUER) == condition.get_term(PropertyName.JL_ISSUER)
        assert vpr_condition.get_term(PropertyName.JL_CREDENTIAL_TYPE) == condition.get_term(
            PropertyName.JL_CREDENTIAL_TYPE
        )
        assert vpr_condition.get_term(PropertyName.JL_PROPERTY) == condition.get_term(PropertyName.JL_PROPERTY)

    def test_from_json(self, vpr: VPR):
        # GIVEN a VprCondition and properties for JsonLdVpr object
        # WHEN try to create JsonLdVpr object
        json_ld_vpr: JsonLdVpr = JsonLdVpr.from_json(vpr.as_dict())

        # THEN success to get above properties from JsonLdVpr
        pr: Dict[str, Any] = json_ld_vpr.get_term(PropertyName.JL_PRESENTATION_REQUEST)
        condition: VprCondition = VprCondition(pr.get(PropertyName.JL_CONDITION))
        self._assert(json_ld_vpr, vpr, condition)

    def test_from_vpr(self, vpr: VPR, condition: VprCondition):
        # GIVEN a VprCondition and properties for JsonLdVpr object
        # WHEN try to create JsonLdVpr object
        json_ld_vpr: JsonLdVpr = JsonLdVpr.from_vpr(vpr, condition)

        # THEN success to get above properties from JsonLdVpr
        self._assert(json_ld_vpr, vpr, condition)

    def _assert(self, json_ld_vpr: JsonLdVpr, vpr: VPR, condition: VprCondition):
        assert json_ld_vpr.get_term(PropertyName.JL_CONTEXT) == vpr.context
        assert json_ld_vpr.get_term(PropertyName.JL_ID) == vpr.id
        assert json_ld_vpr.get_term(PropertyName.JL_PRESENTATION_URL) == vpr.presentation_url

        pr: Dict[str, Any] = json_ld_vpr.get_term(PropertyName.JL_PRESENTATION_REQUEST)
        assert pr.get(PropertyName.JL_PURPOSE) == vpr.pr.purpose
        assert pr.get(PropertyName.JL_PURPOSE_LABEL) is vpr.pr.purpose_label
        assert pr.get(PropertyName.JL_VERIFIER) == vpr.pr.verifier

        pr_condition: dict[str, Any] = pr.get(PropertyName.JL_CONDITION)
        assert pr_condition.get(PropertyName.JL_CONTEXT) == condition.context
        assert pr_condition.get(PropertyName.JL_ID) == condition.id
        assert pr_condition.get(PropertyName.JL_AT_TYPE) == condition.type
        assert pr_condition.get(PropertyName.JL_CONDITION_ID) == condition.get_term(PropertyName.JL_CONDITION_ID)
        assert pr_condition.get(PropertyName.JL_ISSUER) == condition.get_term(PropertyName.JL_ISSUER)
        assert pr_condition.get(PropertyName.JL_CREDENTIAL_TYPE) == condition.get_term(PropertyName.JL_CREDENTIAL_TYPE)
        assert pr_condition.get(PropertyName.JL_PROPERTY) == condition.get_term(PropertyName.JL_PROPERTY)

        vpr_condition: VprCondition = json_ld_vpr.condition
        assert vpr_condition.get_term(PropertyName.JL_CONTEXT) == condition.context
        assert vpr_condition.get_term(PropertyName.JL_ID) == condition.id
        assert vpr_condition.get_term(PropertyName.JL_AT_TYPE) == condition.type
        assert vpr_condition.get_term(PropertyName.JL_CONDITION_ID) == condition.get_term(PropertyName.JL_CONDITION_ID)
        assert vpr_condition.get_term(PropertyName.JL_ISSUER) == condition.get_term(PropertyName.JL_ISSUER)
        assert vpr_condition.get_term(PropertyName.JL_CREDENTIAL_TYPE) == condition.get_term(
            PropertyName.JL_CREDENTIAL_TYPE
        )
        assert vpr_condition.get_term(PropertyName.JL_PROPERTY) == condition.get_term(PropertyName.JL_PROPERTY)
