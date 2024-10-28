import pytest

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld.json_ld_vcr import JsonLdVcr


class TestJsonLdVcr:
    @pytest.fixture
    def context(self) -> list:
        return [
            "https://vc-test.zzeung.id/credentials/v1.json",
            "https://vc-test.zzeung.id/credentials/il/driver_license/kor/v1.json",
        ]

    @pytest.fixture
    def id_(self) -> str:
        return "https://www.zzeung.id/vcr/driver_license/123623"

    @pytest.fixture
    def type_(self) -> list:
        return ["JsonLdVcrTest"]

    @pytest.fixture
    def json_ld_vcr(self, context: list, id_: str, type_: list, vc_claim: dict) -> JsonLdVcr:
        return JsonLdVcr(context=context, id_=id_, type_=type_, request_claim=vc_claim)

    def test_create(self, context: list, id_: str, type_: list, vc_claim: dict):
        # GIVEN some claims and base data
        # WHEN try to create a object type of JsonLdVcr
        json_ld_vcr: JsonLdVcr = JsonLdVcr(context=context, id_=id_, type_=type_, request_claim=vc_claim)

        # THEN success to get above claims from JsonLdVcr
        assert context == json_ld_vcr.get_term(PropertyName.JL_CONTEXT)
        assert id_ == json_ld_vcr.get_term(PropertyName.JL_ID)
        assert type_ == json_ld_vcr.get_term(PropertyName.JL_AT_TYPE)
        assert vc_claim["name"] == json_ld_vcr.get_request_claim("name")
        assert vc_claim["birthDate"] == json_ld_vcr.get_request_claim("birthDate")
        assert vc_claim["gender"] == json_ld_vcr.get_request_claim("gender")
        assert vc_claim["telco"] == json_ld_vcr.get_request_claim("telco")
        assert vc_claim["phoneNumber"] == json_ld_vcr.get_request_claim("phoneNumber")
        assert vc_claim["connectingInformation"] == json_ld_vcr.get_request_claim("connectingInformation")
        assert vc_claim["citizenship"] == json_ld_vcr.get_request_claim("citizenship")
        assert vc_claim["bank"] == json_ld_vcr.get_request_claim("bank")
        assert vc_claim["accountNumber"] == json_ld_vcr.get_request_claim("accountNumber")

    def test_from_(self, context: list, id_: str, type_: list, vc_claim: dict):
        # GIVEN a data for creation a JsonLdVcr
        data = {
            PropertyName.JL_CONTEXT: context,
            PropertyName.JL_ID: id_,
            PropertyName.JL_AT_TYPE: type_,
            PropertyName.JL_REQUEST_CLAIM: vc_claim,
        }

        # WHEN try to create a JsonLdVcr object using the `from_` method.
        json_ld_vcr: JsonLdVcr = JsonLdVcr.from_(data)

        # THEN success to get above claims from JsonLdVcr
        assert context == json_ld_vcr.get_term(PropertyName.JL_CONTEXT)
        assert id_ == json_ld_vcr.get_term(PropertyName.JL_ID)
        assert type_ == json_ld_vcr.get_term(PropertyName.JL_AT_TYPE)
        assert vc_claim["name"] == json_ld_vcr.get_request_claim("name")
        assert vc_claim["birthDate"] == json_ld_vcr.get_request_claim("birthDate")
        assert vc_claim["gender"] == json_ld_vcr.get_request_claim("gender")
        assert vc_claim["telco"] == json_ld_vcr.get_request_claim("telco")
        assert vc_claim["phoneNumber"] == json_ld_vcr.get_request_claim("phoneNumber")
        assert vc_claim["connectingInformation"] == json_ld_vcr.get_request_claim("connectingInformation")
        assert vc_claim["citizenship"] == json_ld_vcr.get_request_claim("citizenship")
        assert vc_claim["bank"] == json_ld_vcr.get_request_claim("bank")
        assert vc_claim["accountNumber"] == json_ld_vcr.get_request_claim("accountNumber")

    @pytest.mark.parametrize("key", ["name", "birthDate", "gender", "accountNumber"])
    def test_request_claim(self, json_ld_vcr: JsonLdVcr, vc_claim: dict, key: str):
        # GIVEN a JsonLdVcr object
        # WHEN try to get a claim by a key
        claim = json_ld_vcr.get_request_claim(key)

        # THEN success to get same value with source claim
        assert vc_claim[key] == claim
