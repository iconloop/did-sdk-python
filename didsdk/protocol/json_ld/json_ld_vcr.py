from typing import List, Any, Dict

from didsdk.core.property_name import PropertyName
from didsdk.protocol.json_ld.base_json_ld import BaseJsonLd


class JsonLdVcr(BaseJsonLd):
    def __init__(self, context, id_: str, type_: List[str], request_claim: Dict[str, Any]):
        super().__init__({PropertyName.JL_CONTEXT: context,
                          PropertyName.JL_ID: id_,
                          PropertyName.JL_AT_TYPE: type_,
                          PropertyName.JL_REQUEST_CLAIM: request_claim})

    @staticmethod
    def from_(data: Dict[str, Any]) -> 'JsonLdVcr':
        return JsonLdVcr(context=data.get(PropertyName.JL_CONTEXT), id_=data.get(PropertyName.JL_ID),
                         type_=data.get(PropertyName.JL_AT_TYPE), request_claim=data.get(PropertyName.JL_REQUEST_CLAIM))
