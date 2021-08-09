import json
from dataclasses import dataclass
from typing import List

from didsdk.core.property_name import PropertyName


@dataclass
class InfoParam:
    content: str = None
    data_uri: str = None
    name: str = None
    type: List[str] = None
    url: str = None

    def to_json(self) -> str:
        param = {PropertyName.JL_AT_TYPE: self.type}
        if self.name:
            param['name'] = self.name

        if self.content:
            param['content'] = self.content

        if self.url:
            param['url'] = self.url

        if self.data_uri:
            param['dataUri'] = self.data_uri

        return json.dumps(param)
