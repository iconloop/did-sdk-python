from dataclasses import dataclass
from enum import Enum
from typing import List

from didsdk.core.property_name import PropertyName


class InfoViewType(Enum):
    TEXT_VIEW = "TextView"
    WEB_VIEW = "WebView"
    IMAGE_VIEW = "ImageView"


@dataclass
class InfoParam:
    content: str = None
    data_uri: str = None
    name: str = None
    type: List[str] = None
    url: str = None

    @classmethod
    def for_text_view(cls, name: str, content: str):
        return cls(type=[InfoViewType.TEXT_VIEW.value], name=name, content=content)

    @classmethod
    def for_web_view(cls, name: str, url: str):
        return cls(type=[InfoViewType.TEXT_VIEW.value], name=name, content=url)

    @classmethod
    def for_image_view(cls, name: str, data_uri: str):
        return cls(type=[InfoViewType.TEXT_VIEW.value], name=name, content=data_uri)

    def as_dict(self) -> dict:
        param = {PropertyName.JL_AT_TYPE: self.type}
        if self.name:
            param["name"] = self.name

        if self.content:
            param["content"] = self.content

        if self.url:
            param["url"] = self.url

        if self.data_uri:
            param["dataUri"] = self.data_uri

        return param

    @classmethod
    def from_json(cls, json_data: dict):
        return cls(
            json_data.get("content"),
            json_data.get("dataUri"),
            json_data.get("name"),
            json_data.get(PropertyName.JL_AT_TYPE),
            json_data.get("url"),
        )
