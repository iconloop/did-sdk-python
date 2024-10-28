import json
from typing import Any, Dict, Optional

from loguru import logger

from didsdk.core.property_name import PropertyName
from didsdk.document.encoding import Base64URLEncoder


class BaseJsonLd:
    def __init__(self, data: Dict = None):
        self._context = None
        self.id = None
        self.type = None
        self.node: Optional[Dict[str, Any]] = None

        if data:
            self.set_node(data)

    @property
    def context(self) -> Optional[Dict[str, Any]]:
        return self._context if self._context and self.is_context_object() else None

    def as_dict(self) -> dict:
        return self.node

    def is_context_object(self) -> bool:
        try:
            json.dumps(self._context)
            return True
        except ValueError as e:
            logger.debug(f"It's not a json data. {e}")
            return False

    def get_term(self, key) -> Any:
        return self.node.get(key)

    def set_node(self, data: dict = None):
        self._context = data.get(PropertyName.JL_CONTEXT)
        self.id = data.get(PropertyName.JL_ID) or data.get(PropertyName.JL_AT_ID)
        self.type = data.get(PropertyName.JL_TYPE) or data.get(PropertyName.JL_AT_TYPE)
        self.node: Optional[Dict[str, Any]] = data

    def as_base64_url_string(self, encoding="utf-8") -> str:
        return Base64URLEncoder.encode(json.dumps(self.node).encode(encoding))
