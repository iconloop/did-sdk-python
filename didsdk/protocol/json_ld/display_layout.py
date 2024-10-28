from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class DisplayLayout:
    layout: Any = None

    @property
    def is_string(self):
        return True if isinstance(self.layout, str) else False

    def get_display(self) -> List[str]:
        return self.layout if self.is_string else None

    def get_object_display(self) -> List[Dict[str, List[str]]]:
        return self.layout if not self.is_string else None
