from dataclasses import dataclass
from typing import Any, List, Dict


@dataclass
class DisplayLayout:
    layout: Any = None
    is_string: bool = None

    def get_display(self) -> List[str]:
        return self.layout if self.is_string else None

    def get_object_display(self) -> List[Dict[str, List[str]]]:
        return self.layout if not self.is_string else None
