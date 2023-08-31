from dataclasses import dataclass


@dataclass
class ResponseResult:
    result: bool
    error_code: str
    error_message: str

    def __init__(self, result: bool, error_code: str = None, error_message: str = None):
        if not result:
            if not error_code:
                raise ValueError("error_code is None. If result is false, errorMessage is required.")
            if not error_message:
                raise ValueError("error message is None. If result is false, errorMessage is required.")

        self.result = result
        self.error_code = error_code
        self.error_message = error_message

    def __eq__(self, other) -> bool:
        if self is other:
            return True

        if other is None or self.__class__ != other.__class__:
            return False

        return (
            self.result == other.result
            and self.error_code == other.error_code
            and self.error_message == other.error_message
        )
