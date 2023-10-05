from enum import Enum


class ProtocolType(Enum):
    # new
    DID_INIT = "did_init"
    DID_AUTH = "did_auth"
    REQUEST_CREDENTIAL = "request_credential"
    REQUEST_PRESENTATION = "request_presentation"
    RESPONSE_CREDENTIAL = "response_credential"
    RESPONSE_PRESENTATION = "response_presentation"
    CREDENTIAL_RESULT = "credential_result"
    REQUEST_REVOCATION = "request_revocation"
    RESPONSE_REVOCATION = "response_revocation"

    # old
    RESPONSE_CREDENTIAL_OLD = "credential"
    RESPONSE_PRESENTATION_OLD = "presentation"
    RESPONSE_PROTECTED_CREDENTIAL = "protected_credential"
    RESPONSE_PROTECTED_PRESENTATION = "protected_presentation"

    UNKNOWN = "unknown"

    def is_credential(self) -> bool:
        return self in [self.RESPONSE_CREDENTIAL, self.RESPONSE_CREDENTIAL_OLD, self.RESPONSE_PROTECTED_CREDENTIAL]

    def is_presentation(self) -> bool:
        return self in [
            self.RESPONSE_PRESENTATION,
            self.RESPONSE_PRESENTATION_OLD,
            self.RESPONSE_PROTECTED_PRESENTATION,
        ]

    def is_request(self) -> bool:
        return self in [self.REQUEST_CREDENTIAL, self.REQUEST_PRESENTATION, self.REQUEST_REVOCATION, self.DID_INIT]

    def is_response(self) -> bool:
        return self in [self.CREDENTIAL_RESULT, self.RESPONSE_REVOCATION, self.DID_AUTH]

    @classmethod
    def is_credential_member(cls, value: str) -> bool:
        return value in [
            cls.RESPONSE_CREDENTIAL.value,
            cls.RESPONSE_CREDENTIAL_OLD.value,
            cls.RESPONSE_PROTECTED_CREDENTIAL.value,
        ]

    @classmethod
    def is_presentation_member(cls, value: str) -> bool:
        return value in [
            cls.RESPONSE_PRESENTATION.value,
            cls.RESPONSE_PRESENTATION_OLD.value,
            cls.RESPONSE_PROTECTED_PRESENTATION.value,
        ]

    @classmethod
    def is_request_member(cls, value: str) -> bool:
        return value in [
            cls.REQUEST_CREDENTIAL.value,
            cls.REQUEST_PRESENTATION.value,
            cls.REQUEST_REVOCATION.value,
            cls.DID_INIT.value,
        ]

    @classmethod
    def is_response_member(cls, value: str) -> bool:
        return value in [cls.CREDENTIAL_RESULT.value, cls.RESPONSE_REVOCATION.value, cls.DID_AUTH.value]
