import json
from typing import Optional
from ecdsa import ECDH

from didsdk.credential import CredentialVersion, Credential
from didsdk.document.encoding import Base64URLEncoder
from didsdk.exceptions import JweException
from didsdk.jwe.ecdhkey import ECDHKey
from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.jwe.jwe import Jwe
from didsdk.jwt.jwt import Jwt
from didsdk.presentation import Presentation
from didsdk.protocol.claim_request import ClaimRequest
from didsdk.protocol.claim_response import ClaimResponse
from didsdk.protocol.json_ld.json_ld_param import JsonLdParam
from didsdk.protocol.protocol_type import ProtocolType


class ProtocolMessage:
    def __init__(self, type_: str,
                 protected_message: str = None,
                 plain_message: str = None,
                 param: str = None,
                 param_string: str = None,
                 is_protected: bool = None,
                 credential: Credential = None,
                 presentation: Presentation = None,
                 claim_request: ClaimRequest = None,
                 claim_response: ClaimResponse = None,
                 issued: int = None,
                 expiration: int = None,
                 request_public_key: EphemeralPublicKey = None,
                 is_decrypted: bool = None):

        if not type_:
            raise ValueError('type cannot be emptied.')

        self._type: str = type_
        self._protected_message: str = protected_message
        self._plain_message: str = plain_message
        self._claim_request: Optional[ClaimRequest] = claim_request
        self._claim_response: Optional[ClaimResponse] = claim_response
        self._credential: Optional[Credential] = credential
        self._presentation: Optional[Presentation] = presentation
        self._param_string: str = param_string
        self._param: str = param
        self._ld_param: Optional[JsonLdParam] = None
        self._issued: int = issued
        self._expiration: int = expiration
        self._request_public_key: EphemeralPublicKey = request_public_key
        self._jwe: Optional[Jwe] = None
        self._jwt: Optional[Jwt] = None
        self._is_protected: bool = is_protected if is_protected else False
        self._is_decrypted: bool = is_decrypted if is_decrypted else False

    @classmethod
    def from_(cls, type_: str, message: str = None, param: str = None, is_protected: bool = None) -> 'ProtocolMessage':
        protocol_message = cls(type_)

        if is_protected:
            protocol_message._protected_message = message
            protocol_message._jwe = Jwe.decode(message)
        else:
            protocol_message._plain_message = message
            protocol_message._jwt = Jwt.decode(message)

            version: str = ''
            if ProtocolType.is_request_member(value=type_):
                version = protocol_message._jwt.payload.version
                if type_ == ProtocolType.REQUEST_PRESENTATION.value and version == CredentialVersion.v2_0:
                    protocol_message._claim_request = ClaimRequest.from_presentation(protocol_message._jwt)
                else:
                    protocol_message._claim_request = ClaimRequest.from_jwt(protocol_message._jwt)
            elif ProtocolType.is_credential_member(value=type_):
                protocol_message._credential = Credential.from_jwt(protocol_message._jwt)
                version = protocol_message._credential.version
            elif ProtocolType.is_presentation_member(value=type_):
                protocol_message._presentation = Presentation.from_jwt(protocol_message._jwt)
                version = protocol_message._presentation.version
            elif ProtocolType.is_response_member(value=type_):
                protocol_message._claim_response = ClaimResponse.from_jwt(protocol_message._jwt)

            if param:
                protocol_message._param_string = param
                if version == CredentialVersion.v1_1:
                    protocol_message._param = Base64URLEncoder.decode(param)
                elif version == CredentialVersion.v2_0:
                    protocol_message._ld_param = JsonLdParam.from_encoded_param(param)
                else:
                    raise ValueError('version cannot be emptied.')

            protocol_message._is_decrypted = True

            return protocol_message

    @classmethod
    def _for(cls, protocol_type: ProtocolType, issued: int, expiration: int,
             request_public_key: EphemeralPublicKey = None,
             credential: Credential = None,
             presentation: Presentation = None,
             claim_request: ClaimRequest = None,
             claim_response: ClaimResponse = None) -> 'ProtocolMessage':

        if not protocol_type:
            raise ValueError('protocol_type cannot be emptied.')

        return cls(type_=protocol_type.value,
                   credential=credential,
                   presentation=presentation,
                   claim_request=claim_request,
                   claim_response=claim_response,
                   issued=issued,
                   expiration=expiration,
                   request_public_key=request_public_key,
                   is_decrypted=True)

    @classmethod
    def for_credential(cls, protocol_type: ProtocolType,
                       credential: Credential,
                       issued: int,
                       expiration: int,
                       request_public_key: EphemeralPublicKey) -> 'ProtocolMessage':

        if not protocol_type.is_response():
            raise ValueError('type must be a type of '
                             '[RESPONSE_CREDENTIAL, RESPONSE_CREDENTIAL_OLD, RESPONSE_PROTECTED_CREDENTIAL]')

        return cls._for(protocol_type=protocol_type,
                        credential=credential,
                        issued=issued,
                        expiration=expiration,
                        request_public_key=request_public_key)

    @classmethod
    def for_presentation(cls, protocol_type: ProtocolType,
                         presentation: Presentation = None,
                         issued: int = None,
                         expiration: int = None,
                         request_public_key: EphemeralPublicKey = None) -> 'ProtocolMessage':

        if not protocol_type.is_presentation():
            raise ValueError('type must be a type of '
                             '[RESPONSE_PRESENTATION, RESPONSE_PRESENTATION_OLD, RESPONSE_PROTECTED_PRESENTATION]')

        return cls._for(protocol_type=protocol_type,
                        presentation=presentation,
                        issued=issued,
                        expiration=expiration,
                        request_public_key=request_public_key)

    @classmethod
    def for_request(cls, protocol_type: ProtocolType,
                    claim_request: ClaimRequest = None,
                    issued: int = None,
                    expiration: int = None,
                    request_public_key: EphemeralPublicKey = None) -> 'ProtocolMessage':

        if not protocol_type.is_request():
            raise ValueError('type must be a type of '
                             '[REQUEST_CREDENTIAL, REQUEST_PRESENTATION, REQUEST_REVOCATION, DID_INIT]')

        return cls._for(protocol_type=protocol_type,
                        claim_request=claim_request,
                        issued=issued,
                        expiration=expiration,
                        request_public_key=request_public_key)

    @classmethod
    def for_response(cls, protocol_type: ProtocolType,
                     claim_response: ClaimResponse = None,
                     issued: int = None,
                     expiration: int = None,
                     request_public_key: EphemeralPublicKey = None) -> 'ProtocolMessage':

        if not protocol_type.is_response():
            raise ValueError('type must be a type of [CREDENTIAL_RESULT, RESPONSE_REVOCATION, DID_AUTH]')

        return cls._for(protocol_type=protocol_type,
                        claim_response=claim_response,
                        issued=issued,
                        expiration=expiration,
                        request_public_key=request_public_key)
