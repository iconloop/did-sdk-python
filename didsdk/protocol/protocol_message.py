import dataclasses
import json
import time
from dataclasses import dataclass
from typing import Optional, Union

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from joserfc import jwe
from joserfc.jwk import JWKRegistry
from joserfc.rfc7518.ec_key import CURVES_DSS, ECBinding, ECDictKey, ECKey
from joserfc.util import int_to_base64
from loguru import logger

from didsdk.core.did_key_holder import DidKeyHolder
from didsdk.core.property_name import PropertyName
from didsdk.credential import Credential, CredentialVersion
from didsdk.document.encoding import Base64URLEncoder
from didsdk.exceptions import JweException, JwtException
from didsdk.jwe.ecdhkey import ECDHKey
from didsdk.jwe.ephemeral_publickey import EphemeralPublicKey
from didsdk.jwt.elements import HeaderAlgorithmType
from didsdk.jwt.jwt import Jwt
from didsdk.presentation import Presentation
from didsdk.protocol.base_param import BaseParam
from didsdk.protocol.claim_request import ClaimRequest
from didsdk.protocol.claim_response import ClaimResponse
from didsdk.protocol.json_ld.json_ld_param import JsonLdParam
from didsdk.protocol.protocol_type import ProtocolType


@dataclass
class SignResult:
    success: bool = False
    result: Optional[dict] = None
    fail_message: str = None


class P256KECBinding(ECBinding):
    """WARNING: This class is patch for P-256K curve name binding secp256k1

    If P-256K curve name removed, this class no more needed.
    """

    @staticmethod
    def export_private_key(key: EllipticCurvePrivateKey) -> ECDictKey:
        def get_crv_name(curve_name: str) -> str:
            if curve_name == "secp256k1":
                return "P-256K"
            else:
                return CURVES_DSS[curve_name]

        numbers = key.private_numbers()

        return {
            "crv": get_crv_name(key.curve.name),
            "x": int_to_base64(numbers.public_numbers.x),
            "y": int_to_base64(numbers.public_numbers.y),
            "d": int_to_base64(numbers.private_value),
        }


ECKey.binding = P256KECBinding


class ProtocolMessage:
    def __init__(
        self,
        type_: str,
        protected_message: str = None,
        plain_message: str = None,
        param: Union[str, BaseParam] = None,
        param_string: str = None,
        is_protected: bool = None,
        credential: Credential = None,
        presentation: Presentation = None,
        claim_request: ClaimRequest = None,
        claim_response: ClaimResponse = None,
        issued: int = None,
        expiration: int = None,
        request_public_key: EphemeralPublicKey = None,
        is_decrypted: bool = None,
    ):
        if not type_:
            raise ValueError("type cannot be emptied.")

        self._type: str = type_
        self._protected_message: str = protected_message
        self._plain_message: str = plain_message
        self._claim_request: Optional[ClaimRequest] = claim_request
        self._claim_response: Optional[ClaimResponse] = claim_response
        self._credential: Optional[Credential] = credential
        self._presentation: Optional[Presentation] = presentation
        self._param_string: str = param_string
        self._param: Union[str, BaseParam] = param
        self._ld_param: Optional[JsonLdParam] = None
        self._issued: int = issued
        self._expiration: int = expiration
        self._request_public_key: EphemeralPublicKey = request_public_key
        self._jwe: Optional[str] = None
        self._jwt: Optional[Jwt] = None
        self._is_protected: bool = is_protected if is_protected else False
        self._is_decrypted: bool = is_decrypted if is_decrypted else False

    @property
    def base_param(self) -> BaseParam:
        return self._param

    @property
    def claim_request(self) -> ClaimRequest:
        if self._is_decrypted:
            if ProtocolType.is_request_member(self._type):
                if not self._claim_request:
                    self._claim_request = ClaimRequest.from_jwt(self._jwt)
                return self._claim_request
            else:
                raise JweException("This is not request message.")
        else:
            raise JweException("It is not yet decrypted.")

    @property
    def claim_response(self) -> ClaimResponse:
        if self._is_decrypted:
            if ProtocolType.is_response_member(self._type):
                if not self._claim_response:
                    self._claim_response = ClaimResponse.from_jwt(self._jwt)
                return self._claim_response
            else:
                raise JweException("This is not response message.")
        else:
            raise JweException("It is not yet decrypted.")

    @property
    def credential(self) -> Credential:
        if self._is_decrypted:
            if ProtocolType.is_credential_member(self._type):
                if not self._credential:
                    self._claim_response = Credential.from_jwt(self._jwt)
                return self._credential
            else:
                raise JweException("This is not credential message.")
        else:
            raise JweException("It is not yet decrypted.")

    @property
    def is_protected(self) -> bool:
        return self._is_protected

    @property
    def jwe(self) -> Optional[str]:
        return self._jwe

    @property
    def jwt(self) -> Jwt:
        return self._jwt

    @property
    def jwt_token(self) -> Optional[str]:
        return None if self._is_protected else self._plain_message

    @property
    def ld_param(self) -> JsonLdParam:
        return self._ld_param

    @property
    def message(self) -> str:
        return self._protected_message if self._is_protected else self._plain_message

    @property
    def param_string(self) -> str:
        return self._param_string

    @property
    def presentation(self) -> Presentation:
        if self._is_decrypted:
            if ProtocolType.is_presentation_member(self._type):
                if not self._presentation:
                    self._presentation = Presentation.from_jwt(self._jwt)
                return self._presentation
            else:
                raise JweException("This is not presentation message.")
        else:
            raise JweException("It is not yet decrypted.")

    @property
    def type(self) -> str:
        return self._type

    def decrypt_jwe(self, my_key: ECDHKey, encoding="utf-8"):
        if self._is_decrypted:
            raise JweException("Already has decrypted JWE token.")
        if not my_key:
            raise JweException("ECDH key cannot be None.")

        try:
            key = JWKRegistry.import_key(dataclasses.asdict(my_key))
            decrypted = jwe.decrypt_compact(self.jwe, key)
        except Exception as e:
            raise JweException(f"JWE decryption is failed. {e}")

        payload: dict = json.loads(decrypted.plaintext.decode())
        logger.debug(f">>>decoded jwt: {payload}")
        self._plain_message = payload[PropertyName.KEY_PROTOCOL_MESSAGE]
        self._param_string = payload.get(PropertyName.KEY_PROTOCOL_PARAM)
        self._is_decrypted = True
        self._is_protected = False
        self._jwt = Jwt.decode(self._plain_message)
        logger.debug(f">>>decoded payload: {self._jwt.payload.as_dict()}")

        if ProtocolType.is_request_member(self._type):
            if self._type == ProtocolType.REQUEST_PRESENTATION.value:
                self._claim_request = ClaimRequest.for_presentation_from_jwt(self._jwt)
            else:
                self._claim_request = ClaimRequest.from_jwt(self._jwt)
        elif ProtocolType.is_credential_member(self._type):
            self._credential = Credential.from_jwt(self._jwt)
            if self._param_string:
                if self._credential.version == CredentialVersion.v1_1:
                    param_string = Base64URLEncoder.decode(self._param_string).decode(encoding)
                    self._param = BaseParam(**json.loads(param_string))
                elif self._credential.version == CredentialVersion.v2_0:
                    self._ld_param = JsonLdParam.from_encoded_param(self._param_string)
        elif ProtocolType.is_presentation_member(self._type):
            self._presentation = Presentation.from_encoded_jwt(self._plain_message)
        elif ProtocolType.is_response_member(self._type):
            self._claim_response = ClaimResponse.from_jwt(self._jwt)

    @classmethod
    def from_(
        cls,
        type_: str,
        message: str = None,
        param: str = None,
        is_protected: bool = None,
    ) -> "ProtocolMessage":
        protocol_message = cls(type_, is_protected=is_protected)

        if is_protected:
            protocol_message._protected_message = message
            protocol_message._jwe = message
        else:
            protocol_message._plain_message = message
            protocol_message._jwt = Jwt.decode(message)

            version: str = ""
            if ProtocolType.is_request_member(value=type_):
                version = protocol_message._jwt.payload.version
                if type_ == ProtocolType.REQUEST_PRESENTATION.value and version == CredentialVersion.v2_0:
                    protocol_message._claim_request = ClaimRequest.for_presentation_from_jwt(protocol_message._jwt)
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
            if protocol_message._param_string:
                if version == CredentialVersion.v1_1:
                    protocol_message._param = Base64URLEncoder.decode(param)
                elif version == CredentialVersion.v2_0:
                    protocol_message._ld_param = JsonLdParam.from_encoded_param(param)
                else:
                    raise ValueError("version cannot be emptied.")

            protocol_message._is_decrypted = True

        return protocol_message

    @classmethod
    def from_json(cls, json_data: dict) -> "ProtocolMessage":
        type_ = json_data.get(PropertyName.KEY_PROTOCOL_TYPE)
        param = None
        is_protected = False

        if PropertyName.KEY_PROTOCOL_PROTECTED in json_data:
            message = json_data[PropertyName.KEY_PROTOCOL_PROTECTED]
            is_protected = True
        else:
            if PropertyName.KEY_PROTOCOL_MESSAGE not in json_data:
                raise JweException(f"{PropertyName.KEY_PROTOCOL_MESSAGE} is None.")

            message = json_data[PropertyName.KEY_PROTOCOL_MESSAGE]
            param = json_data.get(PropertyName.KEY_PROTOCOL_PARAM)

        if not message:
            raise JwtException('One of "protected" or "message" must be filled.')

        return cls.from_(type_=type_, message=message, param=param, is_protected=is_protected)

    @classmethod
    def _for_decrypted_state(
        cls,
        protocol_type: ProtocolType,
        issued: int,
        expiration: int,
        request_public_key: EphemeralPublicKey = None,
        credential: Credential = None,
        presentation: Presentation = None,
        claim_request: ClaimRequest = None,
        claim_response: ClaimResponse = None,
        protected_message: str = None,
    ) -> "ProtocolMessage":
        if not protocol_type:
            raise ValueError("protocol_type cannot be emptied.")

        return cls(
            type_=protocol_type.value,
            credential=credential,
            presentation=presentation,
            claim_request=claim_request,
            claim_response=claim_response,
            protected_message=protected_message,
            issued=issued,
            expiration=expiration,
            request_public_key=request_public_key,
            is_decrypted=True,
        )

    @classmethod
    def for_credential(
        cls,
        protocol_type: ProtocolType,
        credential: Credential,
        issued: int,
        expiration: int,
        request_public_key: EphemeralPublicKey,
    ) -> "ProtocolMessage":
        if not protocol_type.is_credential():
            raise ValueError(
                "type must be a type of "
                "[RESPONSE_CREDENTIAL, RESPONSE_CREDENTIAL_OLD, RESPONSE_PROTECTED_CREDENTIAL]"
            )

        return cls._for_decrypted_state(
            protocol_type=protocol_type,
            credential=credential,
            issued=issued,
            expiration=expiration,
            request_public_key=request_public_key,
        )

    @classmethod
    def for_presentation(
        cls,
        protocol_type: ProtocolType,
        presentation: Presentation = None,
        issued: int = None,
        expiration: int = None,
        request_public_key: EphemeralPublicKey = None,
    ) -> "ProtocolMessage":
        if not protocol_type.is_presentation():
            raise ValueError(
                "type must be a type of "
                "[RESPONSE_PRESENTATION, RESPONSE_PRESENTATION_OLD, RESPONSE_PROTECTED_PRESENTATION]"
            )

        return cls._for_decrypted_state(
            protocol_type=protocol_type,
            presentation=presentation,
            issued=issued,
            expiration=expiration,
            request_public_key=request_public_key,
        )

    @classmethod
    def for_request(
        cls,
        protocol_type: ProtocolType,
        claim_request: ClaimRequest = None,
        issued: int = None,
        expiration: int = None,
        request_public_key: EphemeralPublicKey = None,
    ) -> "ProtocolMessage":
        if not protocol_type.is_request():
            raise ValueError(
                "type must be a type of " "[REQUEST_CREDENTIAL, REQUEST_PRESENTATION, REQUEST_REVOCATION, DID_INIT]"
            )

        return cls._for_decrypted_state(
            protocol_type=protocol_type,
            claim_request=claim_request,
            issued=issued,
            expiration=expiration,
            request_public_key=request_public_key,
        )

    @classmethod
    def for_response(
        cls,
        protocol_type: ProtocolType,
        claim_response: ClaimResponse = None,
        issued: int = None,
        expiration: int = None,
        request_public_key: EphemeralPublicKey = None,
    ) -> "ProtocolMessage":
        if not protocol_type.is_response():
            raise ValueError("type must be a type of [CREDENTIAL_RESULT, RESPONSE_REVOCATION, DID_AUTH]")

        return cls._for_decrypted_state(
            protocol_type=protocol_type,
            claim_response=claim_response,
            issued=issued,
            expiration=expiration,
            request_public_key=request_public_key,
        )

    @classmethod
    def for_revocation(cls, protected_message: str, issued: int = None, expiration: int = None) -> "ProtocolMessage":
        if not issued:
            issued = int(time.time())
        if not expiration:
            expiration = issued * 2

        return cls._for_decrypted_state(
            protocol_type=ProtocolType.REQUEST_REVOCATION,
            protected_message=protected_message,
            issued=issued,
            expiration=expiration,
        )

    def sign_encrypt(self, did_key_holder: Optional[DidKeyHolder], ecdh_key: Optional[ECDHKey] = None) -> SignResult:
        if not did_key_holder and self._type != ProtocolType.REQUEST_PRESENTATION.value:
            return SignResult(fail_message="DidKeyHolder is required for sign.")

        if ProtocolType.is_request_member(self._type):
            self._plain_message = (
                did_key_holder.sign(self._claim_request.jwt) if did_key_holder else self._claim_request.compact
            )
        elif ProtocolType.is_credential_member(self._type):
            self._plain_message = did_key_holder.sign(self._credential.as_jwt(self._issued, self._expiration))
            if self._credential.version == CredentialVersion.v1_1:
                self._param = self._credential.base_claim.attribute.base_param
                param: dict = dataclasses.asdict(self._param)
                self._param_string = Base64URLEncoder.encode(json.dumps(param).encode("utf-8"))
            elif self._credential.version == CredentialVersion.v2_0:
                self._ld_param = self._credential.param
                self._param_string = self._ld_param.as_base64_url_string()
        elif ProtocolType.is_presentation_member(self._type):
            self._plain_message = did_key_holder.sign(self._presentation.as_jwt(self._issued, self._expiration))
        elif ProtocolType.is_response_member(self._type):
            self._plain_message = did_key_holder.sign(self._claim_response.jwt)
        else:
            return SignResult(fail_message=f"Type({self._type}) is cannot sign.")

        self._jwt = Jwt.decode(self._plain_message)
        logger.debug(f">>>jwt header:{self._jwt.header.as_dict()}")
        logger.debug(f">>>jwt payload:{self._jwt.payload.as_dict()}")
        if self._request_public_key:
            if not ecdh_key:
                return SignResult(fail_message="Issuer's ECDH PrivateKey is required for createJwe.")

            decoded_message = dict()
            decoded_message[PropertyName.KEY_PROTOCOL_MESSAGE] = self._plain_message
            if self._param_string:
                decoded_message[PropertyName.KEY_PROTOCOL_PARAM] = self._param_string

            jwe_header = {
                "kid": self._request_public_key.kid,
                "alg": HeaderAlgorithmType.JWE_ALGO_ECDH_ES,
                "enc": HeaderAlgorithmType.JWE_ALGO_A128GCM,
            }

            recipient = JWKRegistry.import_key(self._request_public_key.epk.as_dict_without_kid())
            logger.debug(f">>>before decrypt: {decoded_message}")
            encrypted = jwe.encrypt_compact(jwe_header, json.dumps(decoded_message), recipient)
            result = {
                PropertyName.KEY_PROTOCOL_TYPE: self._type,
                PropertyName.KEY_PROTOCOL_PROTECTED: encrypted,
            }
        else:
            result = {
                PropertyName.KEY_PROTOCOL_TYPE: self._type,
                PropertyName.KEY_PROTOCOL_MESSAGE: self._plain_message,
            }

            if self._param_string:
                result[PropertyName.KEY_PROTOCOL_PARAM] = self._param_string

        return SignResult(success=True, result=result)

    def get_message_with_param(self) -> dict:
        if not self._param_string:
            raise ValueError("param string is empty.")

        return {
            PropertyName.KEY_PROTOCOL_MESSAGE: self.jwt_token,
            PropertyName.KEY_PROTOCOL_PARAM: self._param_string,
        }
