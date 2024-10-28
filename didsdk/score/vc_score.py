import time
from typing import List

from coincurve import PrivateKey
from iconsdk.builder.call_builder import Call, CallBuilder
from iconsdk.builder.transaction_builder import CallTransaction, CallTransactionBuilder
from iconsdk.icon_service import IconService

from didsdk.score import vc_score_parameter


class VCScore:
    def __init__(self, iconservice: IconService, network_id: int, score_address: str):
        self._iconservice: IconService = iconservice
        self._network_id: int = network_id
        self._score_address: str = score_address

    def _build_call(self, method: str, from_address: str = None, params=None) -> Call:
        builder = CallBuilder(from_=from_address, to=self._score_address, method=method, params=params)
        return builder.build()

    def _build_transaction(self, from_address: str, method: str, params: dict) -> CallTransaction:
        timestamp = int(time.time() * 1_000_000)
        builder = CallTransactionBuilder(
            nid=self._network_id,
            from_=from_address,
            to=self._score_address,
            step_limit=5_000_000,
            timestamp=timestamp,
            method=method,
            params=params,
        )
        return builder.build()

    def register(
        self,
        from_address: str,
        credential: str,
        private_key: PrivateKey,
    ) -> CallTransaction:
        credential_jwt: str = vc_score_parameter.register_jwt(credential, private_key)
        params = {"credentialJwt": credential_jwt}
        return self._build_transaction(from_address, method="register", params=params)

    def register_list(
        self,
        from_address: str,
        signed_credentials: List[str],
        private_key: PrivateKey,
    ) -> CallTransaction:
        credential_list = [
            vc_score_parameter.register_jwt(credential, private_key) for credential in signed_credentials
        ]
        params = {"credentialJwtList": ",".join(credential_list)}
        return self._build_transaction(from_address, method="registerList", params=params)

    def revoke(self, from_address: str, credential: str, issuer_did: str, private_key: PrivateKey) -> CallTransaction:
        credential_jwt: str = vc_score_parameter.revoke_jwt(credential, issuer_did, private_key)
        params = {"credentialJwt": credential_jwt}
        return self._build_transaction(from_address, method="revoke", params=params)

    def revoke_did(
        self, from_address: str, credential: str, issuer_did: str, private_key: PrivateKey
    ) -> CallTransaction:
        credential_jwt: str = vc_score_parameter.revoke_jwt(credential, issuer_did, private_key)
        params = {"credentialJwt": credential_jwt}
        return self._build_transaction(from_address, method="revokeDid", params=params)

    def revoke_vc_and_did(
        self, from_address: str, credential: str, issuer_did: str, private_key: PrivateKey
    ) -> CallTransaction:
        credential_jwt: str = vc_score_parameter.revoke_jwt(credential, issuer_did, private_key)
        params = {"credentialJwt": credential_jwt}
        return self._build_transaction(from_address, method="revokeVcAndDid", params=params)

    def get(self, sig: str) -> dict:
        params = {"sig": sig}
        call = self._build_call(method="get", params=params)
        return self._iconservice.call(call)

    def is_valid(self, sig: str) -> str:
        params = {"sig": sig}
        call = self._build_call(method="isValid", params=params)
        return self._iconservice.call(call)

    def get_undertaker_list(self) -> str:
        params = {}
        call = self._build_call(method="getUndertakerList", params=params)
        return self._iconservice.call(call)

    def get_reject_history(self, vc_id: str) -> str:
        params = {"vcId": vc_id}
        call = self._build_call(method="getRejectHistory", params=params)
        return self._iconservice.call(call)
