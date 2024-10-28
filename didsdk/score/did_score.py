import time

from iconsdk.builder.call_builder import Call, CallBuilder
from iconsdk.builder.transaction_builder import CallTransaction, CallTransactionBuilder
from iconsdk.icon_service import IconService


class DidScore:
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

    def create(self, from_address: str, public_key: str) -> CallTransaction:
        params = {"publicKey": public_key}
        return self._build_transaction(from_address, method="create", params=params)

    def get_did(self, from_address: str) -> str:
        call = self._build_call(from_address=from_address, method="getDid")
        return self._iconservice.call(call)

    def get_did_document(self, did: str) -> dict:
        params = {"did": did}
        call = self._build_call(method="read", params=params)
        return self._iconservice.call(call)

    def get_version(self) -> str:
        call = self._build_call(method="getVersion")
        return self._iconservice.call(call)

    def jwt_method(self, from_address: str, method: str, jwt: str) -> CallTransaction:
        params = {"jwt": jwt}
        return self._build_transaction(from_address, method=method, params=params)
