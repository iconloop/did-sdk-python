import time

from iconsdk.builder.call_builder import Call, CallBuilder
from iconsdk.builder.transaction_builder import CallTransaction, CallTransactionBuilder
from iconsdk.icon_service import IconService


class DidScore:
    def __init__(self, iconservice: IconService, network_id: int, score_address: str):
        self._iconservice = iconservice
        self._network_id = network_id
        self._score_address = score_address

    def _build_call(self, method: str, from_address: str = None, params=None) -> Call:
        builder = CallBuilder(from_=from_address, to=self._score_address, method=method, params=params)
        return builder.build()

    def _build_transaction(self, from_address, method, params) -> CallTransaction:
        timestamp = int(time.time() * 1_000_000)
        builder = CallTransactionBuilder(nid=self._network_id,
                                         from_=from_address,
                                         to=self._score_address,
                                         step_limit=2000000,
                                         timestamp=timestamp,
                                         method=method,
                                         params=params)
        return builder.build()

    def create(self, from_address: str, public_key: str) -> CallTransaction:
        params = {'publicKey': public_key}
        return self._build_transaction(from_address, method='create', params=params)

    def get_did(self, from_address: str) -> dict:
        call = self._build_call(from_address=from_address, method='getDid')
        return self._iconservice.call(call)

    def get_did_document(self, did: str) -> dict:
        params = {'did': did}
        call = self._build_call(method='read', params=params)
        return self._iconservice.call(call)

    def get_version(self) -> str:
        call = self._build_call(method='getVersion')
        return self._iconservice.call(call)

    def jwtMethod(self, from_address: str, method: str, jwt: str) -> CallTransaction:
        params = {'jwt': jwt}
        return self._build_transaction(from_address, method=method, params=params)
