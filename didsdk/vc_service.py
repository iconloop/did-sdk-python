import asyncio
from typing import List

from coincurve import PrivateKey
from iconsdk.exception import JSONRPCException
from iconsdk.icon_service import IconService
from iconsdk.signed_transaction import SignedTransaction, Transaction
from iconsdk.wallet.wallet import KeyWallet, Wallet
from loguru import logger

from didsdk import settings
from didsdk.exceptions import TransactionException, VCException
from didsdk.score.vc_score import VCScore


class VCService:
    """This class use to enable the full functionality of verifiable Credentials on a icon blockchain network.

    In order to register and revoke verifiable credentials,
    a transaction is required and this class uses `iconsdk.icon_service.IconService`.
    https://github.com/icon-project/icon-sdk-python
    """

    def __init__(self, iconservice: IconService, network_id: int, score_address: str, timeout: int = 15_000):
        """Create the instance.

        :param iconservice: the IconService object.
        :param network_id: the network ID of the blockchain.
        :param score_address: the vc score address deployed to the blockchain.
        :param timeout: the specified timeout, in milliseconds.
        """
        self._iconservice: IconService = iconservice
        self._network_id: int = network_id
        self._vc_score: VCScore = VCScore(self._iconservice, self._network_id, score_address)
        self._timeout: int = timeout

    async def _get_transaction_result(self, tx_hash: str) -> dict:
        response = None
        retry_times = settings.DIDSDK_TX_RETRY_COUNT
        while response is None and retry_times > 0:
            try:
                tx_result = self._iconservice.get_transaction_result(tx_hash)
                if not tx_result:
                    raise JSONRPCException("transaction result is None.")
            except JSONRPCException as e:
                logger.debug(f"{e}")

                if retry_times == 0:
                    raise TransactionException(e)

                retry_times -= 1
                logger.debug(f"Remain to retry request for getting transaction result: {retry_times}")

                await asyncio.sleep(settings.DIDSDK_TX_SLEEP_TIME)
                continue

            return tx_result

    def _send_transaction(self, transaction: Transaction, wallet: Wallet) -> str:
        """Sends a transaction.

        :param transaction: the Transaction object.
        :param wallet: the wallet for transaction.
        :return: the hash of transaction.
        """
        signed_tx = SignedTransaction(transaction, wallet)
        return self._iconservice.send_transaction(signed_tx)

    async def register(
        self,
        wallet: KeyWallet,
        credential: str,
        private_key: PrivateKey,
    ) -> dict:
        """Register VC

        :param wallet: the wallet for transaction
        :param credential: signed credential
        :param private_key: Key to sign credential
        :return: the Document object
        """
        transaction = self._vc_score.register(wallet.get_address(), credential, private_key)
        tx_hash = self._send_transaction(transaction, wallet)
        tx_result = await asyncio.wait_for(self._get_transaction_result(tx_hash), timeout=self._timeout)
        if tx_result["status"] != 1:
            raise VCException(tx_result["failure"]["message"])
        return tx_result

    async def register_list(
        self,
        wallet: KeyWallet,
        credential_list: List[str],
        private_key: PrivateKey,
    ) -> dict:
        """Register VC list

        :param wallet: the wallet for transaction
        :param credential_list: signed credential list
        :param private_key: Key to sign credential
        :return: the Document object
        """
        transaction = self._vc_score.register_list(wallet.get_address(), credential_list, private_key)
        tx_hash = self._send_transaction(transaction, wallet)
        tx_result = await asyncio.wait_for(self._get_transaction_result(tx_hash), timeout=self._timeout)
        if tx_result["status"] != 1:
            raise VCException(tx_result["failure"]["message"])
        return tx_result

    async def revoke(self, wallet: KeyWallet, credential: str, issuer_did: str, private_key: PrivateKey) -> dict:
        """revoke vc

        :param wallet: the wallet for transaction
        :param credential: registered credential
        :param issuer_did: the issuer did
        :param private_key: Key to sign credential
        """

        transaction = self._vc_score.revoke(
            from_address=wallet.get_address(), credential=credential, issuer_did=issuer_did, private_key=private_key
        )
        tx_hash = self._send_transaction(transaction, wallet)
        tx_result = await asyncio.wait_for(self._get_transaction_result(tx_hash), timeout=self._timeout)
        if tx_result["status"] != 1:
            raise VCException(tx_result["failure"]["message"])
        return tx_result

    async def revoke_did(self, wallet: KeyWallet, credential: str, issuer_did: str, private_key: PrivateKey) -> dict:
        """revoke did

        :param wallet: the wallet for transaction
        :param credential: registered credential
        :param issuer_did: the issuer did
        :param private_key: Key to sign credential
        """

        transaction = self._vc_score.revoke_did(
            from_address=wallet.get_address(), credential=credential, issuer_did=issuer_did, private_key=private_key
        )
        tx_hash = self._send_transaction(transaction, wallet)
        tx_result = await asyncio.wait_for(self._get_transaction_result(tx_hash), timeout=self._timeout)
        if tx_result["status"] != 1:
            raise VCException(tx_result["failure"]["message"])
        return tx_result

    async def revoke_vc_and_did(
        self, wallet: KeyWallet, credential: str, issuer_did: str, private_key: PrivateKey
    ) -> dict:
        """revoke vc and did

        :param wallet: the wallet for transaction
        :param credential: registered credential
        :param issuer_did: the issuer did
        :param private_key: Key to sign credential
        """

        transaction = self._vc_score.revoke_vc_and_did(
            from_address=wallet.get_address(), credential=credential, issuer_did=issuer_did, private_key=private_key
        )
        tx_hash = self._send_transaction(transaction, wallet)
        tx_result = await asyncio.wait_for(self._get_transaction_result(tx_hash), timeout=self._timeout)
        if tx_result["status"] != 1:
            raise VCException(tx_result["failure"]["message"])
        return tx_result

    def get(self, sig: str) -> dict:
        """Get the registered VC info"""

        return self._vc_score.get(sig)

    def is_valid(self, sig: str) -> str:
        """Check the registered VC info's status

        :param sig: credential signature
        """
        return self._vc_score.is_valid(sig)

    def get_undertaker_list(self):
        """Get the undertaker list"""

        return self._vc_score.get_undertaker_list()

    def get_reject_history(self, vc_id: str):
        """Get the rejected VC info

        :param vc_id: rejected vc ID
        """
        return self._vc_score.get_reject_history(vc_id)
