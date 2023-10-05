from iconsdk.icon_service import IconService
from iconsdk.providers.http_provider import HTTPProvider


class IconServiceFactory:
    LOCAL_BASE_DOMAIN = "http://127.0.0.1:9000"
    TESTNET_BASE_DOMAIN = "https://lisbon.net.solidwallet.io"
    VERSION = 3

    @staticmethod
    def create(url: str, version: int) -> IconService:
        return IconService(IconServiceFactory._create_http_provider(url, version))

    @staticmethod
    def create_local() -> IconService:
        return IconServiceFactory.create(IconServiceFactory.LOCAL_BASE_DOMAIN, IconServiceFactory.VERSION)

    @staticmethod
    def create_testnet() -> IconService:
        return IconServiceFactory.create(IconServiceFactory.TESTNET_BASE_DOMAIN, IconServiceFactory.VERSION)

    @staticmethod
    def _create_http_provider(base_domain_url: str, version: int) -> HTTPProvider:
        return HTTPProvider(base_domain_url, version)
