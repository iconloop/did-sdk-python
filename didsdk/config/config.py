from loguru import logger
from pydantic import BaseSettings

PROJECT_NAME = "did-sdk-python"

DEFAULT_LOG_LEVEL = "TRACE"
DEFAULT_LOG_FILE = "logs/backend.log"
DEFAULT_LOG_ROTATION = "daily"
DEFAULT_LOG_RETENTION = "1 months"
DEFAULT_LOG_COMPRESSION = "tar.gz"


class Settings(BaseSettings):
    PROJECT_NAME: str = PROJECT_NAME

    LOG_LEVEL: str = DEFAULT_LOG_LEVEL
    LOG_FILE: str = DEFAULT_LOG_FILE
    LOG_ROTATION: str
    LOG_RETENTION: str
    LOG_COMPRESSION: str

    class Config:
        case_sensitive = True


DEFAULT_DID_NETWORK_ID: int = 4424297
DEFAULT_ICONSERVICE_VERSION: int = 3
DEFAULT_DID_SERVICE_TIMEOUT: int = 600


settings = Settings()
logger.debug(f"{settings.__name__}: {settings.dict()}")
