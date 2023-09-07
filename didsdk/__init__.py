from loguru import logger

from didsdk.config import settings

if settings.LOG_ENABLE_DID_LOGGER:
    logger.enable(__name__)
else:
    logger.disable(__name__)

logger.debug(f"LOG_ENABLE_DID_LOGGER is {settings.LOG_ENABLE_DID_LOGGER}")
logger.debug(f"{settings.__repr_name__()}: {settings.dict()}")
