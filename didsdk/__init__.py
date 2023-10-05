from loguru import logger

from didsdk.config import settings

if settings.DIDSDK_LOG_ENABLE_LOGGER:
    logger.enable(__name__)
else:
    logger.disable(__name__)

logger.debug(f"{settings.DIDSDK_LOG_ENABLE_LOGGER=}")
logger.debug(f"{settings.__repr_name__()}: {settings.dict()}")
