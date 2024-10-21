from cryptography.hazmat.primitives.asymmetric.ec import SECP256K1
from joserfc.jws import JWSRegistry
from joserfc.rfc7518.ec_key import CURVES_DSS, DSS_CURVES
from joserfc.rfc7518.jws_algs import ECAlgModel
from loguru import logger

from didsdk.config import settings

if settings.DIDSDK_LOG_ENABLE_LOGGER:
    logger.enable(__name__)
else:
    logger.disable(__name__)

logger.debug(f"{settings.DIDSDK_LOG_ENABLE_LOGGER=}")
logger.debug(f"{settings.__repr_name__()}: {settings.dict()}")


def register_p_256k():
    JWSRegistry.register(ECAlgModel("ES256K", "P-256K", 256))
    DSS_CURVES["P-256K"] = SECP256K1
    CURVES_DSS["P-256K"] = "secp256k1"


register_p_256k()
