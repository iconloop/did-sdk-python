from typing import Union

from pydantic import BaseSettings


class DidSettings(BaseSettings):
    DIDSDK_PROJECT_NAME: str = "did-sdk-python"
    DIDSDK_TX_RETRY_COUNT: int = 5
    # Second
    DIDSDK_TX_SLEEP_TIME: Union[int, float] = 1
    DIDSDK_LOG_ENABLE_LOGGER: bool = False

    class Config:
        case_sensitive = True


settings = DidSettings()
