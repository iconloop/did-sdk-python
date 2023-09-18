from pydantic import BaseSettings


class DidSettings(BaseSettings):
    PROJECT_NAME: str = "did-sdk-python"
    TX_RETRY_COUNT: int = 5
    TX_SLEEP_TIME: int = 2
    LOG_ENABLE_DID_LOGGER: bool = False

    class Config:
        case_sensitive = True


settings = DidSettings()
