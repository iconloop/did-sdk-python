from pydantic import BaseSettings


class DidSettings(BaseSettings):
    PROJECT_NAME: str = "did-sdk-python"
    LOG_ENABLE_DID_LOGGER: bool = False

    class Config:
        case_sensitive = True


settings = DidSettings()
