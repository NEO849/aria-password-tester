"""Konfiguration via Umgebungsvariablen (.env).

Methoden-Übersicht:
  Settings.load()  -> liest .env und liefert konfiguriertes Settings-Objekt
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Zentrale Konfiguration, aus .env geladen."""
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"
    rate_limit: str = "30/minute"
    enable_hibp: bool = True
    cors_origins: str = "*"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def cors_list(self) -> list[str]:
        """Liefert CORS-Origins als Liste."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
