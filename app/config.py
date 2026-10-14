"""Settings read from the environment. No defaults for secrets: fail closed."""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ConfigError(f"missing required setting {name}")
    return value


@dataclass(frozen=True)
class Settings:
    database_url: str
    token_secret: str
    webhook_secret: str
    webhook_tolerance_s: int = 300


def load() -> Settings:
    return Settings(
        database_url=_required("DATABASE_URL"),
        token_secret=_required("TOKEN_SECRET"),
        webhook_secret=_required("PAYMENT_WEBHOOK_SECRET"),
        webhook_tolerance_s=int(os.environ.get("PAYMENT_WEBHOOK_TOLERANCE_S", "300")),
    )
