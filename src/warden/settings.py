"""Central configuration for Warden.

Everything that depends on the environment (API keys, model choice, feature
toggles) is read here in ONE place, so the rest of the code never touches
os.environ directly. That keeps the pipeline testable and makes it obvious
what the program is allowed to read from its environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Load variables from a local .env file (if present) into os.environ.
# This is a no-op in production where real env vars are already set.
load_dotenv()


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Immutable snapshot of configuration, resolved once at startup."""

    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    model: str = os.getenv("WARDEN_MODEL", "gpt-4o-mini")
    use_fake_llm: bool = _as_bool(os.getenv("WARDEN_FAKE_LLM"), default=False)
    temperature: float = float(os.getenv("WARDEN_TEMPERATURE", "0.0"))


# A single shared instance the rest of the app imports.
settings = Settings()
