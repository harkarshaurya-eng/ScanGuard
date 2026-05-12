"""Configuration models and helpers."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from recon_ai.constants import (
    CONFIG_ROOT,
    DEFAULT_GROQ_BASE_URL,
    DEFAULT_GROQ_MODEL,
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_USER_SYSTEM_PROMPT,
    DEFAULT_WORKSPACE_ROOT,
    PROMPT_PATH,
)


class AppSettings(BaseSettings):
    """Environment-backed application settings."""

    model_config = SettingsConfigDict(
        env_prefix="RECON_AI_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    groq_api_key: str | None = Field(default=None, validation_alias="GROQ_API_KEY")
    groq_model: str = Field(default=DEFAULT_GROQ_MODEL, validation_alias="GROQ_MODEL")
    groq_base_url: str = Field(default=DEFAULT_GROQ_BASE_URL, validation_alias="GROQ_BASE_URL")
    auto_safe: bool = False
    workspace_root: Path = DEFAULT_WORKSPACE_ROOT
    http_timeout_seconds: int = DEFAULT_HTTP_TIMEOUT_SECONDS
    log_level: str = "INFO"
    sqlite_busy_timeout_ms: int = 5000


class RuntimeProfile(BaseModel):
    """Runtime execution controls."""

    auto_safe: bool = False
    baseline_timeout_seconds: int = 900
    chat_timeout_seconds: int = 1200


class PromptBundle(BaseModel):
    immutable_safety_prompt: str
    user_editable_system_prompt: str
    tool_policy_prompt: str
    project_context_prompt: str
    current_user_message: str


def ensure_user_prompt() -> Path:
    """Create the user-editable system prompt if missing."""
    CONFIG_ROOT.mkdir(parents=True, exist_ok=True)
    if not PROMPT_PATH.exists():
        PROMPT_PATH.write_text(DEFAULT_USER_SYSTEM_PROMPT + "\n", encoding="utf-8")
    return PROMPT_PATH


def load_user_prompt() -> str:
    """Load the editable prompt."""
    prompt_path = ensure_user_prompt()
    return prompt_path.read_text(encoding="utf-8").strip()


def ensure_env_file(base_dir: Path) -> Path:
    """Create a local .env file if needed."""
    env_path = base_dir / ".env"
    if not env_path.exists():
        env_path.write_text(
            "\n".join(
                [
                    "GROQ_API_KEY=",
                    f"GROQ_MODEL={DEFAULT_GROQ_MODEL}",
                    f"GROQ_BASE_URL={DEFAULT_GROQ_BASE_URL}",
                    "RECON_AI_AUTO_SAFE=false",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    return env_path

