from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    text: str = Field(min_length=1, max_length=1500)

    @field_validator("text")
    @classmethod
    def _trim_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Message cannot be empty")
        return value


class GuidanceChatRequest(BaseModel):
    messages: list[ChatTurn] = Field(min_length=1, max_length=12)


class GuidanceChatResponse(BaseModel):
    answer: str
    provider: Literal["gemini", "rules"]
    model: str | None = None


class GuidanceStatus(BaseModel):
    provider: Literal["gemini", "rules"]
    model: str | None = None
