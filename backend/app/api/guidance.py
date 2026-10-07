from fastapi import APIRouter, Depends, Request

from app.core.config import get_settings
from app.core.limiter import limiter
from app.models import User
from app.schemas.guidance import GuidanceChatRequest, GuidanceChatResponse, GuidanceStatus
from app.security.deps import get_current_user
from app.services.guidance import answer

router = APIRouter(prefix="/api/guidance", tags=["guidance"])


@router.get("/status", response_model=GuidanceStatus)
def guidance_status(_: User = Depends(get_current_user)):
    settings = get_settings()
    return GuidanceStatus(
        provider="gemini" if settings.google_api_key else "rules",
        model=settings.gemini_model if settings.google_api_key else None,
    )


@router.post("/chat", response_model=GuidanceChatResponse)
@limiter.limit("4/minute")
async def guidance_chat(
    request: Request,
    payload: GuidanceChatRequest,
    user: User = Depends(get_current_user),
):
    role_names = {role.name for role in user.roles}
    message, provider, model = await answer(payload.messages, role_names)
    return GuidanceChatResponse(answer=message, provider=provider, model=model)
