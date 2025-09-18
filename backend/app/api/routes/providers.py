"""AI provider configuration routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...db.models import ProviderProfile, User
from ...db.session import get_db
from ...providers.base import ProviderConfiguration, ProviderError
from ...providers.registry import (
    PRICE_PER_MILLION,
    estimate_cost,
    provider_types,
)
from ...services.secrets import encrypt_secret, encryption_available, key_hint
from ..deps import get_container_dep, get_current_user, require_admin

router = APIRouter(prefix="/providers", tags=["providers"])


class ProviderProfileRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    provider_type: str = Field(min_length=1, max_length=32)
    base_url: str = Field(default="", max_length=512)
    model: str = Field(default="", max_length=128)
    api_key: str | None = Field(default=None, max_length=4096)
    extra_headers: dict[str, str] = Field(default_factory=dict)
    options: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=120, ge=5, le=600)
    max_retries: int = Field(default=2, ge=0, le=10)
    max_tokens: int = Field(default=4096, ge=64, le=200_000)
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    is_default: bool = False


def _serialize(profile: ProviderProfile) -> dict[str, Any]:
    return {
        "id": profile.id,
        "name": profile.name,
        "provider_type": profile.provider_type,
        "base_url": profile.base_url,
        "model": profile.model,
        "has_api_key": bool(profile.api_key_encrypted),
        "api_key_hint": profile.api_key_hint,
        "extra_header_names": sorted(profile.extra_headers or {}),
        "options": profile.options,
        "timeout_seconds": profile.options.get("timeout_seconds", 120),
        "max_retries": profile.options.get("max_retries", 2),
        "max_tokens": profile.options.get("max_tokens", 4096),
        "temperature": profile.options.get("temperature", 0.2),
        "is_active": profile.is_active,
        "is_default": profile.is_default,
        "last_test_at": profile.last_test_at.isoformat() if profile.last_test_at else None,
        "last_test_ok": profile.last_test_ok,
        "last_test_message": profile.last_test_message,
    }


@router.get("/types")
async def list_provider_types(_: User = Depends(get_current_user)) -> dict[str, Any]:
    """Describe the supported provider types and the price table."""
    return {
        "types": provider_types(),
        "pricing": {
            model: {"input_per_1m": price[0], "output_per_1m": price[1]}
            for model, price in sorted(PRICE_PER_MILLION.items())
        },
        "pricing_note": "Published list prices used for estimates only.",
    }


@router.get("")
async def list_profiles(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    """List the configured provider profiles."""
    profiles = list(db.execute(select(ProviderProfile).order_by(ProviderProfile.name)).scalars())
    settings = get_settings()
    return {
        "profiles": [_serialize(profile) for profile in profiles],
        "environment": {
            "default_provider": settings.default_provider,
            "default_model": settings.provider_model,
            "default_base_url": settings.provider_base_url,
            "has_env_api_key": bool(settings.provider_api_key),
            "encryption_available": encryption_available(settings),
        },
    }


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_profile(
    payload: ProviderProfileRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Create a provider profile."""
    settings = get_settings()
    existing = (
        db.execute(select(ProviderProfile).where(ProviderProfile.name == payload.name)).scalars().first()
    )
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The profile name is taken.")

    encrypted = ""
    hint = ""
    if payload.api_key:
        if not encryption_available(settings):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "Provider credentials cannot be stored because no encryption key is "
                    "configured. Set SAXIS_PROVIDER_SECRET_KEY or use environment "
                    "variables instead."
                ),
            )
        encrypted = encrypt_secret(payload.api_key, settings)
        hint = key_hint(payload.api_key)

    profile = ProviderProfile(
        name=payload.name,
        provider_type=payload.provider_type,
        base_url=payload.base_url,
        model=payload.model,
        api_key_encrypted=encrypted or None,
        api_key_hint=hint,
        extra_headers=payload.extra_headers,
        options={
            **payload.options,
            "timeout_seconds": payload.timeout_seconds,
            "max_retries": payload.max_retries,
            "max_tokens": payload.max_tokens,
            "temperature": payload.temperature,
        },
        is_active=payload.is_default,
        is_default=payload.is_default,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return _serialize(profile)


@router.put("/{profile_id}")
async def update_profile(
    profile_id: str,
    payload: ProviderProfileRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Update a provider profile."""
    settings = get_settings()
    profile = db.get(ProviderProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found.")

    profile.provider_type = payload.provider_type
    profile.base_url = payload.base_url
    profile.model = payload.model
    profile.extra_headers = payload.extra_headers
    profile.options = {
        **payload.options,
        "timeout_seconds": payload.timeout_seconds,
        "max_retries": payload.max_retries,
        "max_tokens": payload.max_tokens,
        "temperature": payload.temperature,
    }
    if payload.api_key:
        if not encryption_available(settings):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="No encryption key is configured; refusing to store the credential.",
            )
        profile.api_key_encrypted = encrypt_secret(payload.api_key, settings)
        profile.api_key_hint = key_hint(payload.api_key)
    if payload.is_default:
        for other in db.execute(select(ProviderProfile)).scalars():
            other.is_default = other.id == profile.id
            other.is_active = other.id == profile.id
    db.commit()
    db.refresh(profile)
    return _serialize(profile)


@router.delete("/{profile_id}")
async def delete_profile(
    profile_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Delete a provider profile."""
    profile = db.get(ProviderProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found.")
    db.delete(profile)
    db.commit()
    return {"status": "deleted", "id": profile_id}


@router.post("/{profile_id}/test")
async def test_profile(
    profile_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Test the connection to a provider profile."""
    profile = db.get(ProviderProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found.")
    try:
        provider = container.provider_from_profile(profile)
    except ProviderError as exc:
        return {"ok": False, "message": str(exc), "error_code": exc.code}
    result = await provider.test_connection()
    profile.last_test_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    profile.last_test_ok = bool(result.get("ok"))
    profile.last_test_message = str(result.get("message", ""))[:2000]
    db.commit()
    return result


@router.get("/models")
async def discover_models(
    profile_id: str | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Discover the models offered by a provider."""
    if profile_id:
        profile = db.get(ProviderProfile, profile_id)
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found.")
        configuration = ProviderConfiguration(
            provider_type=profile.provider_type,
            base_url=profile.base_url,
            api_key=profile.options.get("__key", ""),
            model=profile.model,
        )
        try:
            provider = container.provider_from_profile(profile)
            models = await provider.list_models()
        except ProviderError as exc:
            return {"models": [], "error": str(exc), "error_code": exc.code}
    else:
        configuration = container.default_provider_configuration()
        try:
            provider = container.build_provider(configuration)
            models = await provider.list_models()
        except ProviderError as exc:
            return {"models": [], "error": str(exc), "error_code": exc.code}
    return {"models": models, "count": len(models)}


@router.post("/estimate")
async def estimate(
    payload: dict[str, Any] = Body(...),
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Estimate the cost of a provider call."""
    model = str(payload.get("model") or "")
    prompt_tokens = int(payload.get("prompt_tokens") or 0)
    completion_tokens = int(payload.get("completion_tokens") or 0)
    cost = estimate_cost(model, prompt_tokens, completion_tokens)
    return {
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "estimated_cost_usd": cost,
        "note": "Estimates only - always based on published list prices.",
    }
