"""配置 API"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from app_config.encryption import ConfigEncryption
from app_config.settings import CONFIG_DIR
from app_config.providers import PROVIDERS, PROVIDER_ORDER
from services.llm_service import test_connection

router = APIRouter(prefix="/api/config", tags=["config"])
enc = ConfigEncryption(CONFIG_DIR)


class ProviderConfig(BaseModel):
    api_key: str = ""
    base_url: str = ""
    enabled: bool = False
    models: list[str] = []


@router.get("/providers")
async def list_providers():
    """列出所有 LLM 提供商"""
    saved = enc.load_config()
    result = []
    for pk in PROVIDER_ORDER:
        info = PROVIDERS.get(pk, {})
        saved_cfg = saved.get(pk, {})
        result.append({
            "key": pk,
            "name": info.get("name", pk),
            "base_url": info.get("base_url", ""),
            "api_key_url": info.get("api_key_url", ""),
            "models": saved_cfg.get("models") or info.get("models", []),
            "enabled": saved_cfg.get("enabled", False),
            "has_key": bool(saved_cfg.get("api_key")),
            "supports_tools": info.get("supports_tools", True),
        })
    return {"providers": result, "order": PROVIDER_ORDER}


@router.post("/providers/{provider_key}")
async def save_provider(provider_key: str, cfg: ProviderConfig):
    if provider_key not in PROVIDERS:
        raise HTTPException(404, f"未知提供商: {provider_key}")
    saved = enc.load_config()
    saved[provider_key] = cfg.model_dump(exclude_none=True)
    enc.save_config(saved)
    return {"ok": True}


@router.post("/providers/{provider_key}/test")
async def test_provider(provider_key: str):
    if provider_key not in PROVIDERS:
        raise HTTPException(404, f"未知提供商: {provider_key}")
    saved = enc.load_config().get(provider_key, {})
    api_key = saved.get("api_key", "")
    base_url = saved.get("base_url", "") or PROVIDERS[provider_key].get("base_url", "")
    if not api_key:
        raise HTTPException(400, "未配置 API Key")
    ok, msg = test_connection(provider_key, api_key, base_url)
    return {"ok": ok, "message": msg if not ok else msg}
