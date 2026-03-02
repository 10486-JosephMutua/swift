import os
import logging
from typing import List, Tuple, Any, Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("utils.llm_providers")

# Type alias — BaseChatModel (any LangChain chat model)
LLMProvider = Any


# ============================================================
# INDIVIDUAL PROVIDER BUILDERS
# Each returns (name, llm) or None if key is missing/init fails.
# ============================================================

def _build_groq() -> Optional[Tuple[str, LLMProvider]]:
    key = os.getenv("GROQ_API_KEY", "")
    if not key:
        return None
    try:
        from langchain_groq import ChatGroq
        llm = ChatGroq(
            api_key=key,
            model_name="llama-3.1-70b-versatile",
            temperature=0.1,
            max_retries=0,  # We handle retries ourselves
            timeout=30,
        )
        return ("groq", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] groq init failed: {e}")
        return None


def _build_gemini1() -> Optional[Tuple[str, LLMProvider]]:
    key = os.getenv("GEMINI_API_KEY1", "")
    if not key:
        return None
    try:
        # ── Block Google ADC / GCE metadata probe before import ───────────────
        # google-genai SDK probes http://metadata.google.internal/ on import
        # to detect if running on GCP. On non-GCP Windows machines this TCP
        # connection has no RST/refuse — it just HANGS for up to 5 minutes.
        # Setting these env vars before import tells google-auth to skip the probe.
        # Per google-auth-library docs: NO_GCE_CHECK disables metadata check.
        os.environ.setdefault("NO_GCE_CHECK", "true")
        os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "none")
        from langchain_google_genai import ChatGoogleGenerativeAI
        llm = ChatGoogleGenerativeAI(
            api_key=key,
            model="gemini-2.5-flash",
            temperature=0,
            max_retries=0,
            timeout=120,
        )
        return ("gemini1", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] gemini1 init failed: {e}")
        return None


def _build_openai_github() -> Optional[Tuple[str, LLMProvider]]:
    key = os.getenv("OPENAI_API_KEY", "")
    if not key:
        return None
    try:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model="openai/gpt-4.1",
            openai_api_key=key,
            openai_api_base="https://models.github.ai/inference",
            temperature=0.2,
            max_retries=0,
            streaming=False,
            timeout=120,
        )
        return ("openai_github", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] openai_github init failed: {e}")
        return None


def _build_sambanova() -> Optional[Tuple[str, LLMProvider]]:
    key = os.getenv("SAMBANOVA_API_KEY", "")
    if not key:
        return None
    try:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model="Llama-4-Maverick-17B-128E-Instruct",
            openai_api_key=key,
            openai_api_base="https://api.sambanova.ai/v1",
            temperature=0.2,
            max_retries=0,
            streaming=False,
            timeout=30,
        )
        return ("sambanova", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] sambanova init failed: {e}")
        return None


def _build_mistral() -> Optional[Tuple[str, LLMProvider]]:
    key = os.getenv("MISTRAL_API_KEY", "")
    if not key:
        return None
    try:
        from langchain_mistralai.chat_models import ChatMistralAI
        llm = ChatMistralAI(
            model="mistral-large-latest",
            api_key=key,
            endpoint="https://api.mistral.ai/v1",
            temperature=0,
            max_retries=0,
            streaming=False,
            timeout=30,
        )
        return ("mistral", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] mistral init failed: {e}")
        return None


def _build_gemini2() -> Optional[Tuple[str, LLMProvider]]:
    key = os.getenv("GEMINI_API_KEY2", "")
    if not key:
        return None
    try:
        # Block Google ADC/GCE metadata probe (see gemini1 for explanation)
        os.environ.setdefault("NO_GCE_CHECK", "true")
        os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "none")
        from langchain_google_genai import ChatGoogleGenerativeAI
        llm = ChatGoogleGenerativeAI(
            api_key=key,
            model="gemini-2.0-flash",
            temperature=0,
            max_retries=0,
            stream=False,
            timeout=30,
        )
        return ("gemini2", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] gemini2 init failed: {e}")
        return None


def _build_scaleway() -> Optional[Tuple[str, LLMProvider]]:
    key = os.getenv("SCW_API_KEY", "")
    if not key:
        return None
    try:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model="openai/gpt-oss-120b:fp4",
            openai_api_key=key,
            openai_api_base="https://api.scaleway.ai/v1",
            temperature=0.2,
            max_retries=0,
            streaming=False,
            timeout=30,
        )
        return ("scaleway", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] scaleway init failed: {e}")
        return None


def _build_nvidia() -> Optional[Tuple[str, LLMProvider]]:
    key = os.getenv("NVIDIA_API_KEY", "")
    if not key:
        return None
    try:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model="nvidia/nemotron-3-nano-30b-a3b",
            openai_api_key=key,
            openai_api_base="https://integrate.api.nvidia.com/v1",
            temperature=0.2,
            max_retries=0,
            streaming=False,
            timeout=30,
        )
        return ("nvidia", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] nvidia init failed: {e}")
        return None


def _build_openrouter() -> Optional[Tuple[str, LLMProvider]]:
    key = os.getenv("open_router_api", "")
    if not key:
        return None
    try:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model="nvidia/nemotron-3-nano-30b-a3b:free",
            openai_api_key=key,
            openai_api_base="https://openrouter.ai/api/v1",
            temperature=0,
            max_retries=0,
            streaming=False,
            timeout=30,
        )
        return ("openrouter", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] openrouter init failed: {e}")
        return None


def _build_novita() -> Optional[Tuple[str, LLMProvider]]:
    key = os.getenv("NOVITA_API_KEY", "")
    if not key:
        return None
    try:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model="meta-llama/llama-3.3-70b-instruct",
            openai_api_key=key,
            openai_api_base="https://api.novita.ai/v3/openai",
            temperature=0.5,
            max_retries=0,
            streaming=False,
            timeout=30,
        )
        return ("novita", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] novita init failed: {e}")
        return None


def _build_deepinfra() -> Optional[Tuple[str, LLMProvider]]:
    key = os.getenv("DEEPINFRA_API_KEY", os.getenv("FIREWORKS_API_KEY", ""))
    if not key:
        return None
    try:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(
            model="accounts/fireworks/models/llama-v3p1-405b-instruct",
            openai_api_key=key,
            openai_api_base="https://api.fireworks.ai/inference/v1",
            temperature=0.5,
            max_retries=0,
            streaming=False,
            timeout=120,
        )
        return ("deepinfra", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] deepinfra init failed: {e}")
        return None


def _build_cloudflare() -> Optional[Tuple[str, LLMProvider]]:
    account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
    api_token  = os.getenv("CLOUDFLARE_API_TOKEN", "")
    if not account_id or not api_token:
        return None
    try:
        from langchain_community.llms.cloudflare_workersai import CloudflareWorkersAI
        llm = CloudflareWorkersAI(
            account_id=account_id,
            api_token=api_token,
            model="@cf/meta/llama-3.2-3b-instruct",
        )
        return ("cloudflare", llm)
    except Exception as e:
        logger.warning(f"[LLM_PROVIDERS] cloudflare init failed: {e}")
        return None


# ============================================================
# CHAIN INITIALISATION
# ============================================================

# All builders in priority order
_BUILDERS = [
    _build_groq,
    _build_gemini1,
    _build_openai_github,
    _build_sambanova,
    _build_mistral,
    _build_gemini2,
    _build_scaleway,
    _build_nvidia,
    _build_openrouter,
    _build_novita,
    _build_deepinfra,
    _build_cloudflare,
]


def _init_providers() -> List[Tuple[str, LLMProvider]]:
    """
    Build every provider. Log successes and failures.
    Returns only the ones that initialised successfully.
    """
    chain = []
    for builder in _BUILDERS:
        result = builder()
        if result is not None:
            name, llm = result
            chain.append((name, llm))
            logger.info(f"[LLM_PROVIDERS] ✅ Loaded provider: {name}")
        else:
            # builder already logged the specific reason
            pass

    if not chain:
        logger.error(
            "[LLM_PROVIDERS] ❌ NO providers initialised. "
            "Check that at least one API key is set in .env"
        )
    else:
        logger.info(
            f"[LLM_PROVIDERS] Chain ready: "
            f"{len(chain)} providers: {[n for n, _ in chain]}"
        )

    return chain


# Module-level singleton: built once, shared across all callers
_PROVIDER_CHAIN: List[Tuple[str, LLMProvider]] = _init_providers()


def get_provider_chain() -> List[Tuple[str, LLMProvider]]:
    """
    Return the full ordered provider chain.

    Returns a shallow copy so callers cannot mutate the module-level list,
    but the LLM objects themselves are shared (they are stateless).
    """
    return list(_PROVIDER_CHAIN)


def get_primary_llm() -> Optional[LLMProvider]:
    """
    Return just the first (highest priority) available LLM.
    Used by agent __init__ methods that need a single instance.
    The fallback engine handles failover at call time.
    """
    if _PROVIDER_CHAIN:
        return _PROVIDER_CHAIN[0][1]
    return None


def get_primary_name() -> str:
    """Return the name of the primary provider, or 'none'."""
    if _PROVIDER_CHAIN:
        return _PROVIDER_CHAIN[0][0]
    return "none"
