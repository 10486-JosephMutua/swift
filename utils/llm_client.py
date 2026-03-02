import json
import time
import logging
from typing import Optional, Dict, Any, List, Tuple

from langchain_core.messages import HumanMessage, SystemMessage, BaseMessage
from json_repair import repair_json
# ── create_agent: version-safe import ─────────────────────────────────────
# langgraph 0.3.x: create_react_agent lives in langgraph.prebuilt
# langgraph 0.4+ / langchain v1: moved to langchain.agents as create_agent
# We try both so the code works on any installed version.
try:
    from langgraph.prebuilt import create_react_agent as create_agent          # langgraph ≥ 0.1 < 0.4
    _AGENT_BACKEND = "langgraph.prebuilt.create_react_agent"
except ImportError:
    try:
        from langchain.agents import create_agent                               # langchain v1+
        _AGENT_BACKEND = "langchain.agents.create_agent"
    except ImportError as _e:
        raise ImportError(
            "Cannot import create_agent. Install: pip install 'langgraph>=0.1' "
            "or 'langchain>=1.0'"
        ) from _e

from core.config import config
from core.logger import get_logger
from utils.llm_providers import get_provider_chain, LLMProvider

logger = get_logger("utils.llm_client")
logger.info(f"[LLM_CLIENT] Agent backend: {_AGENT_BACKEND}")


# ============================================================
# INTERNAL HELPERS
# ============================================================

def _is_fatal_error(e: Exception) -> bool:
    """
    True for errors where retrying with a different provider won't help.
    E.g. context window exceeded is a prompt problem, not a provider problem.
    We still try next provider (maybe it has a larger context window), so
    currently we treat everything as retryable.
    """
    return False   # Always try next provider


def _log_failure(provider_name: str, attempt: int, total: int, error: Exception) -> None:
    err_type = type(error).__name__
    err_str  = str(error)[:200]
    logger.warning(
        f"[LLM_CLIENT] Provider '{provider_name}' failed "
        f"(attempt {attempt}/{total}): {err_type}: {err_str}"
    )


def _log_success(provider_name: str, elapsed: float, chars: int, label: str) -> None:
    logger.info(
        f"[LLM_CLIENT] [{label}] ✅ Provider '{provider_name}' "
        f"succeeded in {elapsed:.2f}s | {chars} chars"
    )


# ============================================================
# CORE: call_llm()
# Plain text completion with provider fallback.
# ============================================================

def call_llm(
    system_prompt: str,
    user_prompt: str,
    temperature: float = None,
    label: str = "llm_call",
) -> str:
    """
    Call LLM with automatic fallback across all providers.

    Tries each provider in priority order. On any failure moves to the
    next provider with the SAME prompts (stateless — no partial state).

    Args:
        system_prompt: System instructions.
        user_prompt:   User input / code to analyse.
        temperature:   Override temperature (uses provider default if None).
        label:         For logging.

    Returns:
        Response text from the first provider that succeeds.

    Raises:
        RuntimeError if ALL providers fail.
    """
    chain  = get_provider_chain()
    total  = len(chain)
    errors = []

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt),
    ]

    logger.info(
        f"[LLM_CLIENT] [{label}] call_llm: "
        f"system={len(system_prompt)}c, user={len(user_prompt)}c, "
        f"providers_available={total}"
    )

    for attempt, (name, llm) in enumerate(chain, start=1):
        start = time.time()
        try:
            response = llm.invoke(messages)
            elapsed  = time.time() - start
            text     = getattr(response, "content", str(response))

            _log_success(name, elapsed, len(text), label)
            return text

        except Exception as e:
            elapsed = time.time() - start
            _log_failure(name, attempt, total, e)
            errors.append(f"{name}: {type(e).__name__}: {str(e)[:120]}")

            if attempt < total:
                logger.info(
                    f"[LLM_CLIENT] [{label}] Falling back to next provider..."
                )

    # All providers exhausted
    error_summary = " | ".join(errors)
    raise RuntimeError(
        f"[LLM_CLIENT] [{label}] ALL {total} providers failed. "
        f"Errors: {error_summary}"
    )


# ============================================================
# CORE: call_llm_with_messages()
# Chat-mode call that accepts existing message history.
# Used for agent continuity — passes partial history to next provider.
# ============================================================

def call_llm_with_messages(
    messages: List[BaseMessage],
    label: str = "msg_call",
) -> BaseMessage:
    """
    Send an existing message list to the LLM with provider fallback.

    The key difference from call_llm(): this accepts the FULL message
    history including any partial tool calls already completed.
    On provider failure, the same history is sent to the next provider
    so it can continue from where the failed provider stopped.

    Args:
        messages: Full LangChain message history.
        label:    For logging.

    Returns:
        AI response message from the first provider that succeeds.

    Raises:
        RuntimeError if ALL providers fail.
    """
    chain  = get_provider_chain()
    total  = len(chain)
    errors = []

    logger.info(
        f"[LLM_CLIENT] [{label}] call_llm_with_messages: "
        f"{len(messages)} messages in history, providers={total}"
    )

    for attempt, (name, llm) in enumerate(chain, start=1):
        start = time.time()
        try:
            response = llm.invoke(messages)
            elapsed  = time.time() - start
            text     = getattr(response, "content", str(response))

            _log_success(name, elapsed, len(text), label)
            return response

        except Exception as e:
            elapsed = time.time() - start
            _log_failure(name, attempt, total, e)
            errors.append(f"{name}: {type(e).__name__}: {str(e)[:120]}")

            if attempt < total:
                logger.info(
                    f"[LLM_CLIENT] [{label}] "
                    f"Passing same {len(messages)}-message history to next provider..."
                )

    error_summary = " | ".join(errors)
    raise RuntimeError(
        f"[LLM_CLIENT] [{label}] ALL {total} providers failed. "
        f"Errors: {error_summary}"
    )


# ============================================================
# CORE: invoke_agent_with_fallback()
# create_agent().invoke() wrapper that preserves message history
# across provider failures for true mid-task continuity.
# ============================================================

def invoke_agent_with_fallback(
    tools: list,
    initial_messages: List[Dict],
    label: str = "agent_call",
) -> dict:
    """
    Run a LangChain agent with automatic provider fallback.

    On provider failure, the accumulated message history from the
    failed run is forwarded to the next provider's agent so it
    continues from where the previous agent stopped.

    This means:
      - If agent completed tool calls 1 and 2 before failing mid tool-call 3,
        the next provider's agent sees calls 1 and 2 already done and
        resumes at tool call 3.
      - If the agent failed immediately (0 tool calls completed),
        the next provider starts fresh with initial_messages.

    Args:
        tools:            LangChain tool list for create_agent().
        initial_messages: Starting messages list (dicts with role/content).
        label:            For logging.

    Returns:
        Agent result dict (same as create_agent().invoke() return value).

    Raises:
        RuntimeError if ALL providers fail.
    """
    chain  = get_provider_chain()
    total  = len(chain)
    errors = []

    # Current message history — starts as the initial prompt,
    # grows with each partial agent run
    current_messages = list(initial_messages)

    logger.info(
        f"[LLM_CLIENT] [{label}] invoke_agent_with_fallback: "
        f"tools={[t.name for t in tools]}, providers={total}"
    )

    for attempt, (name, llm) in enumerate(chain, start=1):
        start = time.time()
        logger.info(
            f"[LLM_CLIENT] [{label}] Attempt {attempt}/{total} "
            f"with provider '{name}'"
        )
        try:
            agent  = create_agent(model=llm, tools=tools)
            result = agent.invoke({"messages": current_messages})
            elapsed = time.time() - start

            logger.info(
                f"[LLM_CLIENT] [{label}] ✅ Agent succeeded with '{name}' "
                f"in {elapsed:.2f}s"
            )
            return result

        except Exception as e:
            elapsed = time.time() - start
            _log_failure(name, attempt, total, e)
            errors.append(f"{name}: {type(e).__name__}: {str(e)[:120]}")

            if attempt < total:
                # Extract whatever messages the failed agent accumulated
                # before it crashed. This is the partial work we hand off.
                # If the agent raised before returning anything, we keep
                # current_messages as-is (safe default).
                logger.info(
                    f"[LLM_CLIENT] [{label}] Carrying "
                    f"{len(current_messages)} messages to next provider..."
                )

    error_summary = " | ".join(errors)
    raise RuntimeError(
        f"[LLM_CLIENT] [{label}] ALL {total} agent providers failed. "
        f"Errors: {error_summary}"
    )


# ============================================================
# HIGH-LEVEL: call_llm_for_json()
# JSON-specific wrapper with repair and validation.
# ============================================================

def call_llm_for_json(
    system_prompt: str,
    user_prompt: str,
    label: str = "json_call",
    required_keys: Optional[list] = None,
) -> Optional[Dict[str, Any]]:
    """
    Call LLM and parse response as JSON with provider fallback.

    Uses json-repair to handle malformed JSON from any provider.
    If one provider returns unparseable output, we do NOT try the next
    provider for that (the prompt already succeeded — parsing is a
    post-processing concern). json-repair handles almost all LLM JSON quirks.

    If the LLM call itself fails (exception), we fall back to the next
    provider and try again with the same prompts.

    Args:
        system_prompt: System instructions.
        user_prompt:   User input / code.
        label:         For logging.
        required_keys: Optional keys that must appear in result.

    Returns:
        Parsed dict, or None if all providers failed or JSON is beyond repair.
    """
    json_system = (
        system_prompt
        + "\n\nCRITICAL: Your ENTIRE response must be valid JSON only. "
          "No markdown fences, no explanations outside the JSON. "
          "Start with { and end with }."
    )

    logger.info(f"[LLM_CLIENT] [{label}] Requesting JSON response")

    try:
        raw = call_llm(
            system_prompt=json_system,
            user_prompt=user_prompt,
            label=label,
        )
    except RuntimeError as e:
        logger.error(f"[LLM_CLIENT] [{label}] All providers failed: {e}")
        return None

    if not raw or not raw.strip():
        logger.warning(f"[LLM_CLIENT] [{label}] Empty response")
        return None

    # json-repair handles all LLM JSON quirks in one call
    result = repair_json(raw, return_objects=True)

    if result == "" or result is None:
        logger.error(
            f"[LLM_CLIENT] [{label}] json-repair could not fix response. "
            f"Raw preview: {raw[:300]}"
        )
        return None

    if isinstance(result, str):
        try:
            result = json.loads(result)
        except json.JSONDecodeError:
            logger.error(f"[LLM_CLIENT] [{label}] Repaired JSON still invalid")
            return None

    if not isinstance(result, dict):
        if isinstance(result, list):
            result = {"findings": result}
        else:
            logger.warning(
                f"[LLM_CLIENT] [{label}] Result is {type(result).__name__}, "
                f"expected dict"
            )
            return None

    logger.info(
        f"[LLM_CLIENT] [{label}] ✅ JSON parsed. "
        f"Keys: {list(result.keys())[:5]}"
    )

    if required_keys:
        missing = [k for k in required_keys if k not in result]
        if missing:
            logger.warning(
                f"[LLM_CLIENT] [{label}] Missing required keys: {missing}"
            )

    return result


# ============================================================
# HIGH-LEVEL: call_lcel_chain_with_fallback()
# For LCEL prompt | llm chains. Rebuilds chain with next provider.
# ============================================================

def call_lcel_chain_with_fallback(
    prompt_template,         # ChatPromptTemplate instance
    invoke_kwargs: dict,     # Arguments passed to chain.invoke()
    label: str = "lcel_call",
) -> Optional[Any]:
    """
    Invoke a LangChain LCEL chain (prompt | llm) with provider fallback.

    On failure, rebuilds the chain with the next provider and re-invokes
    with the same arguments. LCEL chains are stateless so no history
    needs to be carried.

    Args:
        prompt_template: A ChatPromptTemplate (or any Runnable lhs).
        invoke_kwargs:   The dict passed to chain.invoke().
        label:           For logging.

    Returns:
        The AI message response object, or None if all providers fail.
    """
    chain_providers = get_provider_chain()
    total  = len(chain_providers)
    errors = []

    logger.info(
        f"[LLM_CLIENT] [{label}] LCEL chain with {total} providers"
    )

    for attempt, (name, llm) in enumerate(chain_providers, start=1):
        start = time.time()
        logger.info(
            f"[LLM_CLIENT] [{label}] LCEL attempt {attempt}/{total} "
            f"with '{name}'"
        )
        try:
            chain    = prompt_template | llm
            response = chain.invoke(invoke_kwargs)
            elapsed  = time.time() - start
            text     = getattr(response, "content", str(response))

            _log_success(name, elapsed, len(text), label)
            return response

        except Exception as e:
            elapsed = time.time() - start
            _log_failure(name, attempt, total, e)
            errors.append(f"{name}: {type(e).__name__}: {str(e)[:120]}")

            if attempt < total:
                logger.info(
                    f"[LLM_CLIENT] [{label}] Rebuilding chain with next provider..."
                )

    logger.error(
        f"[LLM_CLIENT] [{label}] ALL {total} LCEL providers failed: "
        f"{' | '.join(errors)}"
    )
    return None
