"""Model providers, behind one interface the gateway controls.

The AI half of this product used to be hard-wired to one cloud API. That is a
security problem, not just a vendor problem: a diagnosis sends the user's
question and the *contents of local files* to whoever is answering, so "which
provider, which endpoint" belongs to the same boundary as "which commands may
run". Three consequences shape this module:

1. The provider is chosen by policy first, environment second, and never by a
   silent guess. Falling back to a cloud endpoint because a local one was
   unreachable would move host data without anyone deciding to.
2. A policy that sets ``ai.allow_cloud: false`` cannot be talked into a
   non-loopback endpoint by an environment variable.
3. Every provider returns the same neutral ``Turn`` object, so the risk engine,
   the audit log and the MCP server cannot have provider-specific behaviour.

Ollama and every OpenAI-compatible server (LM Studio, llama.cpp, vLLM,
Together, Groq, OpenAI) share one implementation over stdlib urllib: no
dependency tree, and a fake transport makes the whole layer testable offline.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from typing import Any, Callable

from policy import Policy

PROVIDER_NAMES = ("gemini", "openai", "ollama")

OLLAMA_BASE_URL = "http://127.0.0.1:11434/v1"
OPENAI_BASE_URL = "https://api.openai.com/v1"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com"

# Used only when neither the policy nor the environment names a model. The
# Gemini string is the one this project has actually run against, so keeping
# it means adding a provider layer does not silently change her setup.
DEFAULT_MODELS = {
    "gemini": "gemini-3.6-flash",
    "openai": "gpt-4o-mini",
    "ollama": "qwen2.5-coder:7b",
}

# Names that mean "this machine". A loopback endpoint is the only thing an
# operator can plausibly own, which is what allow_cloud:false tests against.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

DEFAULT_TIMEOUT = 120.0


class ProviderError(Exception):
    """No provider could be chosen, or the chosen one answered badly."""


@dataclass(frozen=True)
class ToolCall:
    """A tool the model asked for. Validation happens later, in risk_engine.

    ``id`` is the OpenAI-compatible correlation handle. Gemini has no equivalent
    and matches function responses by name, so it stays empty there.
    """

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    id: str = ""


@dataclass(frozen=True)
class Observation:
    """One tool call and what the gateway handed back for it.

    A refusal is an observation too: when policy blocks a call the model is told
    it was blocked, rather than the whole diagnosis silently disappearing.
    """

    call: ToolCall
    output: Any


@dataclass(frozen=True)
class Turn:
    """Provider-neutral answer: prose, or one or more tool requests.

    ``raw`` keeps whatever a later round needs (the Gemini content object, or the
    OpenAI assistant message with its tool_calls). Nothing outside this module is
    allowed to look inside it.
    """

    text: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    raw: Any = None


@dataclass(frozen=True)
class Step:
    """One round of the loop: the model's requests plus every answer to them."""

    turn: Turn
    observations: tuple[Observation, ...]


def _is_gemini_endpoint(url: str) -> bool:
    """Whether a configured base_url is the one the Gemini SDK really uses."""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return host == "generativelanguage.googleapis.com"


def is_loopback(url: str) -> bool:
    """True when a URL points at this machine, by hostname, not by substring.

    Parsing matters: 'http://127.0.0.1.evil.com' contains a loopback address as
    a prefix and is not loopback at all.
    """
    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower().strip("[]")
    return host in LOOPBACK_HOSTS or host.endswith(".localhost")


def _schema_of(model: type) -> dict:
    """JSON Schema for a pydantic model, in the shape both APIs accept."""
    try:
        return model.model_json_schema()
    except AttributeError:  # pragma: no cover - defensive
        return {"type": "object", "properties": {}}


# ============================================================
# BASE
# ============================================================

class Provider:
    """One model endpoint. Subclasses implement ``complete``/``structured``."""

    name = "base"

    def __init__(self, model: str, endpoint: str):
        self.model = model
        self.endpoint = endpoint

    @property
    def local(self) -> bool:
        return is_loopback(self.endpoint)

    @property
    def egress_label(self) -> str:
        """How to describe this provider to a human and to the audit log."""
        where = "on this machine" if self.local else "OFF-BOX"
        return f"{self.name} ({self.model}, {self.endpoint}, {where})"

    def complete(
        self,
        *,
        system: str,
        contents: list[dict[str, str]],
        tools: list[dict[str, Any]] | None = None,
        tool_mode: str = "auto",
    ) -> Turn:
        raise NotImplementedError

    def structured(self, *, system: str, user: str, schema: type) -> dict:
        raise NotImplementedError

    def follow_up(
        self,
        *,
        system: str,
        contents: list[dict[str, str]],
        steps: list[Step],
        tools: list[dict[str, Any]] | None = None,
        tool_mode: str = "none",
    ) -> Turn:
        """Replay the completed tool rounds and ask the model again.

        ``tool_mode`` stays ``"none"`` for the answer round: the gateway decides
        how many rounds a diagnosis may take, and the last one can only be prose.
        """
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {
            "provider": self.name,
            "model": self.model,
            "endpoint": self.endpoint,
            "local": self.local,
        }


# ============================================================
# GEMINI
# ============================================================

class GeminiProvider(Provider):
    """The original path, kept working exactly as it did."""

    name = "gemini"

    def __init__(self, api_key: str, model: str, client: Any = None):
        super().__init__(model=model, endpoint=GEMINI_BASE_URL)
        self._api_key = api_key
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            from google import genai  # imported lazily so offline installs work

            self._client = genai.Client(api_key=self._api_key)
        return self._client

    def _tools(self, tools: list[dict[str, Any]]) -> Any:
        from google.genai import types

        declarations = []
        for tool in tools:
            function = tool.get("function", tool)
            declarations.append(
                types.FunctionDeclaration(
                    name=function["name"],
                    description=function.get("description", ""),
                    parameters=function.get(
                        "parameters", {"type": "object", "properties": {}}
                    ),
                )
            )
        return types.Tool(function_declarations=declarations)

    @staticmethod
    def _contents(types: Any, contents: list[dict[str, str]]) -> list[Any]:
        built = []
        for turn in contents:
            built.append(
                types.Content(
                    role=turn["role"],
                    parts=[types.Part.from_text(text=turn["text"])],
                )
            )
        return built

    def structured(self, *, system: str, user: str, schema: type) -> dict:
        from google.genai import types

        response = self.client.models.generate_content(
            model=self.model,
            contents=user,
            config=types.GenerateContentConfig(
                system_instruction=system,
                response_mime_type="application/json",
                response_schema=schema,
            ),
        )
        return _must_be_json(getattr(response, "text", None), self.name)

    def complete(
        self,
        *,
        system: str,
        contents: list[dict[str, str]],
        tools: list[dict[str, Any]] | None = None,
        tool_mode: str = "auto",
    ) -> Turn:
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=system,
            **({"tools": [self._tools(tools)]} if tools else {}),
            tool_config=types.ToolConfig(
                function_calling_config=types.FunctionCallingConfig(
                    mode={"auto": "AUTO", "required": "ANY", "none": "NONE"}[tool_mode]
                )
            ),
        )

        response = self.client.models.generate_content(
            model=self.model,
            contents=self._contents(types, contents),
            config=config,
        )

        candidates = getattr(response, "candidates", None) or []
        if not candidates or not candidates[0].content:
            raise ProviderError(
                f"{self.name} returned no usable candidate; refusing to guess "
                "what the model meant"
            )

        return self._as_turn(candidates[0].content, response)

    def follow_up(
        self,
        *,
        system: str,
        contents: list[dict[str, str]],
        steps: list[Step],
        tools: list[dict[str, Any]] | None = None,
        tool_mode: str = "none",
    ) -> Turn:
        """Replay every round so far, then ask for the next answer."""
        from google.genai import types

        built = self._contents(types, contents)
        for step in steps:
            built.append(step.turn.raw["content"])
            built.append(
                types.Content(
                    role="user",
                    parts=[
                        types.Part.from_function_response(
                            name=observation.call.name,
                            response={"result": observation.output},
                        )
                        for observation in step.observations
                    ],
                )
            )

        response = self.client.models.generate_content(
            model=self.model,
            contents=built,
            config=types.GenerateContentConfig(
                system_instruction=system,
                **({"tools": [self._tools(tools)]}
                   if tools and tool_mode != "none" else {}),
                tool_config=types.ToolConfig(
                    function_calling_config=types.FunctionCallingConfig(
                        mode={"auto": "AUTO", "required": "ANY",
                              "none": "NONE"}[tool_mode]
                    )
                ),
            ),
        )

        candidates = getattr(response, "candidates", None) or []
        if candidates and candidates[0].content:
            return self._as_turn(candidates[0].content, response)

        return Turn(text=getattr(response, "text", None), raw=response)

    @staticmethod
    def _as_turn(content: Any, response: Any) -> Turn:
        calls: list[ToolCall] = []
        text_parts: list[str] = []

        for part in content.parts or []:
            call = getattr(part, "function_call", None)
            if call is not None:
                calls.append(
                    ToolCall(call.name, dict(getattr(call, "args", None) or {}))
                )
            elif getattr(part, "text", None):
                text_parts.append(part.text)

        return Turn(
            text="\n".join(text_parts) or None,
            tool_calls=tuple(calls),
            raw={"content": content, "response": response},
        )


# ============================================================
# OPENAI-COMPATIBLE (also serves Ollama)
# ============================================================

Post = Callable[[str, dict[str, str], dict[str, Any]], dict]


def _urllib_post(url: str, headers: dict[str, str], body: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT) as reply:
            return json.loads(reply.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise ProviderError(
            f"{url} returned HTTP {exc.code}: {detail or exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise ProviderError(
            f"cannot reach {url}: {exc.reason}. Is the server running? "
            "Nothing was guessed and no other provider was tried."
        ) from exc
    except json.JSONDecodeError as exc:
        raise ProviderError(f"{url} replied with something that is not JSON") from exc


class OpenAICompatProvider(Provider):
    """One implementation for every /chat/completions server, Ollama included."""

    def __init__(
        self,
        name: str,
        model: str,
        base_url: str,
        api_key: str = "",
        post: Post | None = None,
    ):
        super().__init__(model=model, endpoint=base_url.rstrip("/"))
        self.name = name
        self.api_key = api_key
        self._post = post or _urllib_post

    def _headers(self) -> dict[str, str]:
        # Ollama ignores auth; OpenAI-compatible servers demand a bearer token.
        return {"Authorization": f"Bearer {self.api_key or 'ollama'}"}

    def _chat(self, body: dict) -> dict:
        payload = self._post(f"{self.endpoint}/chat/completions", self._headers(), body)
        choices = payload.get("choices") or []
        if not choices:
            raise ProviderError(
                f"{self.name} returned no choices: {str(payload)[:200]}"
            )
        return choices[0].get("message") or {}

    def structured(self, *, system: str, user: str, schema: type) -> dict:
        spec = _schema_of(schema)
        # Not every server honours response_schema, so the schema is also stated
        # in words and the answer is parsed strictly either way.
        instruction = (
            f"{system}\n\nReply with a single JSON object and nothing else. "
            f"It MUST match this JSON Schema:\n{json.dumps(spec)}"
        )
        message = self._chat({
            "model": self.model,
            "messages": [
                {"role": "system", "content": instruction},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0,
        })
        return _must_be_json(message.get("content"), self.name)

    def complete(
        self,
        *,
        system: str,
        contents: list[dict[str, str]],
        tools: list[dict[str, Any]] | None = None,
        tool_mode: str = "auto",
    ) -> Turn:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         *_to_chatml(contents)],
            "temperature": 0,
        }

        if tools:
            body["tools"] = _openai_tools(tools)
            body["tool_choice"] = {"auto": "auto", "required": "required",
                                   "none": "none"}[tool_mode]

        return self._as_turn(self._chat(body))

    def _as_turn(self, message: dict) -> Turn:
        """Parse a reply into a Turn, keeping each call's id for the answer."""
        calls: list[ToolCall] = []

        for index, item in enumerate(message.get("tool_calls") or []):
            function = item.get("function") or {}
            arguments = function.get("arguments")
            if isinstance(arguments, str):
                arguments = _must_be_json(arguments, self.name)
            calls.append(ToolCall(str(function.get("name") or ""),
                                  dict(arguments or {}),
                                  item.get("id") or f"call_{index}"))

        return Turn(text=message.get("content") or None,
                    tool_calls=tuple(calls),
                    raw={"message": message})

    def follow_up(
        self,
        *,
        system: str,
        contents: list[dict[str, str]],
        steps: list[Step],
        tools: list[dict[str, Any]] | None = None,
        tool_mode: str = "none",
    ) -> Turn:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system}, *_to_chatml(contents)]

        for step in steps:
            # Some servers omit ids; replay with ours so every response matches
            # the request it answers instead of guessing at the pairing.
            message = dict(step.turn.raw.get("message") or
                           {"role": "assistant", "content": None})
            message["tool_calls"] = [
                {**(item or {}), "id": observation.call.id}
                for item, observation in
                zip(message.get("tool_calls") or [], step.observations)
            ]
            messages.append(message)

            messages.extend({
                "role": "tool",
                "tool_call_id": observation.call.id,
                "content": json.dumps({"result": observation.output}, default=str),
            } for observation in step.observations)

        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "tool_choice": {"auto": "auto", "required": "required",
                            "none": "none"}[tool_mode],
        }
        if tools and tool_mode != "none":
            body["tools"] = _openai_tools(tools)

        message = self._chat(body)
        return self._as_turn(message)


def _openai_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Wrap our tool specs in the shape every /chat/completions server expects."""
    return [
        {
            "type": "function",
            "function": {
                "name": tool.get("function", tool)["name"],
                "description": tool.get("function", tool).get("description", ""),
                "parameters": tool.get("function", tool).get(
                    "parameters", {"type": "object", "properties": {}}
                ),
            },
        }
        for tool in tools
    ]


def _to_chatml(contents: list[dict[str, str]]) -> list[dict[str, str]]:
    """Stored history uses Gemini's 'model' role; chat servers want 'assistant'."""
    return [
        {
            "role": "assistant" if turn["role"] in ("model", "assistant") else "user",
            "content": turn["text"],
        }
        for turn in contents
    ]


_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def _must_be_json(text: Any, provider: str) -> dict:
    """Parse a model's JSON, tolerating the prose some servers wrap it in."""
    if not isinstance(text, str) or not text.strip():
        raise ProviderError(f"{provider} returned empty structured output")

    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", candidate).strip()

    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        match = _JSON_BLOCK.search(candidate)
        if not match:
            raise ProviderError(
                f"{provider} returned invalid structured output: "
                f"{candidate[:160]}"
            ) from None
        data = json.loads(match.group(0))

    if not isinstance(data, dict):
        raise ProviderError(f"{provider} returned JSON that is not an object")
    return data


# ============================================================
# SELECTION
# ============================================================

@dataclass(frozen=True)
class ProviderConfig:
    name: str
    model: str
    base_url: str
    api_key: str
    origin: str


def choose_provider(
    policy: Policy | None = None,
    environ: dict[str, str] | None = None,
) -> ProviderConfig:
    """Decide which provider to use, or refuse. Never guess a cloud endpoint.

    Order of authority: the operator policy, then the environment, then an
    explicit default that only applies when the policy says nothing.
    """
    env = environ if environ is not None else os.environ
    policy = policy or _default_policy()

    def get(key: str) -> str:
        return (env.get(key) or "").strip()

    pinned = policy.ai_provider
    requested = get("SSM_PROVIDER")

    if pinned and requested and requested != pinned:
        raise ProviderError(
            f"policy pins the AI provider to '{pinned}' but SSM_PROVIDER says "
            f"'{requested}'. Refusing to pick one; fix the policy or the "
            "environment."
        )

    name = pinned or requested
    if pinned and requested:
        origin = "policy ai.provider and SSM_PROVIDER agree"
    elif pinned:
        origin = "policy ai.provider"
    elif requested:
        origin = "SSM_PROVIDER"
    else:
        origin = ""

    if not name:
        if get("GEMINI_API_KEY"):
            name, origin = "gemini", "detected: GEMINI_API_KEY is set"
        elif get("SSM_BASE_URL"):
            name, origin = "openai", "detected: SSM_BASE_URL is set"
        else:
            raise ProviderError(
                "no AI provider configured. Set one of these in the "
                "environment or in .env next to the code:\n"
                "  SSM_PROVIDER=ollama   (local, free, no key: run "
                "`ollama serve` and `ollama pull qwen2.5-coder:7b`)\n"
                "  SSM_PROVIDER=openai + OPENAI_API_KEY\n"
                "  GEMINI_API_KEY=...\n"
                "Or pin one in policy.yaml under 'ai: provider:'.\n"
                "Nothing was sent anywhere, because nothing was chosen."
            )

    if name not in PROVIDER_NAMES:
        raise ProviderError(
            f"unknown AI provider '{name}'; choose from "
            f"{', '.join(PROVIDER_NAMES)}"
        )

    if name == "gemini":
        wanted = policy.ai_base_url or get("SSM_BASE_URL")
        if wanted and not _is_gemini_endpoint(wanted):
            raise ProviderError(
                f"provider 'gemini' always talks to {GEMINI_BASE_URL}, so the "
                f"configured base_url {wanted!r} would be ignored instead of "
                "honoured. Remove it, or use 'openai' for an OpenAI-compatible "
                "endpoint."
            )
        key = get("GEMINI_API_KEY")
        if not key:
            raise ProviderError(
                "provider 'gemini' needs GEMINI_API_KEY. It is not created "
                "interactively here: a security gateway should not prompt for a "
                "credential and write it into a file next to the code."
            )
        config = ProviderConfig(
            name="gemini",
            model=policy.ai_model or get("SSM_MODEL") or get("AI_MODEL")
            or DEFAULT_MODELS["gemini"],
            base_url=GEMINI_BASE_URL,
            api_key=key,
            origin=origin,
        )
    elif name == "ollama":
        base = (policy.ai_base_url or get("SSM_BASE_URL") or OLLAMA_BASE_URL)
        config = ProviderConfig(
            name="ollama",
            model=policy.ai_model or get("SSM_MODEL") or DEFAULT_MODELS["ollama"],
            base_url=base,
            api_key=get("OLLAMA_API_KEY"),
            origin=origin,
        )
    else:
        base = policy.ai_base_url or get("SSM_BASE_URL") or OPENAI_BASE_URL
        key = get("SSM_API_KEY") or get("OPENAI_API_KEY")
        if not key and is_loopback(base):
            key = "local"  # a local OpenAI-compatible server with no auth
        if not key:
            raise ProviderError(
                f"provider 'openai' at {base} needs SSM_API_KEY or "
                "OPENAI_API_KEY"
            )
        config = ProviderConfig(
            name="openai",
            model=policy.ai_model or get("SSM_MODEL") or DEFAULT_MODELS["openai"],
            base_url=base,
            api_key=key,
            origin=origin,
        )

    # ---- egress rule -----------------------------------------------------
    if not policy.ai_allow_cloud and not is_loopback(config.base_url):
        raise ProviderError(
            f"ai.allow_cloud is false in the policy, but provider "
            f"'{config.name}' points at {config.base_url}, which is not this "
            "machine. A diagnosis sends your question and the contents of "
            "local files there, so this is refused."
        )

    return config


def build_provider(
    policy: Policy | None = None,
    environ: dict[str, str] | None = None,
    post: Post | None = None,
    client: Any = None,
) -> Provider:
    """Resolve the configuration and construct the provider."""
    config = choose_provider(policy, environ)

    if config.name == "gemini":
        return GeminiProvider(api_key=config.api_key, model=config.model,
                              client=client)

    return OpenAICompatProvider(
        name=config.name,
        model=config.model,
        base_url=config.base_url,
        api_key=config.api_key,
        post=post,
    )


def _default_policy() -> Policy:
    from policy import DEFAULT_POLICY

    return DEFAULT_POLICY
