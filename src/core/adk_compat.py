"""Small compatibility layer for optional Google ADK dependencies.

The lab is designed for Google ADK, but local grading and report generation
should still run when the ADK packages or a Google API key are not available.
This module exposes the ADK names used by the lab and falls back to tiny
in-memory stand-ins that support the callbacks exercised by our tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace


try:
    from google.genai import types as genai_types

    types = genai_types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

    class _Part:
        """Fallback content part used so guardrail plugins can run offline."""

        def __init__(self, text: str | None = None):
            self.text = text

        @classmethod
        def from_text(cls, text: str):
            """Create a text part with the same call shape as google.genai."""
            return cls(text=text)

    class _Content:
        """Fallback chat content container compatible with plugin callbacks."""

        def __init__(self, role: str | None = None, parts: list | None = None):
            self.role = role
            self.parts = parts or []

    types = SimpleNamespace(Part=_Part, Content=_Content)


try:
    from google.adk.plugins import base_plugin
    from google.adk.agents.invocation_context import InvocationContext
    from google.adk.agents import llm_agent
    from google.adk import runners

    ADK_AVAILABLE = True
except ImportError:
    ADK_AVAILABLE = False

    class _BasePlugin:
        """Fallback plugin base that keeps the ADK plugin constructor shape."""

        def __init__(self, name: str | None = None):
            self.name = name or self.__class__.__name__

    base_plugin = SimpleNamespace(BasePlugin=_BasePlugin)

    @dataclass
    class InvocationContext:
        """Fallback invocation context carrying the user id for callbacks."""

        user_id: str = "student"

    class _LlmAgent:
        """Fallback agent that stores model metadata and instructions offline."""

        def __init__(self, model: str, name: str, instruction: str):
            self.model = model
            self.name = name
            self.instruction = instruction

    @dataclass
    class _Session:
        """Fallback session record used by the in-memory runner."""

        id: str

    class _SessionService:
        """Fallback session registry matching the methods used by utils.py."""

        def __init__(self):
            self._sessions = {}
            self._next_id = 1

        async def get_session(self, app_name: str, user_id: str, session_id: str):
            """Return an existing session or raise KeyError if it is missing."""
            key = (app_name, user_id, session_id)
            if key not in self._sessions:
                raise KeyError(session_id)
            return self._sessions[key]

        async def create_session(self, app_name: str, user_id: str):
            """Create a new session so offline chat keeps ADK's call shape."""
            session = _Session(id=f"offline-session-{self._next_id}")
            self._next_id += 1
            self._sessions[(app_name, user_id, session.id)] = session
            return session

    class _InMemoryRunner:
        """Fallback runner that stores plugins for offline callback execution."""

        def __init__(self, agent, app_name: str, plugins: list | None = None):
            self.agent = agent
            self.app_name = app_name
            self.plugins = plugins or []
            self.session_service = _SessionService()
            self.is_stub_runner = True

    llm_agent = SimpleNamespace(LlmAgent=_LlmAgent)
    runners = SimpleNamespace(InMemoryRunner=_InMemoryRunner)

