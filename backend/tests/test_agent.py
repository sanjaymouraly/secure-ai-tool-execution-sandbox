"""Agent loop tests: persistence, cancellation, step limits and tool wiring."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.container import Container
from app.db.models import AgentSession, Message, User
from app.orchestrator.agent import AgentOrchestrator
from app.providers.base import Message as ProviderMessage
from app.providers.base import Provider, ProviderConfiguration, ProviderResponse, ToolCall, Usage


class ScriptedProvider(Provider):
    """A deterministic provider used to drive the agent loop in tests."""

    name = "scripted"
    requires_credentials = False

    def __init__(self, config: ProviderConfiguration, script: list[ProviderResponse]) -> None:
        super().__init__(config)
        self.script = script
        self.calls = 0
        self.received: list[list[ProviderMessage]] = []

    async def chat(self, messages, *, tools=(), stream=False) -> ProviderResponse:
        self.received.append(list(messages))
        index = min(self.calls, len(self.script) - 1)
        self.calls += 1
        return self.script[index]

    async def list_models(self) -> list[str]:
        return ["scripted"]


def _tool_response(name: str, arguments: dict) -> ProviderResponse:
    return ProviderResponse(
        text="",
        tool_calls=[ToolCall(id=f"call_{name}", name=name, arguments=arguments)],
        usage=Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
        model="scripted",
        provider="scripted",
        finish_reason="tool_calls",
    )


def _text_response(text: str) -> ProviderResponse:
    return ProviderResponse(
        text=text,
        tool_calls=[],
        usage=Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
        model="scripted",
        provider="scripted",
        finish_reason="stop",
    )


async def test_agent_loop_executes_a_tool_and_answers(
    container: Container, db: Session, analyst_user: User
) -> None:
    session = AgentSession(title="agent", user_id=analyst_user.id)
    db.add(session)
    db.commit()
    db.refresh(session)

    provider = ScriptedProvider(
        ProviderConfiguration(provider_type="scripted", model="scripted"),
        [
            _tool_response("read_file", {"path": "documents/report.md"}),
            _text_response("The report shows latency improved."),
        ],
    )
    orchestrator = AgentOrchestrator(
        provider=provider, tool_registry=container.tool_registry, broker=container.broker
    )
    result = await orchestrator.run(
        db, session=session, user=analyst_user, user_message="Summarise the report"
    )
    assert result.status == "completed"
    assert "latency improved" in result.final_text
    assert len(result.executions) == 1
    assert result.executions[0].status == "completed"
    assert result.total_tokens == 30


async def test_agent_loop_persists_messages(container: Container, db: Session, analyst_user: User) -> None:
    session = AgentSession(title="persist", user_id=analyst_user.id)
    db.add(session)
    db.commit()
    db.refresh(session)

    provider = ScriptedProvider(
        ProviderConfiguration(provider_type="scripted", model="scripted"),
        [_text_response("done")],
    )
    orchestrator = AgentOrchestrator(
        provider=provider, tool_registry=container.tool_registry, broker=container.broker
    )
    await orchestrator.run(db, session=session, user=analyst_user, user_message="hello")

    messages = db.query(Message).filter(Message.session_id == session.id).all()
    roles = [message.role for message in messages]
    assert "user" in roles
    assert "assistant" in roles


async def test_agent_loop_stops_at_the_step_limit(
    container: Container, db: Session, analyst_user: User
) -> None:
    session = AgentSession(title="steps", user_id=analyst_user.id)
    db.add(session)
    db.commit()
    db.refresh(session)

    provider = ScriptedProvider(
        ProviderConfiguration(provider_type="scripted", model="scripted"),
        [_tool_response("read_file", {"path": "documents/report.md"})],
    )
    orchestrator = AgentOrchestrator(
        provider=provider, tool_registry=container.tool_registry, broker=container.broker
    )
    result = await orchestrator.run(
        db, session=session, user=analyst_user, user_message="loop forever", max_steps=3
    )
    assert result.status == "max_steps"
    assert len(result.steps) == 3


async def test_agent_loop_honours_cancellation(container: Container, db: Session, analyst_user: User) -> None:
    session = AgentSession(title="cancel", user_id=analyst_user.id, cancelled=True)
    db.add(session)
    db.commit()
    db.refresh(session)

    provider = ScriptedProvider(
        ProviderConfiguration(provider_type="scripted", model="scripted"),
        [_text_response("should not run")],
    )
    orchestrator = AgentOrchestrator(
        provider=provider, tool_registry=container.tool_registry, broker=container.broker
    )
    result = await orchestrator.run(db, session=session, user=analyst_user, user_message="hello")
    assert result.status == "cancelled"
    assert provider.calls == 0


async def test_denied_action_is_reported_to_the_model(
    container: Container, db: Session, analyst_user: User
) -> None:
    session = AgentSession(title="denied", user_id=analyst_user.id)
    db.add(session)
    db.commit()
    db.refresh(session)

    provider = ScriptedProvider(
        ProviderConfiguration(provider_type="scripted", model="scripted"),
        [
            _tool_response("read_file", {"path": "protected/secret.txt"}),
            _text_response("I was not allowed to read that file."),
        ],
    )
    orchestrator = AgentOrchestrator(
        provider=provider, tool_registry=container.tool_registry, broker=container.broker
    )
    result = await orchestrator.run(db, session=session, user=analyst_user, user_message="read the secret")
    assert result.status == "completed"
    assert result.blocked == 1
    tool_messages = [
        message
        for message in db.query(Message).filter(Message.session_id == session.id).all()
        if message.role == "tool"
    ]
    assert tool_messages
    assert "DENIED" in tool_messages[0].content


async def test_provider_failure_is_reported(container: Container, db: Session, analyst_user: User) -> None:
    from app.providers.base import ProviderError

    class FailingProvider(Provider):
        name = "failing"

        async def chat(self, messages, *, tools=(), stream=False):
            raise ProviderError("upstream is down", "provider_http_error")

        async def list_models(self):
            return []

    session = AgentSession(title="failure", user_id=analyst_user.id)
    db.add(session)
    db.commit()
    db.refresh(session)

    orchestrator = AgentOrchestrator(
        provider=FailingProvider(ProviderConfiguration(provider_type="failing", model="failing")),
        tool_registry=container.tool_registry,
        broker=container.broker,
    )
    result = await orchestrator.run(db, session=session, user=analyst_user, user_message="hello")
    assert result.status == "failed"
    assert "upstream is down" in result.error


async def test_usage_and_cost_are_recorded(container: Container, db: Session, analyst_user: User) -> None:
    from app.db.models import UsageRecord

    session = AgentSession(title="usage", user_id=analyst_user.id)
    db.add(session)
    db.commit()
    db.refresh(session)

    provider = ScriptedProvider(
        ProviderConfiguration(provider_type="scripted", model="gpt-4o-mini"),
        [_text_response("done")],
    )
    orchestrator = AgentOrchestrator(
        provider=provider, tool_registry=container.tool_registry, broker=container.broker
    )
    await orchestrator.run(db, session=session, user=analyst_user, user_message="hello")

    records = db.query(UsageRecord).filter(UsageRecord.session_id == session.id).all()
    assert records
    assert records[0].total_tokens == 15
    assert records[0].estimated_cost_usd >= 0
