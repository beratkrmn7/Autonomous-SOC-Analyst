from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from sqlalchemy import event, insert

from agent.application.archive import ArchiveService
from agent.archive.io import ArchiveReader
from agent.persistence.orm_models import CanonicalEvent
from agent.persistence.unit_of_work import UnitOfWork
from tests.archive.conftest import ARCHIVE_ID, NOW, make_environment


def test_ten_thousand_candidates_use_bounded_keyset_queries(tmp_path) -> None:
    environment = make_environment(tmp_path)
    settings = environment.settings.model_copy(
        update={"retention_archive_batch_size": 1_000}
    )
    rows = [
        {
            "event_id": f"bulk-event-{index:05d}",
            "timestamp": NOW - timedelta(days=60),
        }
        for index in range(10_000)
    ]
    with environment.session_factory() as session:
        session.execute(insert(CanonicalEvent), rows)
        session.commit()

    statements: list[tuple[str, object]] = []

    def capture_statement(
        _connection,
        _cursor,
        statement,
        parameters,
        _context,
        _executemany,
    ) -> None:
        if statement.lstrip().lower().startswith("select"):
            statements.append((" ".join(statement.lower().split()), parameters))

    event.listen(environment.engine, "before_cursor_execute", capture_statement)
    try:
        result = ArchiveService(
            lambda: UnitOfWork(environment.session_factory),
            environment.store,
            settings,
            clock=lambda: NOW,
            archive_id_factory=lambda: ARCHIVE_ID,
        ).create()
    finally:
        event.remove(environment.engine, "before_cursor_execute", capture_statement)

    try:
        assert result.candidate_record_count == 10_000
        assert result.dependency_record_count == 0
        candidate_queries = [
            sql
            for sql, _parameters in statements
            if "from canonical_events" in sql
            and "order by canonical_events.timestamp asc, "
            "canonical_events.event_id asc" in sql
        ]
        assert len(candidate_queries) == 11
        assert all(" limit " in sql for sql in candidate_queries)
        assert all(
            not sql.endswith(" offset ?")
            or isinstance(parameters, tuple)
            and parameters[-1] == 0
            for sql, parameters in statements
        )
        assert len(statements) <= 55
        assert sum(
            1
            for record in ArchiveReader(environment.store).iter_records(ARCHIVE_ID)
            if record.archive_role == "retention_candidate"
        ) == 10_000

        for repository in (
            Path("agent/persistence/retention_repository.py"),
            Path("agent/persistence/archive_repository.py"),
        ):
            source = repository.read_text(encoding="utf-8")
            assert ".all(" not in source
            assert ".offset(" not in source
    finally:
        environment.engine.dispose()
