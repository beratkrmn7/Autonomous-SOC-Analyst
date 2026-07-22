from datetime import datetime, timezone

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

from agent.persistence.mappers import DataMapper
from agent.schema import CanonicalLogEvent


REVISION = "4c1d8e6f2a90"
PREVIOUS_REVISION = "9f2a4c7e1d83"
NETWORK_COLUMNS = {
    "action_reason",
    "tcp_flags",
    "inbound_interface",
    "outbound_interface",
    "inbound_zone",
    "outbound_zone",
    "source_fqdns",
    "destination_fqdns",
    "bytes",
    "packets",
    "duration_ms",
    "nat_type",
    "translated_src_ip",
    "translated_dst_ip",
    "translated_src_port",
    "translated_dst_port",
    "parser_metadata",
}


def test_canonical_event_network_fields_round_trip() -> None:
    event = CanonicalLogEvent(
        event_id="EVT-ROUNDTRIP",
        timestamp=datetime(2026, 7, 10, 9, 53, tzinfo=timezone.utc),
        observed_at=datetime(2026, 7, 10, 9, 54, tzinfo=timezone.utc),
        src_ip="198.51.100.17",
        dst_ip="203.0.113.25",
        src_port=443,
        dst_port=22,
        protocol="tcp",
        action="pass",
        action_reason="match",
        tcp_flags="RST,ACK",
        inbound_interface="wan0",
        outbound_interface="lan0",
        inbound_zone="wan1-zone",
        outbound_zone="internal-zone",
        source_fqdns=["source.example.test"],
        destination_fqdns=["target.example.test"],
        source_username="analyst",
        bytes=4096,
        packets=12,
        duration_ms=875,
        nat_type="dnat",
        translated_src_ip="198.51.100.18",
        translated_dst_ip="10.0.0.25",
        translated_src_port=8443,
        translated_dst_port=22,
        parser_name="pf_firewall",
        parser_version="2.2.0",
        parse_status="parsed",
        source_name="roundtrip.jsonl",
        source_line=7,
        raw_record_hash="a" * 64,
        safe_message_excerpt="PASS TCP test record",
        parser_metadata={
            "original_device_action": "pass",
            "spi_anomaly": False,
            "tcp_flags_present": True,
            "original_tcp_flags": "AR",
            "tcp_flag_tokens": ["RST", "ACK"],
            "tcp_flags_explicit_none": False,
            "pf_event_type": "natural",
            "source_timezone_offset": "+03:00",
        },
    )

    hydrated = DataMapper.orm_to_domain_event(DataMapper.domain_event_to_orm(event))

    for field in (
        "action_reason",
        "tcp_flags",
        "inbound_interface",
        "outbound_interface",
        "inbound_zone",
        "outbound_zone",
        "source_fqdns",
        "destination_fqdns",
        "bytes",
        "packets",
        "duration_ms",
        "nat_type",
        "translated_src_ip",
        "translated_dst_ip",
        "translated_src_port",
        "translated_dst_port",
        "parser_metadata",
    ):
        assert getattr(hydrated, field) == getattr(event, field)


def test_event_persistence_bounds_collections_and_allowlists_metadata() -> None:
    event = CanonicalLogEvent(
        event_id="EVT-BOUNDED",
        timestamp=datetime(2026, 7, 10, 9, 53, tzinfo=timezone.utc),
        parser_name="pf_firewall",
        parse_status="parsed",
        source_fqdns=[f"source-{index}.example.test" for index in range(30)],
        destination_fqdns=["target.example.test", "target.example.test"],
        parser_metadata={
            "spi_anomaly": True,
            "tcp_flag_tokens": ["RST", "ACK", "ACK"],
            "source_timezone_offset": "+03:00",
            "raw_record": {"secret": "must-not-persist"},
            "secret_token": "must-not-persist",
        },
    )

    orm_event = DataMapper.domain_event_to_orm(event)

    assert len(orm_event.source_fqdns) == 20
    assert orm_event.destination_fqdns == ["target.example.test"]
    assert orm_event.parser_metadata == {
        "spi_anomaly": True,
        "source_timezone_offset": "+03:00",
        "tcp_flag_tokens": ["RST", "ACK"],
    }


def test_event_network_field_migration_upgrade_downgrade_and_single_head(
    tmp_path,
) -> None:
    database_path = tmp_path / "canonical-event-fields.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    script = ScriptDirectory.from_config(config)
    assert script.get_heads() == [REVISION]

    command.upgrade(config, "head")
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        columns = {
            column["name"]
            for column in inspector.get_columns("canonical_events")
        }
        assert NETWORK_COLUMNS <= columns
        assert "ix_canonical_events_inbound_zone" in {
            index["name"]
            for index in inspector.get_indexes("canonical_events")
        }
    finally:
        engine.dispose()

    command.downgrade(config, PREVIOUS_REVISION)
    engine = create_engine(database_url)
    try:
        columns = {
            column["name"]
            for column in inspect(engine).get_columns("canonical_events")
        }
        assert NETWORK_COLUMNS.isdisjoint(columns)
    finally:
        engine.dispose()
