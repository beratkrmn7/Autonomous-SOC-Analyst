"""Rich, provider-free rendering for the bounded SOC triage brief."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agent.detection.detectors.exposure_helpers import (
    is_critical_management_port,
)
from agent.detection.presentation import BriefActionItem, BriefSelection
from agent.detection.rollup import ExposedAsset, RollupResult
from agent.schema import CanonicalLogEvent
from agent.triage.attack_context import derive_attack_context, render_attack_context
from agent.triage.disposition import (
    EVIDENCE_STRENGTH_RANK,
    EvidenceStrength,
    classify_evidence_strength,
)
from agent.triage.enrichment import BriefEnrichmentResult
from agent.triage.localization import Language, render_item_title


MAX_BRIEF_EVIDENCE_IDS = 3
MAX_BRIEF_ASSETS = 10


def _format_timestamp(value: datetime) -> str:
    return value.isoformat(sep=" ", timespec="seconds")


def _format_duration(seconds: float) -> str:
    total = max(0, int(seconds))
    minutes, remainder = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {remainder:02d}s"
    return f"{minutes}m {remainder:02d}s"


def _source_timezone(
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> timezone | None:
    offsets = sorted(
        {
            value
            for event in event_lookup.values()
            if isinstance(event.parser_metadata, dict)
            if isinstance(
                value := event.parser_metadata.get("source_timezone_offset"), str
            )
        }
    )
    if len(offsets) != 1:
        return None
    value = offsets[0]
    if len(value) != 6 or value[0] not in {"+", "-"} or value[3] != ":":
        return None
    try:
        hours = int(value[1:3])
        minutes = int(value[4:6])
    except ValueError:
        return None
    if hours > 23 or minutes > 59:
        return None
    direction = 1 if value[0] == "+" else -1
    return timezone(direction * timedelta(hours=hours, minutes=minutes))


def _in_source_timezone(value: datetime, source_timezone: timezone) -> datetime:
    # SQLite may hydrate an originally aware UTC value as a naive datetime.
    # Canonical timestamps are normalized to UTC before persistence, so UTC is
    # the only safe interpretation for a naive hydrated value here.
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(source_timezone)


def _asset_evidence_strength(
    rollup: RollupResult,
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> dict[str, EvidenceStrength]:
    """Evidence strength per exposed asset, from its exposure events only.

    Scoped to the externally allowed inbound events the roll-up actually built
    the row from. Blocked scans, internal traffic, context events and other
    unrelated flows to the same destination and port must never strengthen an
    asset or raise its priority.
    """
    return {
        asset.effective_destination_ip: classify_evidence_strength(
            [
                event
                for event_id in asset.exposure_event_ids
                if (event := event_lookup.get(event_id)) is not None
            ]
        )
        for asset in rollup.exposed_assets
    }


def _asset_priority(asset: ExposedAsset, strength: EvidenceStrength) -> str:
    critical_management = is_critical_management_port(
        asset.ports[0] if asset.ports else None
    )
    if critical_management:
        return "P1" if strength in _STRONG_STRENGTHS else "P2"
    return "P2" if strength not in _WEAK_STRENGTHS else "P3"


def _asset_risk_key(
    asset: ExposedAsset, strengths: Mapping[str, EvidenceStrength]
) -> tuple:
    strength = strengths.get(
        asset.effective_destination_ip, EvidenceStrength.SYN_ONLY
    )
    return (
        _asset_priority(asset, strength),
        -EVIDENCE_STRENGTH_RANK[strength],
        -asset.distinct_external_source_count,
        asset.effective_destination_ip,
    )


_STRONG_STRENGTHS = frozenset(
    {
        EvidenceStrength.BIDIRECTIONAL_TRANSPORT,
        EvidenceStrength.APPLICATION_EVIDENCE,
    }
)
_WEAK_STRENGTHS = frozenset(
    {EvidenceStrength.SYN_ONLY, EvidenceStrength.SINGLE_PACKET_NON_SYN}
)


# Static UI strings only. Deterministic facts - IDs, addresses, ports,
# severity enum values, evidence-strength values and ATT&CK identifiers - are
# never translated, so both languages cite exactly the same evidence.
_LABELS: dict[str, dict[str, str]] = {
    "en": {
        # Header
        "brief_title": "SOC TRIAGE BRIEF",
        "source": "Source",
        "window": "Window",
        "run": "Run",
        "generated": "Generated",
        "not_persisted": "not persisted",
        "unknown_window": "unknown",
        # Funnel
        "funnel": "FUNNEL",
        "funnel_events": "events",
        "funnel_blocked": "blocked",
        "funnel_exposures": "policy exposures",
        "funnel_actions": "action items",
        # Summary
        "summary_title": "ANALYST SUMMARY",
        "summary_sentence": (
            "{act_now} high-priority item(s), {investigate} investigation "
            "item(s), {recon} fully blocked reconnaissance group(s), and "
            "{assets} exposed asset/service row(s). Firewall pass proves "
            "policy exposure only; it does not prove authentication, "
            "exploitation, or compromise."
        ),
        # Sections
        "act_now": "§1 ACT NOW",
        "investigate": "§2 INVESTIGATE",
        "blocked_fyi": "§3 BLOCKED — FYI",
        "suppressed": "§4 SUPPRESSED",
        "inventory": "§5 EXPOSED ASSET INVENTORY",
        # Action table
        "priority": "Priority",
        "what": "What happened / observed flow",
        "events": "Events",
        "why": "Why it matters / next steps",
        "empty": "No items in this section.",
        "evidence": "Evidence",
        "strength": "Evidence strength",
        "members": "Grouped canonical incidents",
        "destinations": "destination(s)",
        "shared": "Applies to every item above",
        "review": "NEEDS REVIEW",
        "unknown_source": "unknown source",
        "unknown_destination": "unknown destination",
        "unknown_port": "unknown port",
        "allowed": "ALLOWED",
        "blocked": "BLOCKED",
        "packets_short": "pkt",
        "none": "none",
        # Recon table
        "recon_source_scope": "Source scope",
        "recon_family_scope": "Family / service scope",
        "recon_sources": "Sources",
        "recon_targets": "Targets",
        "recon_ports": "Ports",
        "recon_events": "Events",
        "recon_empty": "No fully blocked recon groups",
        # Suppressed table
        "suppressed_source": "Source",
        "suppressed_targets": "Targets",
        "suppressed_reason": "Reason",
        "suppressed_events": "Events",
        "suppressed_empty": "No suppressed signals",
        "unknown": "unknown",
        # Inventory table
        "asset_priority": "Priority",
        "asset_destination": "Effective destination",
        "asset_service": "Service / ports",
        "asset_strength": "Evidence strength",
        "asset_sources": "Sources",
        "asset_nat": "NAT / public destination",
        "asset_empty": "No exposed sensitive services",
        "no_nat": "no NAT",
        "public_unknown": "public address unknown",
        "assets_truncated": (
            "{count} additional asset/service row(s) remain available in the "
            "full canonical result."
        ),
        # Footer
        "provider_calls": "Provider calls for this request",
    },
    "tr": {
        # Header
        "brief_title": "SOC TRİYAJ ÖZETİ",
        "source": "Kaynak",
        "window": "Zaman aralığı",
        "run": "Çalıştırma",
        "generated": "Oluşturulma",
        "not_persisted": "kaydedilmedi",
        "unknown_window": "bilinmiyor",
        # Funnel
        "funnel": "HUNİ",
        "funnel_events": "olay",
        "funnel_blocked": "engellendi",
        "funnel_exposures": "politika açığı",
        "funnel_actions": "aksiyon maddesi",
        # Summary
        "summary_title": "ANALİST ÖZETİ",
        "summary_sentence": (
            "{act_now} yüksek öncelikli madde, {investigate} inceleme "
            "maddesi, {recon} tamamen engellenmiş keşif grubu ve {assets} "
            "açığa çıkan varlık/servis satırı. Güvenlik duvarının izin "
            "vermesi yalnızca politika açığını kanıtlar; kimlik doğrulamayı, "
            "istismarı veya ele geçirilmeyi kanıtlamaz."
        ),
        # Sections
        "act_now": "§1 HEMEN AKSİYON AL",
        "investigate": "§2 İNCELE",
        "blocked_fyi": "§3 ENGELLENDİ — BİLGİ",
        "suppressed": "§4 BASTIRILAN",
        "inventory": "§5 AÇIĞA ÇIKAN VARLIK ENVANTERİ",
        # Action table
        "priority": "Öncelik",
        "what": "Ne oldu / gözlenen akış",
        "events": "Olaylar",
        "why": "Neden önemli / sonraki adımlar",
        "empty": "Bu bölümde öğe yok.",
        "evidence": "Kanıt",
        "strength": "Kanıt gücü",
        "members": "Gruplanan kanonik olaylar",
        "destinations": "hedef",
        "shared": "Yukarıdaki tüm maddeler için geçerli",
        "review": "İNCELEME GEREKLİ",
        "unknown_source": "kaynak bilinmiyor",
        "unknown_destination": "hedef bilinmiyor",
        "unknown_port": "port bilinmiyor",
        "allowed": "İZİN VERİLDİ",
        "blocked": "ENGELLENDİ",
        "packets_short": "paket",
        "none": "yok",
        # Recon table
        "recon_source_scope": "Kaynak kapsamı",
        "recon_family_scope": "Aile / servis kapsamı",
        "recon_sources": "Kaynaklar",
        "recon_targets": "Hedefler",
        "recon_ports": "Portlar",
        "recon_events": "Olaylar",
        "recon_empty": "Tamamen engellenmiş keşif grubu yok",
        # Suppressed table
        "suppressed_source": "Kaynak",
        "suppressed_targets": "Hedefler",
        "suppressed_reason": "Sebep",
        "suppressed_events": "Olaylar",
        "suppressed_empty": "Bastırılan sinyal yok",
        "unknown": "bilinmiyor",
        # Inventory table
        "asset_priority": "Öncelik",
        "asset_destination": "Etkin hedef",
        "asset_service": "Servis / portlar",
        "asset_strength": "Kanıt gücü",
        "asset_sources": "Kaynaklar",
        "asset_nat": "NAT / genel hedef",
        "asset_empty": "Açığa çıkan hassas servis yok",
        "no_nat": "NAT yok",
        "public_unknown": "genel adres bilinmiyor",
        "assets_truncated": (
            "{count} ek varlık/servis satırı tam kanonik sonuçta mevcuttur."
        ),
        # Footer
        "provider_calls": "Bu istek için sağlayıcı çağrısı",
    },
}


def _priority(severity: str) -> str:
    if severity == "critical":
        return "P1"
    if severity == "high":
        return "P2"
    if severity == "medium":
        return "P3"
    return "P4"


def _item_flow(item: BriefActionItem, labels: dict[str, str]) -> str:
    sources = list(item.source_ips[:2])
    source_text = ", ".join(sources) or labels["unknown_source"]
    if item.source_count > len(sources):
        source_text += f" (+{item.source_count - len(sources)})"
    destinations = list(item.effective_destinations[:2])
    destination_text = ", ".join(destinations) or labels["unknown_destination"]
    port_text = ",".join(str(port) for port in item.ports[:6]) or labels["unknown_port"]
    if item.allowed_event_count and item.blocked_event_count:
        action_text = (
            f"{item.allowed_event_count} {labels['allowed']} / "
            f"{item.blocked_event_count} {labels['blocked']}"
        )
    elif item.allowed_event_count:
        action_text = labels["allowed"]
    else:
        action_text = labels["blocked"]
    nat_text = " · NAT" if item.nat_observed else ""
    return (
        f"{source_text} -> {destination_text}:{port_text} · {action_text}{nat_text}\n"
        f"{item.destination_count} {labels['destinations']}"
    )


def _item_attack_context(item: BriefActionItem, lang: Language) -> str:
    context = derive_attack_context(
        incident_family=item.incident_family,
        service=item.service,
        evidence_strength=item.evidence_strength,
        distinct_port_count=len(item.ports),
        distinct_destination_count=item.destination_count,
    )
    return render_attack_context(context, lang)


def _shared_actions(
    items: Sequence[BriefActionItem],
    enrichment: BriefEnrichmentResult | None,
    lang: Language,
) -> list[str]:
    """Actions every row repeats, so they can be shown once per section."""
    if enrichment is None or len(items) < 2:
        return []
    per_item: list[set[str]] = []
    for item in items:
        entry = enrichment.for_item(item.item_id)
        if entry is None:
            return []
        actions = (
            entry.recommended_actions_tr if lang == "tr" else entry.recommended_actions_en
        )
        per_item.append(set(actions))
    if not per_item:
        return []
    shared = set.intersection(*per_item)
    # Only pull an action out of the rows if something row-specific remains.
    if any(len(actions - shared) == 0 for actions in per_item):
        return []
    return sorted(shared)


def _action_table(
    title: str,
    items: Sequence[BriefActionItem],
    enrichment: BriefEnrichmentResult | None,
    lang: Language,
    shared: Sequence[str] = (),
) -> Table:
    labels = _LABELS[lang]
    table = Table(title=title, expand=True, show_lines=True)
    table.add_column(labels["priority"], no_wrap=True)
    table.add_column(labels["what"], ratio=3)
    table.add_column(labels["events"], no_wrap=True)
    table.add_column(labels["why"], ratio=3)

    for item in items:
        priority = _priority(item.severity)
        severity_text = item.severity.upper()
        if item.verdict == "needs_review":
            severity_text = f"{severity_text}\n{labels['review']}"
        event_summary = str(item.event_count)
        if item.packet_count:
            event_summary += f"\n{item.packet_count} {labels['packets_short']}"

        entry = enrichment.for_item(item.item_id) if enrichment else None
        if entry is not None:
            explanation = (
                entry.explanation_tr if lang == "tr" else entry.explanation_en
            )
            actions = list(
                entry.recommended_actions_tr
                if lang == "tr"
                else entry.recommended_actions_en
            )
        else:
            explanation = ""
            actions = []
        actions = [action for action in actions if action not in set(shared)]

        # The evidence-strength value is a deterministic enum, never translated.
        strength_text = (
            item.evidence_strength.value
            if item.evidence_strength
            else labels["unknown"]
        )
        evidence_text = (
            ", ".join(item.evidence_ids[:MAX_BRIEF_EVIDENCE_IDS]) or labels["none"]
        )
        why_lines = [explanation] if explanation else []
        why_lines.append(_item_attack_context(item, lang))
        why_lines.extend(f"- {action}" for action in actions)
        why_lines.append(f"{labels['evidence']}: {evidence_text}")

        # The canonical English title is the stored identity; the row shows a
        # deterministic language-aware display title instead.
        what_lines = [render_item_title(item, lang), _item_flow(item, labels)]
        what_lines.append(f"{labels['strength']}: {strength_text}")
        if item.member_incident_count > 1:
            what_lines.append(
                f"{labels['members']}: {item.member_incident_count}"
            )

        table.add_row(
            f"[{priority}]\n{severity_text}\nconf {item.confidence:.2f}",
            "\n".join(what_lines),
            event_summary,
            "\n".join(why_lines),
        )

    if not items:
        table.add_row("-", labels["empty"], "0", "-")
    return table


def render_soc_brief(
    console: Console,
    *,
    rollup: RollupResult,
    event_lookup: Mapping[str, CanonicalLogEvent],
    source_name: str,
    job_id: str | None,
    provider_call_count: int,
    selection: BriefSelection | None = None,
    enrichment: BriefEnrichmentResult | None = None,
    lang: Language = "en",
    generated_at: datetime | None = None,
) -> None:
    """Render the brief from deterministic rows plus persisted enrichment text.

    Provider-free by construction: it receives the deterministic rollup, the
    deterministic selection and an already-persisted enrichment artifact, and
    only chooses which language to display. Rendering never triggers a call.
    """
    labels = _LABELS[lang]
    generated_at = generated_at or datetime.now().astimezone()
    timestamps = sorted(
        event.timestamp for event in event_lookup.values() if event.timestamp is not None
    )
    if timestamps:
        first_seen, last_seen = timestamps[0], timestamps[-1]
        source_timezone = _source_timezone(event_lookup)
        if source_timezone is not None:
            first_seen = _in_source_timezone(first_seen, source_timezone)
            last_seen = _in_source_timezone(last_seen, source_timezone)
        window = (
            f"{_format_timestamp(first_seen)} - {_format_timestamp(last_seen)} | "
            f"{_format_duration((last_seen - first_seen).total_seconds())}"
        )
    else:
        window = labels["unknown_window"]

    header = (
        f"{labels['brief_title']}\n"
        f"{labels['source']}: {source_name}\n"
        f"{labels['window']}: {window}\n"
        f"{labels['run']}: {job_id or labels['not_persisted']} | "
        f"{labels['generated']}: {_format_timestamp(generated_at)}"
    )
    console.print(Panel(header, border_style="cyan"))

    funnel = rollup.funnel
    console.print(
        Text(
            f"{labels['funnel']}  "
            f"{funnel.get('total_events', 0):,} {labels['funnel_events']} -> "
            f"{funnel.get('blocked_events', 0):,} {labels['funnel_blocked']} -> "
            f"{funnel.get('policy_exposures', 0):,} {labels['funnel_exposures']} -> "
            f"{funnel.get('action_items', 0):,} {labels['funnel_actions']}",
            style="bold",
        )
    )
    act_now_items = selection.act_now if selection is not None else ()
    investigate_items = selection.investigate if selection is not None else ()

    summary = labels["summary_sentence"].format(
        act_now=len(act_now_items),
        investigate=len(investigate_items),
        recon=len(rollup.recon_groups),
        assets=len(rollup.exposed_assets),
    )
    console.print(
        Panel(summary, title=labels["summary_title"], border_style="yellow")
    )

    for title, items in (
        (labels["act_now"], act_now_items),
        (labels["investigate"], investigate_items),
    ):
        shared = _shared_actions(items, enrichment, lang)
        console.print(_action_table(title, items, enrichment, lang, shared))
        if shared:
            # Shown once instead of repeated on every row above.
            console.print(
                Text(f"{labels['shared']}: " + " | ".join(shared), style="dim")
            )

    recon = Table(title=labels["blocked_fyi"], expand=True)
    recon.add_column(labels["recon_source_scope"])
    recon.add_column(labels["recon_family_scope"])
    recon.add_column(labels["recon_sources"], justify="right")
    recon.add_column(labels["recon_targets"], justify="right")
    recon.add_column(labels["recon_ports"])
    recon.add_column(labels["recon_events"], justify="right")
    for group in rollup.recon_groups:
        ports = ",".join(str(port) for port in group.ports[:8]) or labels["none"]
        # A single contributing source is shown as its exact address; a CIDR
        # is only honest when several exact sources are actually present.
        if group.source_count == 1 and group.representative_sources:
            source_text = group.representative_sources[0]
        else:
            source_text = group.source_cidr
        recon.add_row(
            source_text,
            f"{group.incident_family} / {group.service_scope}",
            str(group.source_count),
            str(group.distinct_target_count),
            ports,
            str(group.total_event_count),
        )
    if not rollup.recon_groups:
        recon.add_row("-", labels["recon_empty"], "0", "0", "-", "0")
    console.print(recon)

    suppressed = Table(title=labels["suppressed"], expand=True)
    suppressed.add_column(labels["suppressed_source"])
    suppressed.add_column(labels["suppressed_targets"])
    suppressed.add_column(labels["suppressed_reason"])
    suppressed.add_column(labels["suppressed_events"], justify="right")
    for suppressed_entry in rollup.suppressed:
        suppressed.add_row(
            suppressed_entry.source,
            ", ".join(suppressed_entry.targets) or labels["unknown"],
            suppressed_entry.reason,
            str(suppressed_entry.event_count),
        )
    if not rollup.suppressed:
        suppressed.add_row("-", "-", labels["suppressed_empty"], "0")
    console.print(suppressed)

    assets = Table(title=labels["inventory"], expand=True)
    assets.add_column(labels["asset_priority"], no_wrap=True)
    assets.add_column(labels["asset_destination"])
    assets.add_column(labels["asset_service"])
    assets.add_column(labels["asset_strength"])
    assets.add_column(labels["asset_sources"], justify="right")
    assets.add_column(labels["asset_nat"])
    asset_strength = _asset_evidence_strength(rollup, event_lookup)
    ordered_assets = sorted(
        rollup.exposed_assets,
        key=lambda asset: _asset_risk_key(asset, asset_strength),
    )
    for exposed_asset in ordered_assets[:MAX_BRIEF_ASSETS]:
        nat_text = labels["no_nat"]
        if exposed_asset.nat_observed:
            public = (
                ", ".join(exposed_asset.public_destinations)
                or labels["public_unknown"]
            )
            nat_text = (
                f"{public} -> "
                f"{exposed_asset.internal_address or exposed_asset.effective_destination_ip}"
            )
        strength = asset_strength.get(
            exposed_asset.effective_destination_ip, EvidenceStrength.SYN_ONLY
        )
        assets.add_row(
            _asset_priority(exposed_asset, strength),
            exposed_asset.effective_destination_ip,
            f"{exposed_asset.service} / "
            f"{','.join(str(port) for port in exposed_asset.ports)}",
            strength.value,
            str(exposed_asset.distinct_external_source_count),
            nat_text,
        )
    if not rollup.exposed_assets:
        assets.add_row("-", "-", labels["asset_empty"], "-", "0", "-")
    console.print(assets)
    if len(rollup.exposed_assets) > MAX_BRIEF_ASSETS:
        truncated = labels["assets_truncated"].format(
            count=len(rollup.exposed_assets) - MAX_BRIEF_ASSETS
        )
        console.print(f"[dim]{truncated}[/dim]")
    console.print(f"{labels['provider_calls']}: {provider_call_count}")
