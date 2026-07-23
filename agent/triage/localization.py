"""Language-aware presentation text for deterministic rows.

Only *surrounding presentation text* is localized. Deterministic values are
rendered identically in every language and never translated:

* IP addresses and ports
* incident, signal, evidence and item IDs
* service identifiers (``ssh``, ``redis``, ``docker``, ...)
* severity, verdict and evidence-strength enum values
* ATT&CK technique and tactic IDs (``T1046``, ``TA0007``, ``T1133``, ``TA0001``)

Nothing here reaches persistence. The stored deterministic report and the
stored enrichment artifact are written once in their canonical form; these
helpers only decide how an already-persisted analysis is displayed, so
switching language never triggers a provider call or changes any security
decision.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, Optional

from agent.detection.detectors.scan_helpers import classify_service, is_blocked
from agent.detection.models import IncidentBundle
from agent.schema import CanonicalLogEvent


Language = Literal["en", "tr"]

DEFAULT_LANGUAGE: Language = "en"


def normalize_language(value: object) -> Language:
    return "tr" if str(value).lower() == "tr" else "en"


# ---------------------------------------------------------------------------
# Incident-type display names.
# ---------------------------------------------------------------------------

_INCIDENT_TYPE_LABELS: dict[str, dict[str, str]] = {
    "en": {
        "inbound_sensitive_service_allowed": "Externally allowed sensitive service",
        "critical_management_service_exposed": "Critical management service exposed",
        "dnat_sensitive_service_exposure": "Published internal service (NAT)",
        "wan_to_lan_sensitive_service_allowed": "External access permitted into LAN",
        "wan_to_dmz_administrative_service_allowed": (
            "External administrative access permitted into DMZ"
        ),
        "multi_source_allowed_sensitive_service": (
            "Sensitive service permitted from several sources"
        ),
        "blocked_then_allowed_same_service": "Blocked then permitted on one service",
        "scan_followed_by_allowed_connection": "Scan followed by a permitted connection",
        "spi_followed_by_allowed_connection": (
            "Firewall state anomaly followed by a permitted connection"
        ),
        "fixed_source_port_scan": "Fixed source port service enumeration",
        "vertical_scan": "Port sweep against one host",
        "horizontal_scan": "Host sweep on one service",
        "subnet_sweep": "Subnet sweep",
        "distributed_scan": "Distributed scan",
        "multi_service_sweep": "Multi-service sweep",
        "repeated_blocked_scanner": "Repeatedly blocked scanner",
        "low_and_slow_horizontal_scan": "Low-and-slow host sweep",
        "low_and_slow_vertical_scan": "Low-and-slow port sweep",
        "internal_lateral_scan": "Internal lateral scan",
        "network_flood": "Network flood",
        "remote_service_probe": "Remote access service probe",
        "database_service_probe": "Database service probe",
        "docker_daemon_probe": "Container daemon probe",
        "kubernetes_service_probe": "Kubernetes service probe",
        "smb_probe": "SMB probe",
        "vnc_probe": "VNC probe",
        "winrm_probe": "WinRM probe",
        "web_admin_panel_probe": "Web admin panel probe",
        "legacy_cleartext_service_probe": "Cleartext service probe",
        "spi_anomaly": "Firewall state anomaly",
        "tcp_null_scan": "TCP NULL scan",
        "tcp_xmas_scan": "TCP Xmas scan",
        "tcp_fin_scan": "TCP FIN scan",
        "tcp_ack_scan": "TCP ACK scan",
        "tcp_syn_fin_anomaly": "TCP SYN/FIN anomaly",
        "tcp_syn_rst_anomaly": "TCP SYN/RST anomaly",
        "repeated_tcp_reset_anomaly": "Repeated TCP reset anomaly",
        "other": "Observed activity",
    },
    "tr": {
        "inbound_sensitive_service_allowed": "Dışarıya izin verilen hassas servis",
        "critical_management_service_exposed": "Kritik yönetim servisi açığa çıktı",
        "dnat_sensitive_service_exposure": "Yayınlanan iç servis (NAT)",
        "wan_to_lan_sensitive_service_allowed": "LAN'a dış erişime izin verildi",
        "wan_to_dmz_administrative_service_allowed": (
            "DMZ'ye dış yönetim erişimine izin verildi"
        ),
        "multi_source_allowed_sensitive_service": (
            "Birden çok kaynaktan izin verilen hassas servis"
        ),
        "blocked_then_allowed_same_service": (
            "Aynı serviste önce engellendi sonra izin verildi"
        ),
        "scan_followed_by_allowed_connection": (
            "Taramanın ardından izin verilen bağlantı"
        ),
        "spi_followed_by_allowed_connection": (
            "Güvenlik duvarı durum anomalisinin ardından izin verilen bağlantı"
        ),
        "fixed_source_port_scan": "Sabit kaynak porttan servis taraması",
        "vertical_scan": "Tek sunucuya port taraması",
        "horizontal_scan": "Tek serviste sunucu taraması",
        "subnet_sweep": "Alt ağ taraması",
        "distributed_scan": "Dağıtık tarama",
        "multi_service_sweep": "Çoklu servis taraması",
        "repeated_blocked_scanner": "Tekrarlı engellenen tarayıcı",
        "low_and_slow_horizontal_scan": "Yavaş ve sinsi sunucu taraması",
        "low_and_slow_vertical_scan": "Yavaş ve sinsi port taraması",
        "internal_lateral_scan": "İç ağda yatay tarama",
        "network_flood": "Ağ taşkını",
        "remote_service_probe": "Uzak erişim servisi yoklaması",
        "database_service_probe": "Veritabanı servisi yoklaması",
        "docker_daemon_probe": "Konteyner servisi yoklaması",
        "kubernetes_service_probe": "Kubernetes servisi yoklaması",
        "smb_probe": "SMB yoklaması",
        "vnc_probe": "VNC yoklaması",
        "winrm_probe": "WinRM yoklaması",
        "web_admin_panel_probe": "Web yönetim paneli yoklaması",
        "legacy_cleartext_service_probe": "Şifresiz servis yoklaması",
        "spi_anomaly": "Güvenlik duvarı durum anomalisi",
        "tcp_null_scan": "TCP NULL taraması",
        "tcp_xmas_scan": "TCP Xmas taraması",
        "tcp_fin_scan": "TCP FIN taraması",
        "tcp_ack_scan": "TCP ACK taraması",
        "tcp_syn_fin_anomaly": "TCP SYN/FIN anomalisi",
        "tcp_syn_rst_anomaly": "TCP SYN/RST anomalisi",
        "repeated_tcp_reset_anomaly": "Tekrarlı TCP sıfırlama anomalisi",
        "other": "Gözlenen etkinlik",
    },
}

_UNKNOWN_TYPE_LABEL = {
    "en": "Detected activity",
    "tr": "Tespit edilen etkinlik",
}

_TITLE_TEMPLATES = {
    "en": {
        "exposure_group": "{type_label} ({service}) from {source}",
        "exposure_group_no_source": "{type_label} ({service})",
        "scan_cluster": "{type_label} on source port {port}",
        "incident_with_source": "{type_label} from {source}",
        "incident": "{type_label}",
    },
    "tr": {
        "exposure_group": "{type_label} ({service}) - kaynak {source}",
        "exposure_group_no_source": "{type_label} ({service})",
        "scan_cluster": "{type_label} - kaynak port {port}",
        "incident_with_source": "{type_label} - kaynak {source}",
        "incident": "{type_label}",
    },
}


def incident_type_label(incident_type: str, lang: Language) -> str:
    """A display name for a deterministic incident type.

    The type identifier itself is never translated when it is unknown; it is
    shown verbatim so the row still names the exact deterministic type.
    """
    labels = _INCIDENT_TYPE_LABELS.get(lang, _INCIDENT_TYPE_LABELS["en"])
    known = labels.get(incident_type)
    if known:
        return known
    unknown = _UNKNOWN_TYPE_LABEL.get(lang, _UNKNOWN_TYPE_LABEL["en"])
    return f"{unknown}: {incident_type}"


def render_item_title(item: object, lang: Language) -> str:
    """Build a deterministic, language-aware title for one brief row.

    Derived from the row's kind, incident type and service - never from the
    canonical English ``title`` field, which stays as the stored identity.
    """
    templates = _TITLE_TEMPLATES.get(lang, _TITLE_TEMPLATES["en"])
    kind = getattr(item, "kind", "incident")
    incident_type = str(getattr(item, "incident_type", "other"))
    type_label = incident_type_label(incident_type, lang)
    source_ips = tuple(getattr(item, "source_ips", ()) or ())
    source = source_ips[0] if source_ips else None

    if kind == "exposure_group":
        # Service identifiers are deterministic tokens and stay untranslated.
        service = getattr(item, "service", None) or "service"
        if source:
            return templates["exposure_group"].format(
                type_label=type_label, service=service, source=source
            )
        return templates["exposure_group_no_source"].format(
            type_label=type_label, service=service
        )

    if kind == "scan_cluster":
        ports = tuple(getattr(item, "ports", ()) or ())
        port = getattr(item, "fixed_source_port", None)
        if port is None:
            port = ports[0] if ports else "-"
        return templates["scan_cluster"].format(type_label=type_label, port=port)

    if source:
        return templates["incident_with_source"].format(
            type_label=type_label, source=source
        )
    return templates["incident"].format(type_label=type_label)


# ---------------------------------------------------------------------------
# ATT&CK rendering. IDs never change; only the surrounding words do.
# ---------------------------------------------------------------------------

ATTACK_LABELS = {
    "en": {
        "prefix": "ATT&CK context",
        "insufficient": "insufficient behavioral evidence",
        "T1046": "Network Service Discovery",
        "T1133": "External Remote Services",
        "context_only": "context only",
    },
    "tr": {
        "prefix": "ATT&CK bağlamı",
        "insufficient": "yeterli davranışsal kanıt yok",
        "T1046": "Ağ Servisi Keşfi",
        "T1133": "Dış Uzaktan Erişim Servisleri",
        "context_only": "yalnızca bağlam",
    },
}


# ---------------------------------------------------------------------------
# Deterministic report body, rendered for display only.
# ---------------------------------------------------------------------------

_REPORT_LABELS = {
    "en": {
        "title": "Deterministic Report",
        "observed": "Observed activity",
        "source": "Source",
        "events": "Events",
        "total": "total",
        "blocked": "blocked",
        "targets": "Distinct targets",
        "ports": "Ports",
        "services": "Services",
        "window": "Window",
        "unknown": "unknown",
        "none_observed": "none observed",
        "none_classified": "none classified",
        "all_blocked": (
            "All {count} observed event(s) were blocked by the firewall. No "
            "successful connection, authentication, exploitation, or "
            "compromise was proven by this deterministic analysis."
        ),
        "partially_blocked": (
            "{blocked} of {count} observed event(s) were blocked by the "
            "firewall. No successful connection, authentication, "
            "exploitation, or compromise was proven by this deterministic "
            "analysis."
        ),
    },
    "tr": {
        "title": "Deterministik Rapor",
        "observed": "Gözlenen etkinlik",
        "source": "Kaynak",
        "events": "Olaylar",
        "total": "toplam",
        "blocked": "engellendi",
        "targets": "Farklı hedefler",
        "ports": "Portlar",
        "services": "Servisler",
        "window": "Zaman aralığı",
        "unknown": "bilinmiyor",
        "none_observed": "gözlenmedi",
        "none_classified": "sınıflandırılmadı",
        "all_blocked": (
            "Gözlenen {count} olayın tamamı güvenlik duvarı tarafından "
            "engellendi. Bu deterministik analiz; başarılı bir bağlantı, "
            "kimlik doğrulama, istismar veya ele geçirme kanıtlamamaktadır."
        ),
        "partially_blocked": (
            "Gözlenen {count} olayın {blocked} tanesi güvenlik duvarı "
            "tarafından engellendi. Bu deterministik analiz; başarılı bir "
            "bağlantı, kimlik doğrulama, istismar veya ele geçirme "
            "kanıtlamamaktadır."
        ),
    },
}


_DIGEST_STATEMENTS = {
    "en": (
        "No allowed connection was observed for any incident in this digest; "
        "all {blocked} event(s) were blocked reconnaissance."
    ),
    "tr": (
        "Bu özetteki hiçbir olayda izin verilen bağlantı gözlenmedi; "
        "{blocked} olayın tamamı engellenen keşif etkinliğidir."
    ),
}


def render_digest_statement(digest: Mapping[str, object], lang: Language) -> str:
    """A localized digest statement derived from the digest's own counters.

    The persisted digest is never mutated: its stored English ``statement`` is
    left untouched and this text is derived from ``total_blocked_events`` for
    display only. No provider is involved.
    """
    blocked = digest.get("total_blocked_events", 0)
    blocked_count = blocked if isinstance(blocked, int) else 0
    template = _DIGEST_STATEMENTS.get(lang, _DIGEST_STATEMENTS["en"])
    return template.format(blocked=blocked_count)


def render_deterministic_report(
    incident: IncidentBundle,
    incident_events: Sequence[CanonicalLogEvent],
    lang: Language,
) -> str:
    """Presentation-only deterministic report in the requested language.

    Built from the same structured facts as the persisted English report and
    never written back, so the stored report body is untouched and language
    stays a display concern.
    """
    labels = _REPORT_LABELS.get(lang, _REPORT_LABELS["en"])
    event_count = len(incident_events)
    blocked_count = sum(1 for event in incident_events if is_blocked(event))
    target_ips = sorted({event.dst_ip for event in incident_events if event.dst_ip})
    ports = sorted(
        {event.dst_port for event in incident_events if event.dst_port is not None}
    )
    services = sorted(
        {
            service
            for port in ports
            if (service := classify_service(port)) is not None
        }
    )

    target_summary = ", ".join(target_ips[:10]) or labels["unknown"]
    if len(target_ips) > 10:
        target_summary += ", ..."
    port_summary = ", ".join(str(port) for port in ports[:15]) or labels["none_observed"]
    if len(ports) > 15:
        port_summary += ", ..."
    service_summary = ", ".join(services) or labels["none_classified"]

    from agent.triage.provenance import format_event_provenance

    provenance = format_event_provenance(event_count, incident.metrics, lang)
    type_label = incident_type_label(incident.incident_type, lang)
    lines = [
        f"# {labels['title']}: {type_label}",
        "",
        f"- **{labels['observed']}:** {incident.incident_type} "
        f"({incident.incident_family})",
        f"- **{labels['source']}:** {incident.primary_entity}",
        f"- **{labels['events']}:** {provenance} {labels['total']}, "
        f"{blocked_count} {labels['blocked']}",
        f"- **{labels['targets']}:** {len(target_ips)} ({target_summary})",
        f"- **{labels['ports']}:** {port_summary}",
        f"- **{labels['services']}:** {service_summary}",
        f"- **{labels['window']}:** {incident.first_seen.isoformat()} - "
        f"{incident.last_seen.isoformat()}",
        "",
    ]
    if event_count > 0 and blocked_count == event_count:
        lines.append(labels["all_blocked"].format(count=event_count))
    else:
        lines.append(
            labels["partially_blocked"].format(
                count=event_count, blocked=blocked_count
            )
        )
    return "\n".join(lines)


def find_incident(
    incidents: Sequence[IncidentBundle], incident_id: str
) -> Optional[IncidentBundle]:
    for incident in incidents:
        if incident.incident_id == incident_id:
            return incident
    return None


def incident_events(
    incident: IncidentBundle,
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> list[CanonicalLogEvent]:
    return [
        event_lookup[event_id]
        for event_id in incident.event_ids
        if event_id in event_lookup
    ]
