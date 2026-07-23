"""Bounded batch brief enrichment: the model's only job is explanatory text.

One analyze job makes at most one logical provider call. The request carries
bounded structured facts for at most ten deterministic brief rows; the
response carries only prose and recommended actions, in English and Turkish,
for those same rows.

The model never returns - and can never influence - counts, addresses, ports,
services, action state, evidence IDs, incident identity, verdict, severity,
confidence, ATT&CK IDs, routing or grouping. Those are rendered from the
deterministic item the request was built from. Anything the model returns that
introduces a fact the deterministic view does not already contain causes that
one item to fall back to deterministic text; the rest of the batch is kept.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from agent.detection.presentation import BriefActionItem
from agent.triage.disposition import EvidenceStrength


ENRICHMENT_SCHEMA_VERSION = "soc-brief-enrichment-v1"
REPORT_FORMAT = "soc-brief-enrichment-v1"

MAX_BATCH_ITEMS = 10
MAX_EXPLANATION_CHARS = 500
MIN_ACTIONS = 2
MAX_ACTIONS = 4
MAX_ACTION_CHARS = 200

MAX_REQUEST_SOURCES = 5
MAX_REQUEST_DESTINATIONS = 5
MAX_REQUEST_PORTS = 10
MAX_REQUEST_MEMBERS = 10
MAX_REQUEST_EVIDENCE_IDS = 5

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MARKDOWN_TABLE = re.compile(r"\|.*\|")
_URL = re.compile(r"(?i)\b(?:https?://|www\.|ftp://)\S+")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOSTNAME = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|local|internal|lan|corp|tr|edu|gov)\b",
    re.IGNORECASE,
)
_PORT_MENTION = re.compile(r"(?i)\b(?:port|tcp|udp)[\s:/]*([0-9]{1,5})\b")
_BARE_NUMBER = re.compile(r"\b\d{2,}\b")

#: Claims a firewall log can never support, in English.
_FORBIDDEN_CLAIM_PATTERNS_EN = (
    re.compile(
        r"(?i)\b(compromis(?:e|ed|ing)|breached?|owned|pwned|takeover|taken over)\b"
    ),
    re.compile(r"(?i)\b(exploit(?:ed|ation)?|exploiting)\b"),
    re.compile(r"(?i)\b(malware|ransomware|trojan|backdoor|implant|c2|beacon)\b"),
    re.compile(
        r"(?i)\b(authenticated|logged[\s-]?in|login succeeded|successful "
        r"(?:login|authentication|auth))\b"
    ),
    re.compile(r"(?i)\b(data (?:exfiltration|theft|stolen)|exfiltrated)\b"),
    re.compile(r"(?i)\b(credentials? (?:stolen|harvested|dumped))\b"),
    re.compile(
        r"(?i)\b(revenue|financial loss|reputational damage|business impact|"
        r"regulatory fine|sla breach)\b"
    ),
    re.compile(r"(?i)\bshell (?:access|obtained)\b"),
    re.compile(r"(?i)\broot access\b"),
)

#: The same prohibitions in Turkish. Turkish is agglutinative, so each stem is
#: matched with an open suffix tail rather than a fixed word list - "ele
#: geçirildi", "ele geçirilmiş", "ele geçirilmedi" and "ele geçirilmesi" all
#: match one pattern. Matching the stem also means a negated form is caught,
#: which is intended: there is no negation exception in either language.
_FORBIDDEN_CLAIM_PATTERNS_TR = (
    # compromise / takeover
    re.compile(r"(?i)\bele\s+geçir\w*"),
    re.compile(r"\b(?i:ele\s+geçirilme\w*)"),
    # breach
    re.compile(r"(?i)\bgüvenlik\s+ihlal\w*"),
    re.compile(r"(?i)\bihlal\s+edil\w*"),
    # exploitation
    re.compile(r"(?i)\bistismar\w*"),
    re.compile(r"(?i)\bsömür\w*"),
    re.compile(r"(?i)\bzafiyet\s+kullan\w*"),
    # malware
    re.compile(r"(?i)\bzararlı\s+yazılım\w*"),
    re.compile(r"(?i)\bkötü\s+amaçlı\s+yazılım\w*"),
    re.compile(r"(?i)\bfidye\s+yazılım\w*"),
    re.compile(r"(?i)\barka\s+kapı\w*"),
    re.compile(r"(?i)\btruva\s+atı\w*"),
    # authentication success
    re.compile(r"(?i)\bkimlik\s+doğrulan\w*"),
    re.compile(r"(?i)\bkimlik\s+doğrulama\s+başar\w*"),
    re.compile(r"(?i)\boturum\s+açıl\w*"),
    re.compile(r"(?i)\bgiriş\s+başar\w*"),
    re.compile(r"(?i)\bbaşarıyla\s+giriş\w*"),
    # data exfiltration / credential theft
    re.compile(r"(?i)\bveri(?:ler)?\s+(?:sızdır\w*|çalın\w*|dışarı\s+aktar\w*)"),
    re.compile(r"(?i)\bdışarı\s+sızdır\w*"),
    re.compile(r"(?i)\bveri\s+sızıntı\w*"),
    re.compile(r"(?i)\b(?:kimlik\s+bilgi\w*|parola\w*|şifre\w*)\s+çalın\w*"),
    # business impact
    re.compile(r"(?i)\b(?:mali|finansal)\s+kayıp\w*"),
    re.compile(r"(?i)\biş\s+etkisi\w*"),
    re.compile(r"(?i)\bitibar\s+kayb\w*"),
    re.compile(r"(?i)\bdüzenleyici\s+ceza\w*"),
    # privileged access
    re.compile(r"(?i)\bkabuk\s+erişim\w*"),
    re.compile(r"(?i)\bkök\s+erişim\w*"),
    re.compile(r"(?i)\byönetici\s+erişimi\s+elde\s+edil\w*"),
)

#: Every generated text field is checked against both sets regardless of which
#: language it is supposed to be in, so a Turkish claim in an English field -
#: or a mixed-language sentence - is caught either way.
_FORBIDDEN_CLAIM_PATTERNS = (
    *_FORBIDDEN_CLAIM_PATTERNS_EN,
    *_FORBIDDEN_CLAIM_PATTERNS_TR,
)


class BriefEnrichmentFacts(BaseModel):
    """The bounded structured view of one row that the provider receives."""

    model_config = ConfigDict(frozen=True)

    item_id: str
    member_incident_ids: tuple[str, ...] = ()
    incident_type: str
    incident_family: str
    service: Optional[str] = None
    evidence_strength: Optional[str] = None
    source_count: int = 0
    source_ips: tuple[str, ...] = ()
    destination_count: int = 0
    effective_destinations: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    allowed_event_count: int = 0
    blocked_event_count: int = 0
    packet_count: int = 0
    byte_count: int = 0
    severity: str
    confidence: float
    verdict: str
    evidence_ids: tuple[str, ...] = ()
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None


class BriefEnrichmentRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = ENRICHMENT_SCHEMA_VERSION
    items: tuple[BriefEnrichmentFacts, ...] = ()


class BriefEnrichmentItem(BaseModel):
    """Accepted, validated prose for one row."""

    model_config = ConfigDict(frozen=True)

    item_id: str
    explanation_en: str = Field(max_length=MAX_EXPLANATION_CHARS)
    explanation_tr: str = Field(max_length=MAX_EXPLANATION_CHARS)
    recommended_actions_en: tuple[str, ...] = ()
    recommended_actions_tr: tuple[str, ...] = ()
    #: True when the text came from the deterministic fallback, not a model.
    deterministic_fallback: bool = False


class BriefEnrichmentResult(BaseModel):
    """The persisted, replayable enrichment artifact for one job."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = ENRICHMENT_SCHEMA_VERSION
    items: tuple[BriefEnrichmentItem, ...] = ()
    #: Logical provider invocations attempted for this job: 0 or 1.
    provider_invocation_count: int = 0
    provider_retry_count: int = 0
    #: Bounded record of why enrichment text is deterministic, if it is.
    enrichment_failure_reason: Optional[str] = None

    def for_item(self, item_id: str) -> Optional[BriefEnrichmentItem]:
        for item in self.items:
            if item.item_id == item_id:
                return item
        return None


def build_enrichment_request(
    items: Sequence[BriefActionItem],
) -> BriefEnrichmentRequest:
    """Build the bounded request. No raw records or parser metadata."""
    facts = tuple(
        BriefEnrichmentFacts(
            item_id=item.item_id,
            member_incident_ids=item.member_incident_ids[:MAX_REQUEST_MEMBERS],
            incident_type=item.incident_type,
            incident_family=item.incident_family,
            service=item.service,
            evidence_strength=(
                item.evidence_strength.value if item.evidence_strength else None
            ),
            source_count=item.source_count,
            source_ips=item.source_ips[:MAX_REQUEST_SOURCES],
            destination_count=item.destination_count,
            effective_destinations=item.effective_destinations[
                :MAX_REQUEST_DESTINATIONS
            ],
            ports=item.ports[:MAX_REQUEST_PORTS],
            allowed_event_count=item.allowed_event_count,
            blocked_event_count=item.blocked_event_count,
            packet_count=item.packet_count,
            byte_count=item.byte_count,
            severity=item.severity,
            confidence=item.confidence,
            verdict=item.verdict,
            evidence_ids=item.evidence_ids[:MAX_REQUEST_EVIDENCE_IDS],
            mitre_technique=item.mitre_technique,
            mitre_tactic=item.mitre_tactic,
        )
        for item in items[:MAX_BATCH_ITEMS]
    )
    return BriefEnrichmentRequest(items=facts)


def _known_numbers(item: BriefActionItem) -> set[str]:
    values: set[str] = set()
    for port in item.ports:
        values.add(str(port))
    for number in (
        item.event_count,
        item.allowed_event_count,
        item.blocked_event_count,
        item.packet_count,
        item.byte_count,
        item.source_count,
        item.destination_count,
    ):
        values.add(str(number))
    return values


def _known_addresses(item: BriefActionItem) -> set[str]:
    return {
        *item.source_ips,
        *item.effective_destinations,
        *item.original_destinations,
    }


def _rejection_reason(text: str, item: BriefActionItem) -> Optional[str]:
    if not text or not text.strip():
        return "empty_text"
    if _CONTROL_CHARACTERS.search(text):
        return "control_characters"
    if _MARKDOWN_TABLE.search(text):
        return "markdown_table"
    if _URL.search(text):
        return "url"
    for pattern in _FORBIDDEN_CLAIM_PATTERNS:
        if pattern.search(text):
            # No negation exception. A nearby "not" is not reliable evidence
            # that the forbidden term is being denied - "not merely scanned
            # but compromised" is an affirmative claim - and the prompt already
            # tells the model never to use this vocabulary at all.
            return "unsupported_claim"

    known_addresses = _known_addresses(item)
    for address in _IPV4.findall(text):
        if address not in known_addresses:
            return "unseen_ip_address"
    for hostname in _HOSTNAME.findall(text):
        if hostname not in known_addresses:
            return "unseen_hostname"

    known_numbers = _known_numbers(item)
    for port in _PORT_MENTION.findall(text):
        if port not in known_numbers:
            return "unseen_port"
    return None


def _clean_actions(values: Iterable[str]) -> tuple[str, ...]:
    cleaned: list[str] = []
    for value in values:
        text = " ".join(str(value).split())
        if text and text not in cleaned:
            cleaned.append(text[:MAX_ACTION_CHARS])
    return tuple(cleaned[:MAX_ACTIONS])


def validate_enrichment_payload(
    payload: object,
    items: Sequence[BriefActionItem],
) -> tuple[tuple[BriefEnrichmentItem, ...], dict[str, str]]:
    """Validate a raw provider payload against the requested items.

    Returns the accepted items and a map of ``item_id -> rejection reason``.
    Unknown IDs are discarded, duplicates keep the first occurrence, and any
    item whose text introduces an unseen fact or an unsupported claim is
    rejected on its own without affecting the rest of the batch.
    """
    by_id = {item.item_id: item for item in items}
    accepted: list[BriefEnrichmentItem] = []
    rejected: dict[str, str] = {}

    rows = payload
    if isinstance(payload, dict):
        rows = payload.get("items", [])
    if not isinstance(rows, list):
        return (), {item.item_id: "malformed_payload" for item in items}

    seen: set[str] = set()
    for row in rows[: MAX_BATCH_ITEMS * 2]:
        if not isinstance(row, dict):
            continue
        item_id = str(row.get("item_id", ""))
        if item_id not in by_id or item_id in seen:
            # Unknown or duplicate IDs are silently discarded.
            continue
        seen.add(item_id)
        item = by_id[item_id]

        explanation_en = " ".join(str(row.get("explanation_en", "")).split())
        explanation_tr = " ".join(str(row.get("explanation_tr", "")).split())
        actions_en = _clean_actions(row.get("recommended_actions_en", []) or [])
        actions_tr = _clean_actions(row.get("recommended_actions_tr", []) or [])

        if (
            len(explanation_en) > MAX_EXPLANATION_CHARS
            or len(explanation_tr) > MAX_EXPLANATION_CHARS
        ):
            rejected[item_id] = "explanation_too_long"
            continue
        if not (MIN_ACTIONS <= len(actions_en) <= MAX_ACTIONS):
            rejected[item_id] = "action_count_out_of_bounds"
            continue
        if not (MIN_ACTIONS <= len(actions_tr) <= MAX_ACTIONS):
            rejected[item_id] = "action_count_out_of_bounds"
            continue

        reason = None
        for text in (explanation_en, explanation_tr, *actions_en, *actions_tr):
            reason = _rejection_reason(text, item)
            if reason:
                break
        if reason:
            rejected[item_id] = reason
            continue

        accepted.append(
            BriefEnrichmentItem(
                item_id=item_id,
                explanation_en=explanation_en,
                explanation_tr=explanation_tr,
                recommended_actions_en=actions_en,
                recommended_actions_tr=actions_tr,
            )
        )

    for item in items:
        if item.item_id not in seen and item.item_id not in rejected:
            rejected[item.item_id] = "missing_item"
    return tuple(accepted), rejected


# ---------------------------------------------------------------------------
# Deterministic fallback text.
# ---------------------------------------------------------------------------

_SERVICE_TEXT_EN = {
    "ssh": "Secure Shell provides interactive administrative access to the host.",
    "rdp": "Remote Desktop provides interactive graphical access to the host.",
    "telnet": "Telnet carries administrative sessions in cleartext.",
    "ftp": "FTP carries file transfers and credentials in cleartext.",
    "smb": "SMB exposes file shares and is a common lateral-movement path.",
    "vnc": "VNC provides remote graphical control of the host.",
    "winrm": "WinRM provides remote command execution on Windows hosts.",
    "database": "The database service holds application data directly.",
    "redis": "Redis commonly runs without authentication by default.",
    "mongodb": "MongoDB commonly runs without authentication by default.",
    "elasticsearch": "Elasticsearch exposes indexed data over HTTP.",
    "docker": "The Docker daemon API grants control of the container host.",
    "kubernetes": "The Kubernetes API controls workloads on the cluster.",
    "memcached": "Memcached has no authentication and is abused for reflection.",
    "ipmi": "IPMI provides out-of-band control of the physical server.",
    "snmp": "SNMP can disclose device configuration and topology.",
    "ldap": "LDAP exposes directory data used for authentication.",
    "msrpc": "MSRPC exposes Windows remote procedure call endpoints.",
}

_SERVICE_TEXT_TR = {
    "ssh": "SSH, sunucuya etkileşimli yönetim erişimi sağlar.",
    "rdp": "RDP, sunucuya etkileşimli grafik erişim sağlar.",
    "telnet": "Telnet, yönetim oturumlarını şifresiz taşır.",
    "ftp": "FTP, dosya aktarımını ve kimlik bilgilerini şifresiz taşır.",
    "smb": "SMB, dosya paylaşımlarını açar ve yatay harekette sık kullanılır.",
    "vnc": "VNC, sunucunun uzaktan grafik kontrolünü sağlar.",
    "winrm": "WinRM, Windows sunucularda uzaktan komut çalıştırmayı sağlar.",
    "database": "Veritabanı servisi uygulama verisini doğrudan barındırır.",
    "redis": "Redis varsayılan olarak genellikle kimlik doğrulamasız çalışır.",
    "mongodb": "MongoDB varsayılan olarak genellikle kimlik doğrulamasız çalışır.",
    "elasticsearch": "Elasticsearch, indekslenmiş veriyi HTTP üzerinden açar.",
    "docker": "Docker daemon API'si konteyner sunucusunun kontrolünü verir.",
    "kubernetes": "Kubernetes API'si kümedeki iş yüklerini yönetir.",
    "memcached": "Memcached kimlik doğrulamasızdır ve yansıma saldırılarında kullanılır.",
    "ipmi": "IPMI, fiziksel sunucunun bant dışı kontrolünü sağlar.",
    "snmp": "SNMP, cihaz yapılandırmasını ve topolojisini sızdırabilir.",
    "ldap": "LDAP, kimlik doğrulamada kullanılan dizin verisini açar.",
    "msrpc": "MSRPC, Windows uzak yordam çağrısı uç noktalarını açar.",
}

_STRENGTH_TEXT_EN = {
    EvidenceStrength.SYN_ONLY: (
        "Only an unanswered connection attempt was observed, so the firewall "
        "policy allowed the attempt but no session was proven."
    ),
    EvidenceStrength.SINGLE_PACKET_NON_SYN: (
        "A single packet was observed without a recorded handshake, so the "
        "policy exposure is confirmed but the session state is not."
    ),
    EvidenceStrength.MULTI_PACKET_UNIDIRECTIONAL: (
        "Several packets were observed in one direction, which is more than a "
        "single probe but still does not prove the peer replied."
    ),
    EvidenceStrength.PAYLOAD_BEARING_UNIDIRECTIONAL: (
        "Payload-bearing transport was observed in one direction. The client "
        "sent data; nothing observed shows the service accepted or answered it."
    ),
    EvidenceStrength.BIDIRECTIONAL_TRANSPORT: (
        "Traffic was observed in both directions. This does not by itself "
        "prove authentication succeeded or that any action was completed."
    ),
    EvidenceStrength.APPLICATION_EVIDENCE: (
        "Application-layer activity was recorded for this flow. This does not "
        "by itself prove authentication succeeded."
    ),
}

_STRENGTH_TEXT_TR = {
    EvidenceStrength.SYN_ONLY: (
        "Yalnızca yanıtlanmamış bir bağlantı denemesi görüldü; güvenlik duvarı "
        "denemeye izin verdi ancak bir oturum kanıtlanmadı."
    ),
    EvidenceStrength.SINGLE_PACKET_NON_SYN: (
        "El sıkışma kaydı olmadan tek bir paket görüldü; politika açığı "
        "doğrulandı ancak oturum durumu doğrulanmadı."
    ),
    EvidenceStrength.MULTI_PACKET_UNIDIRECTIONAL: (
        "Tek yönde birden fazla paket görüldü; bu tek bir denemeden fazlasıdır "
        "ancak karşı tarafın yanıt verdiğini kanıtlamaz."
    ),
    EvidenceStrength.PAYLOAD_BEARING_UNIDIRECTIONAL: (
        "Tek yönde veri taşıyan trafik görüldü. İstemci veri gönderdi; "
        "servisin bunu kabul ettiğine veya yanıtladığına dair gözlem yok."
    ),
    EvidenceStrength.BIDIRECTIONAL_TRANSPORT: (
        "Trafik her iki yönde de görüldü. Bu tek başına kimlik doğrulamanın "
        "başarılı olduğunu veya bir işlemin tamamlandığını kanıtlamaz."
    ),
    EvidenceStrength.APPLICATION_EVIDENCE: (
        "Bu akış için uygulama katmanı etkinliği kaydedildi. Bu tek başına "
        "kimlik doğrulamanın başarılı olduğunu kanıtlamaz."
    ),
}

_ACTIONS_EN = {
    "ssh": (
        "Confirm whether this host should accept SSH from the internet.",
        "Restrict the exposure to known management networks or a VPN.",
        "Review the host's authentication log for the same window.",
    ),
    "rdp": (
        "Confirm whether Remote Desktop should be reachable externally.",
        "Place the service behind a VPN or gateway and enforce MFA.",
        "Review the host's logon events for the same window.",
    ),
    "redis": (
        "Confirm whether this Redis instance should be internet reachable.",
        "Require authentication and bind the service to internal interfaces.",
        "Review the instance for unexpected keys or configuration changes.",
    ),
    "docker": (
        "Confirm whether the Docker API should be published at all.",
        "Bind the daemon to a local socket and require mutual TLS.",
        "Review the host for containers created during this window.",
    ),
    "mongodb": (
        "Confirm whether this database should be internet reachable.",
        "Enable authentication and restrict the listener to internal networks.",
        "Review the database audit log for the same window.",
    ),
    "elasticsearch": (
        "Confirm whether this cluster should be internet reachable.",
        "Enable authentication and restrict the listener to internal networks.",
        "Review index access logs for the same window.",
    ),
    "database": (
        "Confirm whether this database should accept external connections.",
        "Restrict the listener to application networks only.",
        "Review the database authentication log for the same window.",
    ),
    "ipmi": (
        "Confirm whether out-of-band management should be internet reachable.",
        "Move the management interface to an isolated network.",
        "Review the controller's access log for the same window.",
    ),
}

_ACTIONS_TR = {
    "ssh": (
        "Bu sunucunun internetten SSH kabul etmesi gerekip gerekmediğini doğrulayın.",
        "Erişimi bilinen yönetim ağlarıyla veya VPN ile sınırlayın.",
        "Aynı zaman aralığı için sunucunun kimlik doğrulama kaydını inceleyin.",
    ),
    "rdp": (
        "Uzak Masaüstü'nün dışarıdan erişilebilir olması gerekip gerekmediğini doğrulayın.",
        "Servisi VPN veya ağ geçidi arkasına alın ve MFA zorunlu kılın.",
        "Aynı zaman aralığı için oturum açma olaylarını inceleyin.",
    ),
    "redis": (
        "Bu Redis örneğinin internetten erişilebilir olması gerekip gerekmediğini doğrulayın.",
        "Kimlik doğrulamayı zorunlu kılın ve servisi iç arayüzlere bağlayın.",
        "Örnekte beklenmeyen anahtar veya yapılandırma değişikliği olup olmadığını inceleyin.",
    ),
    "docker": (
        "Docker API'sinin yayınlanması gerekip gerekmediğini doğrulayın.",
        "Daemon'ı yerel sokete bağlayın ve karşılıklı TLS zorunlu kılın.",
        "Bu zaman aralığında oluşturulan konteynerleri inceleyin.",
    ),
    "mongodb": (
        "Bu veritabanının internetten erişilebilir olması gerekip gerekmediğini doğrulayın.",
        "Kimlik doğrulamayı etkinleştirin ve dinleyiciyi iç ağlarla sınırlayın.",
        "Aynı zaman aralığı için veritabanı denetim kaydını inceleyin.",
    ),
    "elasticsearch": (
        "Bu kümenin internetten erişilebilir olması gerekip gerekmediğini doğrulayın.",
        "Kimlik doğrulamayı etkinleştirin ve dinleyiciyi iç ağlarla sınırlayın.",
        "Aynı zaman aralığı için indeks erişim kayıtlarını inceleyin.",
    ),
    "database": (
        "Bu veritabanının dış bağlantı kabul etmesi gerekip gerekmediğini doğrulayın.",
        "Dinleyiciyi yalnızca uygulama ağlarıyla sınırlayın.",
        "Aynı zaman aralığı için veritabanı kimlik doğrulama kaydını inceleyin.",
    ),
    "ipmi": (
        "Bant dışı yönetimin internetten erişilebilir olması gerekip gerekmediğini doğrulayın.",
        "Yönetim arayüzünü izole bir ağa taşıyın.",
        "Aynı zaman aralığı için denetleyicinin erişim kaydını inceleyin.",
    ),
}

_GENERIC_ACTIONS_EN = (
    "Confirm whether this exposure is an intended firewall policy.",
    "Restrict the rule to the networks that actually need it.",
    "Review host-side logs for the same window before escalating.",
)

_GENERIC_ACTIONS_TR = (
    "Bu açığın amaçlanan bir güvenlik duvarı politikası olup olmadığını doğrulayın.",
    "Kuralı yalnızca gerçekten ihtiyaç duyan ağlarla sınırlayın.",
    "Yükseltmeden önce aynı zaman aralığı için sunucu kayıtlarını inceleyin.",
)

_SCAN_ACTIONS_EN = (
    "Confirm whether any of the probed services should be reachable externally.",
    "Check whether the probed hosts responded on the services that were allowed.",
    "Consider rate limiting or blocking the source if the activity persists.",
)

_SCAN_ACTIONS_TR = (
    "Taranan servislerden herhangi birinin dışarıdan erişilebilir olması gerekip gerekmediğini doğrulayın.",
    "Taranan sunucuların izin verilen servislerde yanıt verip vermediğini kontrol edin.",
    "Etkinlik sürerse kaynağı hız sınırlamayı veya engellemeyi değerlendirin.",
)


def deterministic_fallback(item: BriefActionItem) -> BriefEnrichmentItem:
    """Service-specific deterministic text used whenever no model text applies.

    This is a complete answer, not a placeholder: it explains why the service
    matters, how strong the evidence is, and what to verify next.
    """
    service = item.service or ""
    is_scan = item.kind == "scan_cluster" or item.incident_family in {
        "network_scanning",
        "service_probing",
    }

    if is_scan:
        why_en = (
            "Repeated connection attempts across several ports indicate service "
            "enumeration rather than ordinary client traffic."
        )
        why_tr = (
            "Birden fazla porta yapılan tekrarlı bağlantı denemeleri, olağan "
            "istemci trafiğinden çok servis taraması olduğunu gösterir."
        )
        actions_en = _SCAN_ACTIONS_EN
        actions_tr = _SCAN_ACTIONS_TR
    else:
        why_en = _SERVICE_TEXT_EN.get(
            service, "The exposed service is reachable from outside the perimeter."
        )
        why_tr = _SERVICE_TEXT_TR.get(
            service, "Açığa çıkan servise çevre dışından erişilebiliyor."
        )
        actions_en = _ACTIONS_EN.get(service, _GENERIC_ACTIONS_EN)
        actions_tr = _ACTIONS_TR.get(service, _GENERIC_ACTIONS_TR)

    strength = item.evidence_strength
    strength_en = _STRENGTH_TEXT_EN.get(strength, "") if strength else ""
    strength_tr = _STRENGTH_TEXT_TR.get(strength, "") if strength else ""

    explanation_en = " ".join(part for part in (why_en, strength_en) if part)
    explanation_tr = " ".join(part for part in (why_tr, strength_tr) if part)

    return BriefEnrichmentItem(
        item_id=item.item_id,
        explanation_en=explanation_en[:MAX_EXPLANATION_CHARS],
        explanation_tr=explanation_tr[:MAX_EXPLANATION_CHARS],
        recommended_actions_en=tuple(actions_en[:MAX_ACTIONS]),
        recommended_actions_tr=tuple(actions_tr[:MAX_ACTIONS]),
        deterministic_fallback=True,
    )


def complete_with_fallback(
    accepted: Sequence[BriefEnrichmentItem],
    items: Sequence[BriefActionItem],
) -> tuple[BriefEnrichmentItem, ...]:
    """Fill every requested row, using deterministic text where needed."""
    by_id = {item.item_id: item for item in accepted}
    return tuple(
        by_id.get(item.item_id) or deterministic_fallback(item) for item in items
    )


def serialize_result(result: BriefEnrichmentResult) -> str:
    """Stable JSON for the persisted artifact."""
    return json.dumps(
        result.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def deserialize_result(content: str) -> Optional[BriefEnrichmentResult]:
    try:
        payload = json.loads(content)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("schema_version") != ENRICHMENT_SCHEMA_VERSION:
        return None
    try:
        return BriefEnrichmentResult.model_validate(payload)
    except ValueError:
        return None
