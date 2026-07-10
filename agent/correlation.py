from typing import List
from datetime import datetime, timedelta
from agent.schema import CanonicalLogEvent
from agent.models import IncidentBundle
import uuid

class CorrelationEngine:
    def __init__(self):
        pass

    def build_incidents(self, candidate_events: List[CanonicalLogEvent], context_events: List[CanonicalLogEvent]) -> List[IncidentBundle]:
        bundles = []
        
        # We sort all candidates by timestamp
        candidates = sorted(
            [e for e in candidate_events if e.timestamp], 
            key=lambda x: x.timestamp or datetime.min
        )
        
        if not candidates:
            return []
            
        bundles.extend(self.detect_horizontal_port_scan(candidates, context_events))
        bundles.extend(self.detect_vertical_port_scan(candidates, context_events))
        bundles.extend(self.detect_rdp_scan(candidates, context_events))
        bundles.extend(self.detect_ssh_scan(candidates, context_events))
        bundles.extend(self.detect_spi_anomaly_cluster(candidates, context_events))
        
        # Any remaining candidate events that haven't been assigned to an incident
        assigned_ids = {ev.event_id for b in bundles for ev in b.events}
        unassigned = [e for e in candidates if e.event_id not in assigned_ids]
        
        # Group remaining unassigned by src_ip roughly
        if unassigned:
            src_groups: dict[str, List[CanonicalLogEvent]] = {}
            for e in unassigned:
                if not e.src_ip:
                    continue
                if e.src_ip not in src_groups:
                    src_groups[e.src_ip] = []
                src_groups[e.src_ip].append(e)
                
            for src, evs in src_groups.items():
                if len(evs) > 2: # At least 3 unassigned suspicious events from same IP
                    b = self._create_bundle(
                        incident_type="generic_suspicious_activity",
                        events=evs,
                        context_events=[],
                        reason=f"Multiple unclassified suspicious events from {src}",
                        metrics={"source_ip": src, "event_count": len(evs)}
                    )
                    bundles.append(b)

        return bundles

    def _create_bundle(self, incident_type: str, events: List[CanonicalLogEvent], context_events: List[CanonicalLogEvent], reason: str, metrics: dict) -> IncidentBundle:
        events = sorted(events, key=lambda x: x.timestamp if x.timestamp else datetime.min)
        src_ips = list(set([e.src_ip for e in events if e.src_ip]))
        dst_ips = list(set([e.dst_ip for e in events if e.dst_ip]))
        dst_ports = list(set([e.dst_port for e in events if e.dst_port]))
        
        return IncidentBundle(
            incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
            incident_type_hint=incident_type,
            first_seen=events[0].timestamp if events else None,
            last_seen=events[-1].timestamp if events else None,
            source_ips=src_ips,
            destination_ips=dst_ips,
            destination_ports=dst_ports,
            event_ids=[e.event_id for e in events],
            events=events,
            context_events=context_events,
            correlation_reason=reason,
            correlation_metrics=metrics,
            severity_hint="medium",
            confidence_hint=0.8
        )

    def detect_horizontal_port_scan(self, candidates: List[CanonicalLogEvent], context_events: List[CanonicalLogEvent]) -> List[IncidentBundle]:
        # Same src_ip, same dst_port, distinct_dst_ips >= 5 within 5 minutes
        bundles = []
        groups: dict[tuple[str, int], List[CanonicalLogEvent]] = {}
        for ev in candidates:
            if not ev.src_ip:
                continue
            if not ev.dst_port:
                continue
            key = (ev.src_ip, ev.dst_port)
            if key not in groups:
                groups[key] = []
            groups[key].append(ev)
            
        for (src, port), evs in groups.items():
            if len(evs) < 5:
                continue
            # Simple window sliding
            for i in range(len(evs)):
                window = []
                distinct_dst = set()
                t_start = evs[i].timestamp
                for j in range(i, len(evs)):
                    if evs[j].timestamp and t_start and evs[j].timestamp - t_start > timedelta(minutes=5):  # type: ignore
                        break
                    window.append(evs[j])
                    distinct_dst.add(evs[j].dst_ip)
                    
                if len(distinct_dst) >= 5:
                    bundles.append(self._create_bundle(
                        "horizontal_port_scan", 
                        window, 
                        [], 
                        f"Horizontal port scan detected on port {port} targeting {len(distinct_dst)} hosts.",
                        {"distinct_destination_ips": len(distinct_dst), "port": port}
                    ))
                    break # One bundle per scan pattern for this src/port is enough for PoC
        return bundles
        
    def detect_vertical_port_scan(self, candidates: List[CanonicalLogEvent], context_events: List[CanonicalLogEvent]) -> List[IncidentBundle]:
        # Same src_ip, same dst_ip, distinct_dst_ports >= 5 within 5 minutes
        bundles = []
        groups: dict[tuple[str, str], List[CanonicalLogEvent]] = {}
        for ev in candidates:
            if not ev.src_ip:
                continue
            if not ev.dst_ip:
                continue
            key = (ev.src_ip, ev.dst_ip)
            if key not in groups:
                groups[key] = []
            groups[key].append(ev)
            
        for (src, dst), evs in groups.items():
            if len(evs) < 5:
                continue
            for i in range(len(evs)):
                window = []
                distinct_ports = set()
                t_start = evs[i].timestamp
                for j in range(i, len(evs)):
                    if evs[j].timestamp and t_start and evs[j].timestamp - t_start > timedelta(minutes=5):  # type: ignore
                        break
                    window.append(evs[j])
                    if evs[j].dst_port:
                        distinct_ports.add(evs[j].dst_port)
                    
                if len(distinct_ports) >= 5:
                    bundles.append(self._create_bundle(
                        "vertical_port_scan", 
                        window, 
                        [], 
                        f"Vertical port scan detected targeting {dst} across {len(distinct_ports)} ports.",
                        {"distinct_ports": len(distinct_ports), "target": dst}
                    ))
                    break
        return bundles

    def detect_rdp_scan(self, candidates: List[CanonicalLogEvent], context_events: List[CanonicalLogEvent]) -> List[IncidentBundle]:
        rdp = [e for e in candidates if e.dst_port == 3389 and str(e.action).lower() in ["block", "deny", "drop"]]
        return self._detect_service_scan(rdp, "rdp_scan", "RDP")

    def detect_ssh_scan(self, candidates: List[CanonicalLogEvent], context_events: List[CanonicalLogEvent]) -> List[IncidentBundle]:
        ssh = [e for e in candidates if e.dst_port in [22, 2022, 2222] and str(e.action).lower() in ["block", "deny", "drop"]]
        return self._detect_service_scan(ssh, "ssh_scan", "SSH")
        
    def _detect_service_scan(self, events: List[CanonicalLogEvent], incident_type: str, svc_name: str) -> List[IncidentBundle]:
        bundles = []
        groups: dict[str, List[CanonicalLogEvent]] = {}
        for ev in events:
            if not ev.src_ip:
                continue
            if ev.src_ip not in groups:
                groups[ev.src_ip] = []
            groups[ev.src_ip].append(ev)
            
        for src, evs in groups.items():
            if len(evs) >= 3:
                bundles.append(self._create_bundle(
                    incident_type,
                    evs,
                    [],
                    f"Blocked {svc_name} scanning activity detected from {src}.",
                    {"blocked_count": len(evs)}
                ))
        return bundles

    def detect_spi_anomaly_cluster(self, candidates: List[CanonicalLogEvent], context_events: List[CanonicalLogEvent]) -> List[IncidentBundle]:
        spi = [e for e in candidates if "blocked by spi" in str(e.raw_message).lower()]
        bundles = []
        groups: dict[str, List[CanonicalLogEvent]] = {}
        for ev in spi:
            if not ev.src_ip:
                continue
            if ev.src_ip not in groups:
                groups[ev.src_ip] = []
            groups[ev.src_ip].append(ev)
            
        for src, evs in groups.items():
            if len(evs) >= 3:
                bundles.append(self._create_bundle(
                    "spi_anomaly",
                    evs,
                    [],
                    f"Repeated SPI anomaly blocks from {src}.",
                    {"spi_block_count": len(evs)}
                ))
        return bundles
