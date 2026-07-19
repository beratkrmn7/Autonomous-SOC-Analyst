"""
Detectors module
"""
def register_default_rules():
    from agent.detection.registry import default_registry

    from agent.detection.detectors.horizontal_scan import HorizontalScanRule
    from agent.detection.detectors.vertical_scan import VerticalScanRule
    from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
    from agent.detection.detectors.spi_anomaly import SPIAnomalyRule
    from agent.detection.detectors.network_flood import NetworkFloodRule
    from agent.detection.detectors.coordinated_scan import (
        DistributedScanRule,
        RepeatedBlockedScannerRule,
    )
    from agent.detection.detectors.low_and_slow_scan import (
        LowAndSlowHorizontalScanRule,
        LowAndSlowVerticalScanRule,
    )
    from agent.detection.detectors.scan_sequence import (
        ScanFollowedByAllowedConnectionRule,
    )
    from agent.detection.detectors.service_sweep import (
        InternalLateralScanRule,
        MultiServiceSweepRule,
    )
    from agent.detection.detectors.subnet_sweep import SubnetSweepRule

    # Register rules
    default_registry.register(HorizontalScanRule())
    default_registry.register(VerticalScanRule())
    default_registry.register(RemoteServiceProbeRule())
    default_registry.register(SPIAnomalyRule())
    default_registry.register(NetworkFloodRule())
    default_registry.register(LowAndSlowHorizontalScanRule())
    default_registry.register(LowAndSlowVerticalScanRule())
    default_registry.register(RepeatedBlockedScannerRule())
    default_registry.register(InternalLateralScanRule())
    default_registry.register(SubnetSweepRule())
    default_registry.register(DistributedScanRule())
    default_registry.register(MultiServiceSweepRule())
    default_registry.register(ScanFollowedByAllowedConnectionRule())
