"""Security assessment module for DomainRaptor."""

from domainraptor.assessment.base import (
    AssessmentConfig,
    BaseAssessmentClient,
    ConfigurationChecker,
    VulnerabilityScanner,
    filter_by_min_severity,
    sort_by_severity,
)
from domainraptor.assessment.dns_security import DnsSecurityChecker, DnsSecurityInfo
from domainraptor.assessment.headers_checker import HeadersChecker, SecurityHeaders
from domainraptor.assessment.orchestrator import (
    AssessmentOptions,
    AssessmentOrchestrator,
    AssessmentProgress,
    run_assessment,
)
from domainraptor.assessment.ssl_analyzer import SSLAnalyzer, SSLInfo

__all__ = [
    # Base
    "AssessmentConfig",
    "BaseAssessmentClient",
    "ConfigurationChecker",
    "VulnerabilityScanner",
    "filter_by_min_severity",
    "sort_by_severity",
    # SSL
    "SSLAnalyzer",
    "SSLInfo",
    # Headers
    "HeadersChecker",
    "SecurityHeaders",
    # DNS
    "DnsSecurityChecker",
    "DnsSecurityInfo",
    # Orchestrator
    "AssessmentOptions",
    "AssessmentOrchestrator",
    "AssessmentProgress",
    "run_assessment",
]

