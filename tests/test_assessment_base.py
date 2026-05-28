"""Tests for assessment base module."""

from __future__ import annotations

from domainraptor.assessment.base import (
    SEVERITY_ORDER,
    AssessmentConfig,
    ConfigurationChecker,
    VulnerabilityScanner,
)
from domainraptor.core.types import ConfigIssue, SeverityLevel, Vulnerability


class TestAssessmentConfig:
    """Tests for AssessmentConfig dataclass."""

    def test_assessment_config_defaults(self) -> None:
        """Test assessment config default values."""
        config = AssessmentConfig()
        assert config.timeout == 30
        assert config.verify_ssl is True
        assert config.follow_redirects is True
        assert config.user_agent == "DomainRaptor/1.0"

    def test_assessment_config_custom(self) -> None:
        """Test custom assessment config."""
        config = AssessmentConfig(
            timeout=60,
            verify_ssl=False,
            user_agent="CustomAgent/1.0",
        )
        assert config.timeout == 60
        assert config.verify_ssl is False
        assert config.user_agent == "CustomAgent/1.0"


class ConcreteVulnScanner(VulnerabilityScanner):
    """Concrete implementation for testing."""

    name = "test_scanner"

    def assess(self, target: str) -> list[Vulnerability]:
        return [
            Vulnerability(
                id="TEST-001",
                title="Test Vulnerability",
                severity=SeverityLevel.MEDIUM,
            )
        ]


class ConcreteConfigChecker(ConfigurationChecker):
    """Concrete implementation for testing."""

    name = "test_checker"
    category = "test"

    def assess(self, target: str) -> list[ConfigIssue]:
        return [
            ConfigIssue(
                id="TEST-001",
                title="Test Issue",
                severity=SeverityLevel.LOW,
                category=self.category,
            )
        ]


class TestBaseAssessmentClient:
    """Tests for BaseAssessmentClient abstract class."""

    def test_client_initialization(self) -> None:
        """Test client initialization."""
        client = ConcreteVulnScanner()
        assert client.config.timeout == 30

    def test_client_with_config(self) -> None:
        """Test client with custom config."""
        config = AssessmentConfig(timeout=60)
        client = ConcreteVulnScanner(config)
        assert client.config.timeout == 60

    def test_client_context_manager(self) -> None:
        """Test client as context manager."""
        with ConcreteVulnScanner() as client:
            assert client is not None

    def test_client_lazy_http_client(self) -> None:
        """Test lazy initialization of HTTP client."""
        client = ConcreteVulnScanner()
        assert client._http_client is None

        http_client = client.http_client
        assert http_client is not None
        assert client._http_client is not None

    def test_client_close(self) -> None:
        """Test closing the client."""
        client = ConcreteVulnScanner()
        _ = client.http_client  # Initialize
        assert client._http_client is not None

        client.close()
        assert client._http_client is None

    def test_assess_safe_catches_exceptions(self) -> None:
        """Test assess_safe returns empty on error."""

        class FailingChecker(ConfigurationChecker):
            name = "failing"
            category = "test"

            def assess(self, target: str) -> list[ConfigIssue]:
                raise ValueError("Test error")

        client = FailingChecker()
        result = client.assess_safe("example.com")
        assert result == []


class TestVulnerabilityScanner:
    """Tests for VulnerabilityScanner base class."""

    def test_scanner_assess(self) -> None:
        """Test scanner assess method."""
        scanner = ConcreteVulnScanner()
        vulns = scanner.assess("example.com")

        assert len(vulns) == 1
        assert vulns[0].id == "TEST-001"
        assert vulns[0].severity == SeverityLevel.MEDIUM


class TestConfigurationChecker:
    """Tests for ConfigurationChecker base class."""

    def test_checker_assess(self) -> None:
        """Test checker assess method."""
        checker = ConcreteConfigChecker()
        issues = checker.assess("example.com")

        assert len(issues) == 1
        assert issues[0].id == "TEST-001"
        assert issues[0].category == "test"

    def test_checker_category(self) -> None:
        """Test checker has category."""
        checker = ConcreteConfigChecker()
        assert checker.category == "test"


class TestSeverityOrder:
    """Tests for SEVERITY_ORDER constant."""

    def test_severity_order_values(self) -> None:
        """Test severity order has all levels."""
        assert SeverityLevel.CRITICAL in SEVERITY_ORDER
        assert SeverityLevel.HIGH in SEVERITY_ORDER
        assert SeverityLevel.MEDIUM in SEVERITY_ORDER
        assert SeverityLevel.LOW in SEVERITY_ORDER
        assert SeverityLevel.INFO in SEVERITY_ORDER

    def test_severity_order_ranking(self) -> None:
        """Test severity order is correct (critical > high > medium > low > info)."""
        assert SEVERITY_ORDER[SeverityLevel.CRITICAL] > SEVERITY_ORDER[SeverityLevel.HIGH]
        assert SEVERITY_ORDER[SeverityLevel.HIGH] > SEVERITY_ORDER[SeverityLevel.MEDIUM]
        assert SEVERITY_ORDER[SeverityLevel.MEDIUM] > SEVERITY_ORDER[SeverityLevel.LOW]
        assert SEVERITY_ORDER[SeverityLevel.LOW] > SEVERITY_ORDER[SeverityLevel.INFO]
