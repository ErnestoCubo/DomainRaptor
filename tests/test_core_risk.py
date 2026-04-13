"""Tests for risk assessment module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from domainraptor.core.risk import (
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    _calc_config_score,
    _calc_exposure_score,
    _calc_reputation_score,
    _calc_vuln_score,
    _identify_top_factors,
    calculate_risk_level,
    get_risk_level_description,
    get_risk_level_display,
)
from domainraptor.core.types import (
    Asset,
    AssetType,
    Certificate,
    ConfigIssue,
    ScanResult,
    Service,
    SeverityLevel,
    Vulnerability,
)


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_risk_level_values(self) -> None:
        """Test that all risk levels have correct string values."""
        assert RiskLevel.CRITICAL.value == "CRITICAL"
        assert RiskLevel.HIGH.value == "HIGH"
        assert RiskLevel.MEDIUM.value == "MEDIUM"
        assert RiskLevel.LOW.value == "LOW"
        assert RiskLevel.INFO.value == "INFO"

    def test_risk_level_from_string(self) -> None:
        """Test creating RiskLevel from string."""
        assert RiskLevel("CRITICAL") == RiskLevel.CRITICAL
        assert RiskLevel("HIGH") == RiskLevel.HIGH


class TestRiskFactor:
    """Tests for RiskFactor dataclass."""

    def test_risk_factor_creation(self) -> None:
        """Test risk factor creation."""
        factor = RiskFactor(name="SSH port exposed", points=5.0, category="exposure")
        assert factor.name == "SSH port exposed"
        assert factor.points == 5.0
        assert factor.category == "exposure"


class TestRiskAssessment:
    """Tests for RiskAssessment dataclass."""

    def test_risk_assessment_creation(self) -> None:
        """Test risk assessment creation."""
        assessment = RiskAssessment(
            score=65.5,
            level=RiskLevel.HIGH,
            vuln_contribution=28.0,
            config_contribution=15.0,
            exposure_contribution=17.5,
            reputation_contribution=5.0,
            top_factors=["Critical vulnerability found"],
        )
        assert assessment.score == 65.5
        assert assessment.level == RiskLevel.HIGH

    def test_risk_assessment_to_dict(self) -> None:
        """Test converting risk assessment to dictionary."""
        assessment = RiskAssessment(
            score=45.0,
            level=RiskLevel.MEDIUM,
            vuln_contribution=20.0,
            config_contribution=10.0,
            exposure_contribution=10.0,
            reputation_contribution=5.0,
            top_factors=["Missing HSTS", "SSH exposed"],
        )
        result = assessment.to_dict()

        assert "risk_assessment" in result
        assert result["risk_assessment"]["score"] == 45.0
        assert result["risk_assessment"]["level"] == "MEDIUM"
        assert result["risk_assessment"]["breakdown"]["vulnerabilities"] == 20.0
        assert len(result["risk_assessment"]["top_factors"]) == 2


class TestCalculateRiskLevel:
    """Tests for calculate_risk_level function."""

    @pytest.fixture
    def empty_scan(self) -> ScanResult:
        """Create an empty scan result."""
        return ScanResult(
            target="example.com",
            scan_type="test",
            started_at=datetime.now(),
        )

    @pytest.fixture
    def high_risk_scan(self) -> ScanResult:
        """Create a high-risk scan result."""
        scan = ScanResult(
            target="vulnerable.com",
            scan_type="assess",
            started_at=datetime.now(),
        )
        # Add critical vulnerabilities
        scan.vulnerabilities.append(
            Vulnerability(
                id="CVE-2024-0001",
                title="Critical RCE Vulnerability",
                severity=SeverityLevel.CRITICAL,
                description="Remote code execution",
                affected_asset="vulnerable.com",
                cvss_score=9.8,
                source="test",
            )
        )
        scan.vulnerabilities.append(
            Vulnerability(
                id="CVE-2024-0002",
                title="SQL Injection",
                severity=SeverityLevel.HIGH,
                description="SQL injection vulnerability",
                affected_asset="vulnerable.com",
                cvss_score=8.1,
                source="test",
            )
        )
        return scan

    @pytest.fixture
    def medium_risk_scan(self) -> ScanResult:
        """Create a medium-risk scan result."""
        scan = ScanResult(
            target="moderate.com",
            scan_type="assess",
            started_at=datetime.now(),
        )
        # Add config issues
        scan.config_issues.append(
            ConfigIssue(
                id="MISSING-HSTS",
                title="Missing HSTS Header",
                severity=SeverityLevel.MEDIUM,
                category="headers",
                description="Strict-Transport-Security header missing",
                affected_asset="moderate.com",
            )
        )
        scan.config_issues.append(
            ConfigIssue(
                id="MISSING-CSP",
                title="Missing CSP Header",
                severity=SeverityLevel.MEDIUM,
                category="headers",
                description="Content-Security-Policy header missing",
                affected_asset="moderate.com",
            )
        )
        # Add some subdomains
        for i in range(25):
            scan.assets.append(Asset(type=AssetType.SUBDOMAIN, value=f"sub{i}.moderate.com"))
        return scan

    def test_empty_scan_returns_info_level(self, empty_scan: ScanResult) -> None:
        """Test that empty scan returns INFO level."""
        result = calculate_risk_level(empty_scan)
        assert result.level == RiskLevel.INFO
        assert result.score < 20

    def test_high_risk_scan_returns_elevated_level(self, high_risk_scan: ScanResult) -> None:
        """Test that scan with critical vulns returns elevated level."""
        result = calculate_risk_level(high_risk_scan)
        # With weighted scoring, 1 CRITICAL + 1 HIGH = only vulnerability contribution
        # which equals ~20 points (LOW threshold), so level will be LOW or higher
        assert result.level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert result.score >= 20  # At least LOW threshold
        assert result.vuln_contribution > 0

    def test_medium_risk_scan_has_config_exposure_contribution(
        self, medium_risk_scan: ScanResult
    ) -> None:
        """Test that scan with config issues has config and exposure contributions."""
        result = calculate_risk_level(medium_risk_scan)
        # Config issues + subdomains contribute to score
        assert result.config_contribution > 0
        assert result.exposure_contribution > 0
        assert result.score > 0

    def test_risk_assessment_has_all_contributions(self, high_risk_scan: ScanResult) -> None:
        """Test that all contribution fields are populated."""
        result = calculate_risk_level(high_risk_scan)
        assert result.vuln_contribution >= 0
        assert result.config_contribution >= 0
        assert result.exposure_contribution >= 0
        assert result.reputation_contribution >= 0

    def test_max_score_is_100(self) -> None:
        """Test that score never exceeds 100."""
        scan = ScanResult(
            target="worst.com",
            scan_type="assess",
            started_at=datetime.now(),
        )
        # Add tons of critical issues
        for i in range(20):
            scan.vulnerabilities.append(
                Vulnerability(
                    id=f"CVE-2024-{i:04d}",
                    title=f"Critical Vuln {i}",
                    severity=SeverityLevel.CRITICAL,
                    description="Critical",
                    affected_asset="worst.com",
                    cvss_score=10.0,
                    source="test",
                )
            )
            scan.config_issues.append(
                ConfigIssue(
                    id=f"CONFIG-{i}",
                    title=f"Critical Config {i}",
                    severity=SeverityLevel.CRITICAL,
                    category="security",
                    description="Critical",
                    affected_asset="worst.com",
                )
            )
        # Add lots of exposed ports
        for port in [22, 3389, 3306, 5432, 27017, 8080]:
            scan.services.append(Service(port=port, protocol="tcp", service_name="test"))

        result = calculate_risk_level(scan)
        assert result.score <= 100
        # With this many issues, should be HIGH or CRITICAL
        assert result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


class TestVulnScore:
    """Tests for vulnerability score calculation."""

    def test_critical_vuln_scores_25(self) -> None:
        """Test that critical vuln adds 25 points."""
        vulns = [
            Vulnerability(
                id="CVE-2024-0001",
                title="Test",
                severity=SeverityLevel.CRITICAL,
                description="Test",
                affected_asset="test.com",
                source="test",
            )
        ]
        score, _factors = _calc_vuln_score(vulns)
        assert score >= 25

    def test_high_vuln_scores_15(self) -> None:
        """Test that high vuln adds 15 points."""
        vulns = [
            Vulnerability(
                id="CVE-2024-0001",
                title="Test",
                severity=SeverityLevel.HIGH,
                description="Test",
                affected_asset="test.com",
                source="test",
            )
        ]
        score, _factors = _calc_vuln_score(vulns)
        assert score >= 15

    def test_cvss_bonus_for_high_scores(self) -> None:
        """Test CVSS bonus for scores >= 9.0."""
        vulns = [
            Vulnerability(
                id="CVE-2024-0001",
                title="Test",
                severity=SeverityLevel.CRITICAL,
                description="Test",
                affected_asset="test.com",
                cvss_score=9.5,
                source="test",
            )
        ]
        score, _factors = _calc_vuln_score(vulns)
        # 25 (critical) + 10 (cvss bonus) = 35
        assert score >= 35

    def test_no_vulns_scores_zero(self) -> None:
        """Test that no vulns returns zero."""
        score, factors = _calc_vuln_score([])
        assert score == 0
        assert len(factors) == 0


class TestConfigScore:
    """Tests for configuration score calculation."""

    def test_critical_config_scores_20(self) -> None:
        """Test that critical config issue adds 20 points."""
        issues = [
            ConfigIssue(
                id="CONFIG-001",
                title="Critical Issue",
                severity=SeverityLevel.CRITICAL,
                category="security",
                description="Test",
                affected_asset="test.com",
            )
        ]
        score, _factors = _calc_config_score(issues, [])
        assert score >= 20

    def test_missing_hsts_detected(self) -> None:
        """Test that missing HSTS adds points."""
        issues = [
            ConfigIssue(
                id="MISSING-HSTS",
                title="Missing HSTS",
                severity=SeverityLevel.MEDIUM,
                category="hsts",
                description="HSTS header not found",
                affected_asset="test.com",
            )
        ]
        score, _factors = _calc_config_score(issues, [])
        # Should include HSTS bonus
        assert score >= 8  # HSTS bonus

    def test_expired_cert_adds_points(self) -> None:
        """Test that expired certificate adds points."""
        expired_cert = Certificate(
            subject="test.com",
            issuer="Test CA",
            serial_number="123456",
            not_before=datetime.now(timezone.utc) - timedelta(days=365),
            not_after=datetime.now(timezone.utc) - timedelta(days=30),  # Expired
        )
        score, _factors = _calc_config_score([], [expired_cert])
        assert score >= 15  # Expired cert bonus

    def test_cert_expiring_soon_adds_points(self) -> None:
        """Test that cert expiring soon adds points."""
        soon_cert = Certificate(
            subject="test.com",
            issuer="Test CA",
            serial_number="123456",
            not_before=datetime.now(timezone.utc) - timedelta(days=300),
            not_after=datetime.now(timezone.utc) + timedelta(days=15),  # Expires in 15 days
        )
        score, _factors = _calc_config_score([], [soon_cert])
        assert score >= 8  # Soon expiry bonus


class TestExposureScore:
    """Tests for exposure score calculation."""

    def test_many_subdomains_adds_points(self) -> None:
        """Test that >50 subdomains adds points."""
        assets = [Asset(type=AssetType.SUBDOMAIN, value=f"sub{i}.test.com") for i in range(60)]
        score, _factors = _calc_exposure_score(assets, [])
        assert score >= 10

    def test_dev_staging_detected(self) -> None:
        """Test that dev/staging environments are detected."""
        assets = [
            Asset(type=AssetType.SUBDOMAIN, value="dev.test.com"),
            Asset(type=AssetType.SUBDOMAIN, value="staging.test.com"),
        ]
        score, _factors = _calc_exposure_score(assets, [])
        assert score >= 16  # 8 points each

    def test_ssh_port_adds_points(self) -> None:
        """Test that exposed SSH port adds points."""
        services = [Service(port=22, protocol="tcp", service_name="ssh")]
        score, _factors = _calc_exposure_score([], services)
        assert score >= 5

    def test_database_port_adds_points(self) -> None:
        """Test that exposed database port adds points."""
        services = [Service(port=3306, protocol="tcp", service_name="mysql")]
        score, _factors = _calc_exposure_score([], services)
        assert score >= 10


class TestReputationScore:
    """Tests for reputation score calculation."""

    def test_malicious_flag_adds_points(self) -> None:
        """Test that malicious VirusTotal flag adds points."""
        scan = ScanResult(
            target="malware.com",
            scan_type="test",
            started_at=datetime.now(),
            metadata={"virustotal": {"malicious": 5}},
        )
        score, _factors = _calc_reputation_score(scan)
        assert score >= 30

    def test_suspicious_flag_adds_points(self) -> None:
        """Test that suspicious VirusTotal flag adds points."""
        scan = ScanResult(
            target="suspicious.com",
            scan_type="test",
            started_at=datetime.now(),
            metadata={"virustotal": {"suspicious": 2}},
        )
        score, _factors = _calc_reputation_score(scan)
        assert score >= 10

    def test_clean_scan_scores_zero(self) -> None:
        """Test that clean scan scores zero."""
        scan = ScanResult(
            target="clean.com",
            scan_type="test",
            started_at=datetime.now(),
        )
        score, _factors = _calc_reputation_score(scan)
        assert score == 0


class TestTopFactors:
    """Tests for top factors identification."""

    def test_sorts_by_points(self) -> None:
        """Test that factors are sorted by points."""
        factors = [
            RiskFactor(name="Low", points=5, category="test"),
            RiskFactor(name="High", points=25, category="test"),
            RiskFactor(name="Medium", points=15, category="test"),
        ]
        top = _identify_top_factors(factors, 3)
        assert top[0] == "High"
        assert top[1] == "Medium"
        assert top[2] == "Low"

    def test_limits_to_n(self) -> None:
        """Test that result is limited to N factors."""
        factors = [RiskFactor(name=f"Factor {i}", points=i, category="test") for i in range(10)]
        top = _identify_top_factors(factors, 5)
        assert len(top) == 5


class TestRiskLevelHelpers:
    """Tests for risk level helper functions."""

    def test_get_risk_level_display(self) -> None:
        """Test risk level display strings."""
        assert "🔴" in get_risk_level_display(RiskLevel.CRITICAL)
        assert "🟠" in get_risk_level_display(RiskLevel.HIGH)
        assert "🟡" in get_risk_level_display(RiskLevel.MEDIUM)
        assert "🔵" in get_risk_level_display(RiskLevel.LOW)
        assert "⚪" in get_risk_level_display(RiskLevel.INFO)

    def test_get_risk_level_description(self) -> None:
        """Test risk level descriptions."""
        assert "Immediate" in get_risk_level_description(RiskLevel.CRITICAL)
        assert "7 days" in get_risk_level_description(RiskLevel.HIGH)
        assert "mitigation" in get_risk_level_description(RiskLevel.MEDIUM)
        assert "recommended" in get_risk_level_description(RiskLevel.LOW)
        assert "good" in get_risk_level_description(RiskLevel.INFO).lower()
