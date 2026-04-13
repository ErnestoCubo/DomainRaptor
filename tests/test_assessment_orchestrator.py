"""Tests for the assessment orchestrator module."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from domainraptor.assessment.orchestrator import (
    AssessmentOptions,
    AssessmentOrchestrator,
    AssessmentProgress,
    run_assessment,
)
from domainraptor.core.types import ConfigIssue, SeverityLevel

if TYPE_CHECKING:
    pass


class TestAssessmentOptions:
    """Tests for AssessmentOptions dataclass."""

    def test_assessment_options_defaults(self) -> None:
        """Test AssessmentOptions with default values."""
        opts = AssessmentOptions()
        assert opts.check_ssl is True
        assert opts.check_headers is True
        assert opts.check_dns is True
        assert opts.min_severity == SeverityLevel.LOW
        assert opts.timeout == 30
        assert opts.max_workers == 3

    def test_assessment_options_custom(self) -> None:
        """Test AssessmentOptions with custom values."""
        opts = AssessmentOptions(
            check_ssl=False,
            check_headers=True,
            check_dns=False,
            min_severity=SeverityLevel.HIGH,
            timeout=60,
            max_workers=5,
        )
        assert opts.check_ssl is False
        assert opts.check_headers is True
        assert opts.check_dns is False
        assert opts.min_severity == SeverityLevel.HIGH
        assert opts.timeout == 60
        assert opts.max_workers == 5


class TestAssessmentProgress:
    """Tests for AssessmentProgress dataclass."""

    def test_assessment_progress_defaults(self) -> None:
        """Test AssessmentProgress with default values."""
        progress = AssessmentProgress()
        assert progress.total_checks == 0
        assert progress.completed_checks == 0
        assert progress.current_check == ""
        assert progress.errors == []

    def test_assessment_progress_custom(self) -> None:
        """Test AssessmentProgress with custom values."""
        progress = AssessmentProgress(
            total_checks=3,
            completed_checks=1,
            current_check="SSL/TLS",
            errors=["Error 1"],
        )
        assert progress.total_checks == 3
        assert progress.completed_checks == 1
        assert progress.current_check == "SSL/TLS"
        assert progress.errors == ["Error 1"]


class TestAssessmentOrchestrator:
    """Tests for AssessmentOrchestrator class."""

    def test_orchestrator_init_defaults(self) -> None:
        """Test AssessmentOrchestrator initialization with defaults."""
        orch = AssessmentOrchestrator()
        assert orch.options is not None
        assert orch.progress_callback is None
        assert orch._progress is not None

    def test_orchestrator_init_custom_options(self) -> None:
        """Test AssessmentOrchestrator with custom options."""
        opts = AssessmentOptions(check_ssl=False, timeout=60)
        orch = AssessmentOrchestrator(options=opts)
        assert orch.options.check_ssl is False
        assert orch.options.timeout == 60

    def test_orchestrator_with_progress_callback(self) -> None:
        """Test AssessmentOrchestrator with progress callback."""
        callback = MagicMock()
        orch = AssessmentOrchestrator(progress_callback=callback)
        assert orch.progress_callback == callback

    def test_report_progress_with_callback(self) -> None:
        """Test _report_progress calls callback."""
        callback = MagicMock()
        orch = AssessmentOrchestrator(progress_callback=callback)

        orch._report_progress()

        callback.assert_called_once_with(orch._progress)

    def test_report_progress_without_callback(self) -> None:
        """Test _report_progress without callback does not error."""
        orch = AssessmentOrchestrator()
        # Should not raise
        orch._report_progress()

    def test_config_is_initialized(self) -> None:
        """Test that AssessmentConfig is initialized."""
        opts = AssessmentOptions(timeout=45)
        orch = AssessmentOrchestrator(options=opts)

        assert orch._config is not None
        assert orch._config.timeout == 45


class TestAssessmentOrchestratorAssess:
    """Tests for AssessmentOrchestrator assess methods."""

    @patch.object(AssessmentOrchestrator, "_check_ssl")
    @patch.object(AssessmentOrchestrator, "_check_headers")
    @patch.object(AssessmentOrchestrator, "_check_dns")
    def test_assess_runs_all_checks(
        self, mock_dns: MagicMock, mock_headers: MagicMock, mock_ssl: MagicMock
    ) -> None:
        """Test assess runs all enabled checks."""
        mock_ssl.return_value = []
        mock_headers.return_value = []
        mock_dns.return_value = []

        orch = AssessmentOrchestrator()
        result = orch.assess("example.com")

        mock_ssl.assert_called_once_with("example.com")
        mock_headers.assert_called_once_with("example.com")
        mock_dns.assert_called_once_with("example.com")
        assert result.status == "completed"
        assert result.scan_type == "assess"

    @patch.object(AssessmentOrchestrator, "_check_ssl")
    @patch.object(AssessmentOrchestrator, "_check_headers")
    @patch.object(AssessmentOrchestrator, "_check_dns")
    def test_assess_with_issues(
        self, mock_dns: MagicMock, mock_headers: MagicMock, mock_ssl: MagicMock
    ) -> None:
        """Test assess collects issues from all checks."""
        mock_ssl.return_value = [
            ConfigIssue(id="ssl-1", title="SSL Issue", severity=SeverityLevel.HIGH, category="ssl")
        ]
        mock_headers.return_value = [
            ConfigIssue(
                id="hdr-1", title="Header Issue", severity=SeverityLevel.MEDIUM, category="headers"
            )
        ]
        mock_dns.return_value = []

        orch = AssessmentOrchestrator()
        result = orch.assess("example.com")

        assert len(result.config_issues) == 2
        # Sorted by severity - HIGH first
        assert result.config_issues[0].severity == SeverityLevel.HIGH

    @patch.object(AssessmentOrchestrator, "_check_ssl")
    @patch.object(AssessmentOrchestrator, "_check_headers")
    @patch.object(AssessmentOrchestrator, "_check_dns")
    def test_assess_handles_exception(
        self, mock_dns: MagicMock, mock_headers: MagicMock, mock_ssl: MagicMock
    ) -> None:
        """Test assess handles exceptions gracefully."""
        mock_ssl.side_effect = Exception("SSL error")
        mock_headers.return_value = []
        mock_dns.return_value = []

        orch = AssessmentOrchestrator()
        result = orch.assess("example.com")

        assert result.status == "completed"
        assert len(result.errors) == 1
        assert "SSL" in result.errors[0]

    @patch.object(AssessmentOrchestrator, "_check_ssl")
    @patch.object(AssessmentOrchestrator, "_check_headers")
    @patch.object(AssessmentOrchestrator, "_check_dns")
    def test_assess_only_ssl(
        self, mock_dns: MagicMock, mock_headers: MagicMock, mock_ssl: MagicMock
    ) -> None:
        """Test assess with only SSL enabled."""
        mock_ssl.return_value = []

        opts = AssessmentOptions(check_ssl=True, check_headers=False, check_dns=False)
        orch = AssessmentOrchestrator(options=opts)
        result = orch.assess("example.com")

        mock_ssl.assert_called_once()
        mock_headers.assert_not_called()
        mock_dns.assert_not_called()
        assert result.status == "completed"

    @patch.object(AssessmentOrchestrator, "_check_ssl")
    @patch.object(AssessmentOrchestrator, "_check_headers")
    @patch.object(AssessmentOrchestrator, "_check_dns")
    def test_assess_with_min_severity(
        self, mock_dns: MagicMock, mock_headers: MagicMock, mock_ssl: MagicMock
    ) -> None:
        """Test assess filters by min_severity."""
        mock_ssl.return_value = [
            ConfigIssue(id="low-1", title="Low Issue", severity=SeverityLevel.LOW, category="ssl"),
            ConfigIssue(
                id="high-1", title="High Issue", severity=SeverityLevel.HIGH, category="ssl"
            ),
        ]
        mock_headers.return_value = []
        mock_dns.return_value = []

        opts = AssessmentOptions(min_severity=SeverityLevel.HIGH)
        orch = AssessmentOrchestrator(options=opts)
        result = orch.assess("example.com")

        # Should filter out LOW severity
        assert len(result.config_issues) == 1
        assert result.config_issues[0].severity == SeverityLevel.HIGH


class TestAssessmentOrchestratorParallel:
    """Tests for AssessmentOrchestrator assess_parallel method."""

    @patch.object(AssessmentOrchestrator, "_check_ssl")
    @patch.object(AssessmentOrchestrator, "_check_headers")
    @patch.object(AssessmentOrchestrator, "_check_dns")
    def test_assess_parallel_runs_all_checks(
        self, mock_dns: MagicMock, mock_headers: MagicMock, mock_ssl: MagicMock
    ) -> None:
        """Test assess_parallel runs all enabled checks."""
        mock_ssl.return_value = []
        mock_headers.return_value = []
        mock_dns.return_value = []

        orch = AssessmentOrchestrator()
        result = orch.assess_parallel("example.com")

        mock_ssl.assert_called_once()
        mock_headers.assert_called_once()
        mock_dns.assert_called_once()
        assert result.status == "completed"
        assert result.scan_type == "assess"

    @patch.object(AssessmentOrchestrator, "_check_ssl")
    @patch.object(AssessmentOrchestrator, "_check_headers")
    @patch.object(AssessmentOrchestrator, "_check_dns")
    def test_assess_parallel_handles_exception(
        self, mock_dns: MagicMock, mock_headers: MagicMock, mock_ssl: MagicMock
    ) -> None:
        """Test assess_parallel handles exceptions."""
        mock_ssl.side_effect = Exception("SSL error")
        mock_headers.return_value = []
        mock_dns.return_value = []

        orch = AssessmentOrchestrator()
        result = orch.assess_parallel("example.com")

        assert result.status == "completed"
        assert len(result.errors) == 1


class TestAssessmentOrchestratorIndividual:
    """Tests for individual assessment methods."""

    @patch.object(AssessmentOrchestrator, "_check_ssl")
    def test_assess_ssl(self, mock_ssl: MagicMock) -> None:
        """Test assess_ssl runs SSL check only."""
        mock_ssl.return_value = [
            ConfigIssue(id="ssl-1", title="SSL Issue", severity=SeverityLevel.HIGH, category="ssl")
        ]

        orch = AssessmentOrchestrator()
        result = orch.assess_ssl("example.com")

        assert result.scan_type == "assess_ssl"
        assert result.status == "completed"
        assert len(result.config_issues) == 1

    @patch.object(AssessmentOrchestrator, "_check_ssl")
    def test_assess_ssl_handles_exception(self, mock_ssl: MagicMock) -> None:
        """Test assess_ssl handles exception."""
        mock_ssl.side_effect = Exception("SSL error")

        orch = AssessmentOrchestrator()
        result = orch.assess_ssl("example.com")

        assert result.status == "completed"
        assert len(result.errors) == 1

    @patch.object(AssessmentOrchestrator, "_check_headers")
    def test_assess_headers(self, mock_headers: MagicMock) -> None:
        """Test assess_headers runs headers check only."""
        mock_headers.return_value = [
            ConfigIssue(
                id="hdr-1", title="Header Issue", severity=SeverityLevel.MEDIUM, category="headers"
            )
        ]

        orch = AssessmentOrchestrator()
        result = orch.assess_headers("example.com")

        assert result.scan_type == "assess_headers"
        assert result.status == "completed"
        assert len(result.config_issues) == 1

    @patch.object(AssessmentOrchestrator, "_check_headers")
    def test_assess_headers_handles_exception(self, mock_headers: MagicMock) -> None:
        """Test assess_headers handles exception."""
        mock_headers.side_effect = Exception("Headers error")

        orch = AssessmentOrchestrator()
        result = orch.assess_headers("example.com")

        assert result.status == "completed"
        assert len(result.errors) == 1

    @patch.object(AssessmentOrchestrator, "_check_dns")
    def test_assess_dns(self, mock_dns: MagicMock) -> None:
        """Test assess_dns runs DNS check only."""
        mock_dns.return_value = [
            ConfigIssue(id="dns-1", title="DNS Issue", severity=SeverityLevel.LOW, category="dns")
        ]

        orch = AssessmentOrchestrator()
        result = orch.assess_dns("example.com")

        assert result.scan_type == "assess_dns"
        assert result.status == "completed"
        assert len(result.config_issues) == 1

    @patch.object(AssessmentOrchestrator, "_check_dns")
    def test_assess_dns_handles_exception(self, mock_dns: MagicMock) -> None:
        """Test assess_dns handles exception."""
        mock_dns.side_effect = Exception("DNS error")

        orch = AssessmentOrchestrator()
        result = orch.assess_dns("example.com")

        assert result.status == "completed"
        assert len(result.errors) == 1


class TestRunAssessmentFunction:
    """Tests for run_assessment convenience function."""

    @patch.object(AssessmentOrchestrator, "assess")
    def test_run_assessment_sequential(self, mock_assess: MagicMock) -> None:
        """Test run_assessment runs sequential assessment."""
        from datetime import datetime

        from domainraptor.core.types import ScanResult

        mock_assess.return_value = ScanResult(
            target="example.com", scan_type="assess", status="completed", started_at=datetime.now()
        )

        result = run_assessment("example.com", parallel=False)

        mock_assess.assert_called_once_with("example.com")
        assert result.status == "completed"

    @patch.object(AssessmentOrchestrator, "assess_parallel")
    def test_run_assessment_parallel(self, mock_assess_parallel: MagicMock) -> None:
        """Test run_assessment runs parallel assessment."""
        from datetime import datetime

        from domainraptor.core.types import ScanResult

        mock_assess_parallel.return_value = ScanResult(
            target="example.com", scan_type="assess", status="completed", started_at=datetime.now()
        )

        result = run_assessment("example.com", parallel=True)

        mock_assess_parallel.assert_called_once_with("example.com")
        assert result.status == "completed"

    @patch.object(AssessmentOrchestrator, "assess")
    def test_run_assessment_with_options(self, mock_assess: MagicMock) -> None:
        """Test run_assessment passes options correctly."""
        from datetime import datetime

        from domainraptor.core.types import ScanResult

        mock_assess.return_value = ScanResult(
            target="example.com", scan_type="assess", status="completed", started_at=datetime.now()
        )

        run_assessment(
            "example.com",
            check_ssl=False,
            check_headers=True,
            check_dns=False,
            min_severity=SeverityLevel.HIGH,
        )

        mock_assess.assert_called_once()
