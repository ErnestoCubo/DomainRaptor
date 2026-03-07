"""Assessment orchestrator for coordinating security checks."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from domainraptor.assessment.base import (
    AssessmentConfig,
    filter_by_min_severity,
    sort_by_severity,
)
from domainraptor.assessment.dns_security import DnsSecurityChecker
from domainraptor.assessment.headers_checker import HeadersChecker
from domainraptor.assessment.ssl_analyzer import SSLAnalyzer
from domainraptor.core.types import ConfigIssue, ScanResult, SeverityLevel

logger = logging.getLogger(__name__)


@dataclass
class AssessmentOptions:
    """Options for assessment orchestration."""

    check_ssl: bool = True
    check_headers: bool = True
    check_dns: bool = True
    min_severity: SeverityLevel = SeverityLevel.LOW
    timeout: int = 30
    max_workers: int = 3


@dataclass
class AssessmentProgress:
    """Track assessment progress."""

    total_checks: int = 0
    completed_checks: int = 0
    current_check: str = ""
    errors: list[str] = field(default_factory=list)


class AssessmentOrchestrator:
    """Orchestrate security assessments across multiple checkers."""

    def __init__(
        self,
        options: AssessmentOptions | None = None,
        progress_callback: Callable[[AssessmentProgress], None] | None = None,
    ) -> None:
        self.options = options or AssessmentOptions()
        self.progress_callback = progress_callback
        self._progress = AssessmentProgress()

        # Initialize config
        self._config = AssessmentConfig(timeout=self.options.timeout)

    def assess(self, target: str) -> ScanResult:
        """Perform full security assessment on target."""
        result = ScanResult(
            target=target,
            scan_type="assess",
            started_at=datetime.now(),
        )

        # Determine which checks to run
        checks: list[tuple[str, Callable[[], list[ConfigIssue]]]] = []

        if self.options.check_ssl:
            checks.append(("SSL/TLS", lambda: self._check_ssl(target)))

        if self.options.check_headers:
            checks.append(("HTTP Headers", lambda: self._check_headers(target)))

        if self.options.check_dns:
            checks.append(("DNS Security", lambda: self._check_dns(target)))

        self._progress.total_checks = len(checks)
        self._progress.completed_checks = 0

        # Run checks (can be parallelized but keeping sequential for progress reporting)
        all_issues: list[ConfigIssue] = []

        for check_name, check_func in checks:
            self._progress.current_check = check_name
            self._report_progress()

            try:
                issues = check_func()
                all_issues.extend(issues)
            except Exception as e:
                error_msg = f"{check_name} failed: {e}"
                logger.error(error_msg)
                result.errors.append(error_msg)
                self._progress.errors.append(error_msg)

            self._progress.completed_checks += 1
            self._report_progress()

        # Filter by severity
        filtered_issues = filter_by_min_severity(all_issues, self.options.min_severity)

        # Sort by severity
        result.config_issues = sort_by_severity(filtered_issues)

        result.completed_at = datetime.now()
        result.status = "completed"

        return result

    def assess_parallel(self, target: str) -> ScanResult:
        """Perform assessment with parallel execution."""
        result = ScanResult(
            target=target,
            scan_type="assess",
            started_at=datetime.now(),
        )

        checks: dict[str, Callable[[], list[ConfigIssue]]] = {}

        if self.options.check_ssl:
            checks["SSL/TLS"] = lambda: self._check_ssl(target)

        if self.options.check_headers:
            checks["HTTP Headers"] = lambda: self._check_headers(target)

        if self.options.check_dns:
            checks["DNS Security"] = lambda: self._check_dns(target)

        self._progress.total_checks = len(checks)
        self._progress.completed_checks = 0

        all_issues: list[ConfigIssue] = []

        with ThreadPoolExecutor(max_workers=self.options.max_workers) as executor:
            future_to_name = {
                executor.submit(check_func): name
                for name, check_func in checks.items()
            }

            for future in as_completed(future_to_name):
                name = future_to_name[future]
                self._progress.current_check = name

                try:
                    issues = future.result()
                    all_issues.extend(issues)
                except Exception as e:
                    error_msg = f"{name} failed: {e}"
                    logger.error(error_msg)
                    result.errors.append(error_msg)

                self._progress.completed_checks += 1
                self._report_progress()

        # Filter and sort
        filtered_issues = filter_by_min_severity(all_issues, self.options.min_severity)
        result.config_issues = sort_by_severity(filtered_issues)

        result.completed_at = datetime.now()
        result.status = "completed"

        return result

    def assess_ssl(self, target: str) -> ScanResult:
        """Perform SSL/TLS assessment only."""
        result = ScanResult(
            target=target,
            scan_type="assess_ssl",
            started_at=datetime.now(),
        )

        try:
            issues = self._check_ssl(target)
            result.config_issues = sort_by_severity(
                filter_by_min_severity(issues, self.options.min_severity)
            )
        except Exception as e:
            result.errors.append(f"SSL check failed: {e}")

        result.completed_at = datetime.now()
        result.status = "completed"
        return result

    def assess_headers(self, target: str) -> ScanResult:
        """Perform HTTP headers assessment only."""
        result = ScanResult(
            target=target,
            scan_type="assess_headers",
            started_at=datetime.now(),
        )

        try:
            issues = self._check_headers(target)
            result.config_issues = sort_by_severity(
                filter_by_min_severity(issues, self.options.min_severity)
            )
        except Exception as e:
            result.errors.append(f"Headers check failed: {e}")

        result.completed_at = datetime.now()
        result.status = "completed"
        return result

    def assess_dns(self, target: str) -> ScanResult:
        """Perform DNS security assessment only."""
        result = ScanResult(
            target=target,
            scan_type="assess_dns",
            started_at=datetime.now(),
        )

        try:
            issues = self._check_dns(target)
            result.config_issues = sort_by_severity(
                filter_by_min_severity(issues, self.options.min_severity)
            )
        except Exception as e:
            result.errors.append(f"DNS check failed: {e}")

        result.completed_at = datetime.now()
        result.status = "completed"
        return result

    def _check_ssl(self, target: str) -> list[ConfigIssue]:
        """Run SSL/TLS checker."""
        with SSLAnalyzer(self._config) as checker:
            return checker.assess(target)

    def _check_headers(self, target: str) -> list[ConfigIssue]:
        """Run HTTP headers checker."""
        with HeadersChecker(self._config) as checker:
            return checker.assess(target)

    def _check_dns(self, target: str) -> list[ConfigIssue]:
        """Run DNS security checker."""
        with DnsSecurityChecker(self._config) as checker:
            return checker.assess(target)

    def _report_progress(self) -> None:
        """Report progress via callback if set."""
        if self.progress_callback:
            self.progress_callback(self._progress)


def run_assessment(
    target: str,
    check_ssl: bool = True,
    check_headers: bool = True,
    check_dns: bool = True,
    min_severity: SeverityLevel = SeverityLevel.LOW,
    parallel: bool = False,
) -> ScanResult:
    """Convenience function to run assessment."""
    options = AssessmentOptions(
        check_ssl=check_ssl,
        check_headers=check_headers,
        check_dns=check_dns,
        min_severity=min_severity,
    )

    orchestrator = AssessmentOrchestrator(options)

    if parallel:
        return orchestrator.assess_parallel(target)
    return orchestrator.assess(target)
