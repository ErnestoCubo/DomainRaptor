"""Tests for db CLI commands."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from domainraptor.cli.main import app
from domainraptor.core.types import AssetType

runner = CliRunner()


# ============================================================================
# Helper Factories
# ============================================================================


def create_mock_scan(
    scan_id: int = 1,
    target: str = "example.com",
    scan_type: str = "discover",
    status: str = "completed",
) -> MagicMock:
    """Create a mock scan object."""
    scan = MagicMock()
    scan.id = scan_id
    scan.target = target
    scan.scan_type = scan_type
    scan.status = status
    scan.started_at = datetime(2024, 1, 15, 10, 0, 0)
    scan.completed_at = datetime(2024, 1, 15, 10, 5, 0)
    scan.duration_seconds = 300.0
    scan.assets = [
        MagicMock(type=AssetType.SUBDOMAIN, value="api.example.com", source="crtsh"),
    ]
    scan.dns_records = [
        MagicMock(record_type="A", value="1.2.3.4", ttl=300),
    ]
    scan.certificates = []
    scan.config_issues = []
    scan.vulnerabilities = []
    return scan


def create_scan_dict(
    scan_id: int = 1,
    target: str = "example.com",
    scan_type: str = "discover",
    status: str = "completed",
) -> dict:
    """Create a scan dictionary for list_scans."""
    return {
        "id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "status": status,
        "started_at": "2024-01-15T10:00:00",
        "asset_count": 5,
        "issue_count": 2,
        "vuln_count": 1,
    }


# ============================================================================
# List Scans Command Tests
# ============================================================================


class TestDbList:
    """Tests for db list command."""

    def test_list_no_scans(self) -> None:
        """Test list when no scans exist."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.list_scans.return_value = []
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "list"])

        assert result.exit_code == 0
        assert "No scans found" in result.output

    def test_list_with_scans(self) -> None:
        """Test list with existing scans."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.list_scans.return_value = [
                create_scan_dict(1, "example.com"),
                create_scan_dict(2, "test.org"),
            ]
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "list"])

        assert result.exit_code == 0
        # Target names may be truncated in table display
        assert "example" in result.output
        assert "test.org" in result.output

    def test_list_with_target_filter(self) -> None:
        """Test list with target filter."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.list_scans.return_value = [create_scan_dict()]
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "list", "--target", "example.com"])

        assert result.exit_code == 0
        mock_repo.list_scans.assert_called_once_with(target="example.com", scan_type=None, limit=20)

    def test_list_with_type_filter(self) -> None:
        """Test list with type filter."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.list_scans.return_value = [create_scan_dict()]
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "list", "--type", "discover"])

        assert result.exit_code == 0
        mock_repo.list_scans.assert_called_once_with(target=None, scan_type="discover", limit=20)

    def test_list_with_limit(self) -> None:
        """Test list with custom limit."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.list_scans.return_value = [create_scan_dict()]
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "list", "--limit", "5"])

        assert result.exit_code == 0
        mock_repo.list_scans.assert_called_once_with(target=None, scan_type=None, limit=5)


# ============================================================================
# Show Scan Command Tests
# ============================================================================


class TestDbShow:
    """Tests for db show command."""

    def test_show_scan_not_found(self) -> None:
        """Test show when scan doesn't exist."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.get_by_id.return_value = None
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "show", "999"])

        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_show_scan_basic(self) -> None:
        """Test show scan basic info."""
        mock_scan = create_mock_scan()

        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.get_by_id.return_value = mock_scan
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "show", "1"])

        assert result.exit_code == 0
        assert "example.com" in result.output
        assert "discover" in result.output

    def test_show_scan_full(self) -> None:
        """Test show scan with full details."""
        mock_scan = create_mock_scan()

        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.get_by_id.return_value = mock_scan
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "show", "1", "--full"])

        assert result.exit_code == 0
        assert "Assets" in result.output or "example.com" in result.output


# ============================================================================
# Delete Scan Command Tests
# ============================================================================


class TestDbDelete:
    """Tests for db delete command."""

    def test_delete_not_found(self) -> None:
        """Test delete when scan doesn't exist."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.get_by_id.return_value = None
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "delete", "999"])

        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_delete_with_force(self) -> None:
        """Test delete with force flag."""
        mock_scan = create_mock_scan()

        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.get_by_id.return_value = mock_scan
            mock_repo.delete.return_value = True
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "delete", "1", "--force"])

        assert result.exit_code == 0
        assert "Deleted" in result.output
        mock_repo.delete.assert_called_once_with(1)

    def test_delete_cancelled(self) -> None:
        """Test delete cancelled by user."""
        mock_scan = create_mock_scan()

        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.get_by_id.return_value = mock_scan
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "delete", "1"], input="n\n")

        assert result.exit_code == 0
        assert "Cancel" in result.output
        mock_repo.delete.assert_not_called()

    def test_delete_confirmed(self) -> None:
        """Test delete confirmed by user."""
        mock_scan = create_mock_scan()

        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.get_by_id.return_value = mock_scan
            mock_repo.delete.return_value = True
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "delete", "1"], input="y\n")

        assert result.exit_code == 0
        mock_repo.delete.assert_called_once_with(1)

    def test_delete_failed(self) -> None:
        """Test delete fails."""
        mock_scan = create_mock_scan()

        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.get_by_id.return_value = mock_scan
            mock_repo.delete.return_value = False
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "delete", "1", "--force"])

        assert result.exit_code == 0  # Command completes, error message shown
        assert "Failed" in result.output


# ============================================================================
# Export Scan Command Tests
# ============================================================================


class TestDbExport:
    """Tests for db export command."""

    def test_export_not_found(self) -> None:
        """Test export when scan doesn't exist."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.export_to_json.return_value = None
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "export", "999"])

        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_export_json_stdout(self) -> None:
        """Test export JSON to stdout."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.export_to_json.return_value = {
                "id": 1,
                "target": "example.com",
                "assets": [],
            }
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "export", "1"])

        assert result.exit_code == 0
        assert "example.com" in result.output

    def test_export_json_file(self, tmp_path: Path) -> None:
        """Test export JSON to file."""
        output_file = tmp_path / "export.json"

        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.export_to_json.return_value = {
                "id": 1,
                "target": "example.com",
                "assets": [],
            }
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(
                app, ["--no-banner", "db", "export", "1", "-o", str(output_file)]
            )

        assert result.exit_code == 0
        assert output_file.exists()
        assert "example.com" in output_file.read_text()

    def test_export_csv_stdout(self) -> None:
        """Test export CSV to stdout."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.export_to_json.return_value = {
                "id": 1,
                "target": "example.com",
                "assets": [{"type": "subdomain", "value": "api.example.com", "source": "crtsh"}],
                "dns_records": [],
                "config_issues": [],
                "vulnerabilities": [],
            }
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "export", "1", "--format", "csv"])

        assert result.exit_code == 0
        assert "category" in result.output
        assert "asset" in result.output

    def test_export_csv_file(self, tmp_path: Path) -> None:
        """Test export CSV to file."""
        output_file = tmp_path / "export.csv"

        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.export_to_json.return_value = {
                "id": 1,
                "target": "example.com",
                "assets": [{"type": "subdomain", "value": "api.example.com", "source": "crtsh"}],
                "dns_records": [],
                "config_issues": [],
                "vulnerabilities": [],
            }
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(
                app,
                ["--no-banner", "db", "export", "1", "-f", "csv", "-o", str(output_file)],
            )

        assert result.exit_code == 0
        assert output_file.exists()

    def test_export_unknown_format(self) -> None:
        """Test export with unknown format."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.export_to_json.return_value = {"id": 1}
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "export", "1", "--format", "xml"])

        assert result.exit_code == 1
        assert "Unknown format" in result.output


# ============================================================================
# Prune Scans Command Tests
# ============================================================================


class TestDbPrune:
    """Tests for db prune command."""

    def test_prune_with_force(self) -> None:
        """Test prune with force flag."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.prune.return_value = 5
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "prune", "--force"])

        assert result.exit_code == 0
        assert "5" in result.output
        mock_repo.prune.assert_called_once_with(30)  # default days

    def test_prune_custom_days(self) -> None:
        """Test prune with custom days."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.prune.return_value = 3
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(
                app, ["--no-banner", "db", "prune", "--older-than", "7", "--force"]
            )

        assert result.exit_code == 0
        mock_repo.prune.assert_called_once_with(7)

    def test_prune_cancelled(self) -> None:
        """Test prune cancelled by user."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "prune"], input="n\n")

        assert result.exit_code == 0
        assert "Cancel" in result.output
        mock_repo.prune.assert_not_called()

    def test_prune_no_scans(self) -> None:
        """Test prune when no scans to prune."""
        with patch("domainraptor.storage.ScanRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.prune.return_value = 0
            mock_repo_class.return_value = mock_repo

            result = runner.invoke(app, ["--no-banner", "db", "prune", "--force"])

        assert result.exit_code == 0
        assert "No scans to prune" in result.output


# ============================================================================
# Stats Command Tests
# ============================================================================


class TestDbStats:
    """Tests for db stats command."""

    def test_stats_basic(self) -> None:
        """Test stats command."""
        mock_db = MagicMock()
        mock_db_path = MagicMock()
        mock_db_path.exists.return_value = False
        mock_db.db_path = mock_db_path

        with (
            patch("domainraptor.storage.ScanRepository") as mock_scan_repo_class,
            patch("domainraptor.storage.WatchRepository") as mock_watch_repo_class,
            patch("domainraptor.storage.get_database", return_value=mock_db),
        ):
            mock_scan_repo = MagicMock()
            mock_scan_repo.list_scans.return_value = [
                {"target": "example.com", "scan_type": "discover"},
                {"target": "example.com", "scan_type": "assess"},
                {"target": "test.org", "scan_type": "discover"},
            ]
            mock_scan_repo_class.return_value = mock_scan_repo

            mock_watch_repo = MagicMock()
            mock_watch_repo.count.return_value = 2
            mock_watch_repo_class.return_value = mock_watch_repo

            result = runner.invoke(app, ["--no-banner", "db", "stats"])

        assert result.exit_code == 0
        assert "Total scans" in result.output
        assert "3" in result.output  # 3 total scans
        assert "Unique targets" in result.output

    def test_stats_with_db_size(self, tmp_path: Path) -> None:
        """Test stats with database file size."""
        # Create a test db file
        db_file = tmp_path / "test.db"
        db_file.write_text("x" * 1024)  # 1KB

        mock_db = MagicMock()
        mock_db.db_path = db_file

        with (
            patch("domainraptor.storage.ScanRepository") as mock_scan_repo_class,
            patch("domainraptor.storage.WatchRepository") as mock_watch_repo_class,
            patch("domainraptor.storage.get_database", return_value=mock_db),
        ):
            mock_scan_repo = MagicMock()
            mock_scan_repo.list_scans.return_value = []
            mock_scan_repo_class.return_value = mock_scan_repo

            mock_watch_repo = MagicMock()
            mock_watch_repo.count.return_value = 0
            mock_watch_repo_class.return_value = mock_watch_repo

            result = runner.invoke(app, ["--no-banner", "db", "stats"])

        assert result.exit_code == 0
        assert "KB" in result.output or "Database size" in result.output
