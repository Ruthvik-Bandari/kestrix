"""Every report and run manifest names the tool and its author."""

from typer.testing import CliRunner

from kestrix import ATTRIBUTION, __author__
from kestrix.bitcoin.models import GuardianResult, MigrationPlan, ScanResult
from kestrix.cli import app
from kestrix.core.evidence import now, run_manifest
from kestrix.forensics.models import FileReport, UrlReport
from kestrix.mail.models import MailReport
from kestrix.webcheck.models import Report


def test_attribution_names_the_author():
    assert __author__ == "Ruthvik Bandari"
    assert ATTRIBUTION == "Kestrix by Ruthvik Bandari"


def test_every_report_model_defaults_to_the_attribution():
    for model in (MailReport, FileReport, UrlReport, ScanResult, MigrationPlan, GuardianResult, Report):
        assert model.model_fields["generated_by"].default == ATTRIBUTION


def test_run_manifest_and_version_carry_the_attribution():
    assert run_manifest(now())["generated_by"] == ATTRIBUTION
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0 and ATTRIBUTION in result.output
