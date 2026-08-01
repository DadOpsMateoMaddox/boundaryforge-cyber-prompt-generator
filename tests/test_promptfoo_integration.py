"""Tests for promptfoo integration and exports."""

import json

import pytest

from prompt_generator.export.json import export_json
from prompt_generator.export.markdown import export_markdown
from prompt_generator.generation import generate_package
from prompt_generator.integrations.promptfoo import export_promptfoo_dataset, write_promptfoo_config
from prompt_generator.models import ExchangeType
from prompt_generator.validators import BoundaryForgeValidator


def test_promptfoo_dataset_structure(tmp_path):
    package = generate_package(
        domain="web_sql_injection",
        exchange_type=ExchangeType.AGENTIC,
        humanize=False,
        seed=42,
    )
    dataset_path = tmp_path / "promptfoo_dataset.json"
    export_promptfoo_dataset(package, dataset_path)

    data = json.loads(dataset_path.read_text(encoding="utf-8"))
    assert len(data) == 3
    for record in data:
        assert "vars" in record
        assert "full_prompt" in record["vars"]
        assert "danger_level" in record["vars"]


def test_promptfoo_config_written(tmp_path):
    pytest.importorskip("yaml")
    dataset_path = tmp_path / "promptfoo_dataset.json"
    config_path = tmp_path / "promptfooconfig.yaml"

    package = generate_package(
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.USER_QUESTION,
        humanize=False,
        seed=42,
    )
    export_promptfoo_dataset(package, dataset_path)
    write_promptfoo_config(dataset_path, config_path)

    assert config_path.exists()
    text = config_path.read_text(encoding="utf-8")
    assert "BoundaryForge" in text
    assert str(dataset_path.as_posix()) in text


def test_json_export(tmp_path):
    package = generate_package(
        domain="linux_privilege_escalation",
        exchange_type=ExchangeType.USER_QUESTION,
        humanize=False,
        seed=42,
    )
    validator = BoundaryForgeValidator()
    report = validator.validate(package)
    path = tmp_path / "package.json"
    export_json(package, report, path)

    data = json.loads(path.read_text(encoding="utf-8"))
    assert "package" in data
    assert "validation_report" in data


def test_markdown_export(tmp_path):
    package = generate_package(
        domain="linux_privilege_escalation",
        exchange_type=ExchangeType.USER_QUESTION,
        humanize=False,
        seed=42,
    )
    validator = BoundaryForgeValidator()
    report = validator.validate(package)
    path = tmp_path / "package.md"
    export_markdown(package, report, path)

    text = path.read_text(encoding="utf-8")
    assert package.package_id in text
    assert report.readiness_status.value in text
