"""MCP tool server reads Elastic config through resolve(), not ELASTIC_* env."""

from unittest.mock import patch

import pytest

from core.integrations.elastic import tool as elastic_tool

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_cached_service():
    elastic_tool._elastic_service = None
    yield
    elastic_tool._elastic_service = None


def _resolved(**overrides):
    config = {
        "elasticsearch_url": "https://es.test:9200",
        "kibana_url": "https://kibana.test:5601",
        "api_key": "secret-from-store",
        "username": None,
        "password": None,
        "index_pattern": None,
        "verify_ssl": None,
    }
    config.update(overrides)
    return config


def test_resolved_fields_reach_the_client():
    with patch.object(elastic_tool, "resolve", return_value=_resolved()):
        svc = elastic_tool.get_elastic_service()
    assert svc is not None
    assert svc.elasticsearch_url == "https://es.test:9200"
    assert svc.api_key == "secret-from-store"
    assert svc.verify_ssl is True
    assert svc.index_pattern == ".alerts-security.alerts-default"


def test_verify_ssl_false_is_preserved():
    with patch.object(
        elastic_tool, "resolve", return_value=_resolved(verify_ssl=False)
    ):
        svc = elastic_tool.get_elastic_service()
    assert svc is not None
    assert svc.verify_ssl is False


def test_ca_cert_path_reaches_the_client():
    with patch.object(
        elastic_tool,
        "resolve",
        return_value=_resolved(ca_cert_path="/etc/vigil/certs/root-ca.pem"),
    ):
        svc = elastic_tool.get_elastic_service()
    assert svc is not None
    assert svc.ca_cert_path == "/etc/vigil/certs/root-ca.pem"


def test_blank_ca_cert_path_is_unset():
    with patch.object(
        elastic_tool, "resolve", return_value=_resolved(ca_cert_path="")
    ):
        svc = elastic_tool.get_elastic_service()
    assert svc is not None
    assert svc.ca_cert_path is None


@pytest.mark.asyncio
async def test_unusable_ca_path_is_reported_to_the_tool_caller(tmp_path):
    """The operator's mistake must reach the agent as an error naming the
    file, not as a generic search failure."""
    from types import SimpleNamespace

    missing = tmp_path / "no-such-ca.pem"
    with patch.object(
        elastic_tool,
        "resolve",
        return_value=_resolved(kibana_url=None, ca_cert_path=str(missing)),
    ):
        outcome = await elastic_tool._on_call_tool(
            None,
            SimpleNamespace(
                name="elastic_search_logs", arguments={"query": '{"match_all": {}}'}
            ),
        )
    assert outcome.is_error is True
    assert "no-such-ca.pem" in outcome.content[0].text


def test_missing_url_is_not_configured():
    with patch.object(
        elastic_tool, "resolve", return_value=_resolved(elasticsearch_url=None)
    ):
        assert elastic_tool.get_elastic_service() is None
