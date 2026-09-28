"""Elastic ingestion without Kibana reads a Wazuh indexer's alert index.

A Wazuh indexer is OpenSearch with no Kibana: its alerts are documents in
``wazuh-alerts-4.x-*``. With the Kibana URL blank, ``ElasticIngestion`` polls
the configured index pattern for alerts at or above a rule level and maps the
Wazuh schema (``rule.level``, ``rule.description``, ``rule.mitre.id``,
``agent.name``, ``data.*``) onto a finding.
"""

import json
import logging
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from core.federation.adapters._siem_base import SIEMIngestionAdapter
from core.integrations.elastic import ingestion as elastic_ingestion
from core.integrations.elastic.ingestion import (
    DEFAULT_MIN_RULE_LEVEL,
    INDEXING_DELAY,
    ElasticIngestion,
    is_wazuh_alert,
    min_rule_level_from_config,
    severity_for_rule_level,
)

pytestmark = pytest.mark.unit

ES_URL = "https://indexer.test:9200"
INDEX = "wazuh-alerts-4.x-*"
SEARCH = f"{ES_URL}/{INDEX}/_search"
NOW = datetime(2026, 9, 28, 12, 0, 0)

# Shape taken from a live wazuh-alerts-4.x document (Wazuh 4.14) after its
# Filebeat pipeline: `timestamp` copied into `@timestamp`, no `host`.
ALERT = {
    "_index": "wazuh-alerts-4.x-2026.09.28",
    "_id": "abc123",
    "_source": {
        "timestamp": "2026-09-28T06:17:18.394-0500",
        "@timestamp": "2026-09-28T11:17:18.394Z",
        "id": "1790597838.2112422",
        "agent": {"id": "001", "name": "web01", "ip": "10.0.0.5"},
        "manager": {"name": "wazuh-manager"},
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "sshd: brute force trying to get access to the system.",
            "groups": ["syslog", "sshd", "authentication_failures"],
            "mitre": {
                "id": ["T1110"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"],
            },
        },
        "data": {
            "srcip": "203.0.113.7",
            "dstuser": "root",
            "win": {"eventdata": {"targetUserName": "svc-backup"}},
        },
        "full_log": "Sep 28 11:17:17 web01 sshd[1]: Failed password for root",
    },
}


def _ingestion(**overrides) -> ElasticIngestion:
    config = {
        "elasticsearch_url": ES_URL,
        "kibana_url": None,
        "api_key": None,
        "username": "vigil-reader",
        "password": "secret",
        "index_pattern": INDEX,
        "min_rule_level": None,
        "verify_ssl": False,
    }
    config.update(overrides)
    with patch("core.integrations.elastic.ingestion.resolve", return_value=config):
        svc = ElasticIngestion()
    svc.ingestion_service = MagicMock()
    return svc


def _body(route) -> dict:
    return json.loads(route.calls.last.request.content)


def _range(body: dict, field: str) -> dict:
    for clause in body["query"]["bool"]["filter"]:
        if field in clause.get("range", {}):
            return clause["range"][field]
    raise AssertionError(f"no range filter on {field}: {body}")


@pytest.fixture
def frozen_now(monkeypatch):
    monkeypatch.setattr(elastic_ingestion, "utcnow", lambda: NOW)
    return NOW


# -- configuration ---------------------------------------------------------


@pytest.mark.parametrize(
    "stored,expected",
    [
        (None, DEFAULT_MIN_RULE_LEVEL),
        (0, DEFAULT_MIN_RULE_LEVEL),
        ("", DEFAULT_MIN_RULE_LEVEL),
        (12, 12),
        ("12", 12),
        (99, 16),
        (-3, 1),
        ("junk", DEFAULT_MIN_RULE_LEVEL),
    ],
)
def test_min_rule_level_from_config(stored, expected):
    assert min_rule_level_from_config({"min_rule_level": stored}) == expected


@respx.mock
@pytest.mark.asyncio
async def test_configured_level_reaches_the_query(frozen_now):
    route = respx.post(SEARCH).mock(
        return_value=httpx.Response(
            200, json={"hits": {"total": {"value": 0}, "hits": []}}
        )
    )
    ingestion = _ingestion(min_rule_level=12)
    await ingestion.fetch_alerts(start_time=NOW - timedelta(minutes=5))
    assert _range(_body(route), "rule.level") == {"gte": 12}
    await ingestion._get_elastic_service().close()


@pytest.mark.parametrize(
    "level,expected",
    [
        (0, "info"),
        (3, "info"),
        (4, "low"),
        (7, "medium"),
        (10, "high"),
        (12, "critical"),
        (15, "critical"),
        ("10", "high"),
        (None, "medium"),
    ],
)
def test_severity_for_rule_level(level, expected):
    assert severity_for_rule_level(level) == expected


def test_is_wazuh_alert_needs_a_rule_level():
    assert is_wazuh_alert(ALERT["_source"])
    # ECS rule field set: a name but no level.
    assert not is_wazuh_alert({"rule": {"name": "x", "id": "y"}})
    assert not is_wazuh_alert({"kibana.alert.rule.name": "x"})
    assert not is_wazuh_alert({"rule": "not a mapping"})
    assert not is_wazuh_alert({})
    # A detection alert wrapping an event that carries its own rule.level
    # (Wazuh forwarded into Elastic Security) is still a detection alert.
    assert not is_wazuh_alert(
        {"kibana.alert.rule.name": "x", "rule": {"level": 10, "description": "y"}}
    )
    assert not is_wazuh_alert({"signal": {"rule": {}}, "rule": {"level": 10}})


# -- fetch: index mode -----------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_without_kibana_queries_the_index_oldest_first(frozen_now):
    route = respx.post(SEARCH).mock(
        return_value=httpx.Response(
            200, json={"hits": {"total": {"value": 1}, "hits": [ALERT]}}
        )
    )
    ingestion = _ingestion()
    start = NOW - timedelta(minutes=5)

    hits = await ingestion.fetch_alerts(start_time=start, limit=50)

    assert hits == [ALERT]
    body = _body(route)
    assert body["size"] == 50
    assert body["sort"] == [
        {"@timestamp": {"order": "asc"}},
        {"_doc": {"order": "asc"}},
    ]
    assert _range(body, "rule.level") == {"gte": DEFAULT_MIN_RULE_LEVEL}
    window = _range(body, "@timestamp")
    # First poll in the process: one delay's worth before the cursor, up to
    # one delay ago.
    assert window == {
        "gte": (start - INDEXING_DELAY).isoformat() + "Z",
        "lte": (NOW - INDEXING_DELAY).isoformat() + "Z",
    }
    await ingestion._get_elastic_service().close()


@respx.mock
@pytest.mark.asyncio
async def test_consecutive_polls_are_contiguous_despite_a_wall_clock_cursor(
    monkeypatch,
):
    """The federation cursor after a short batch is the wall clock at the end
    of the poll, later than the window that poll read. The next window must
    start where the last one ended, not at the cursor."""
    route = respx.post(SEARCH).mock(
        return_value=httpx.Response(
            200, json={"hits": {"total": {"value": 0}, "hits": []}}
        )
    )
    ingestion = _ingestion()
    monkeypatch.setattr(elastic_ingestion, "utcnow", lambda: NOW)
    await ingestion.fetch_alerts(start_time=NOW - timedelta(minutes=5))
    first_until = _range(_body(route), "@timestamp")["lte"]

    # Cursor persisted by the runner: "now" at the end of the first poll.
    cursor = NOW
    later = NOW + timedelta(minutes=5)
    monkeypatch.setattr(elastic_ingestion, "utcnow", lambda: later)
    await ingestion.fetch_alerts(start_time=cursor)
    window = _range(_body(route), "@timestamp")

    assert window["gte"] == first_until
    assert window["lte"] == (later - INDEXING_DELAY).isoformat() + "Z"
    await ingestion._get_elastic_service().close()


@respx.mock
@pytest.mark.asyncio
async def test_a_cursor_older_than_the_last_window_end_wins(monkeypatch):
    """A full batch stops the cursor at its newest alert (or an operator
    resets it). That is earlier than the last window end and must not be
    skipped."""
    route = respx.post(SEARCH).mock(
        return_value=httpx.Response(
            200, json={"hits": {"total": {"value": 0}, "hits": []}}
        )
    )
    ingestion = _ingestion()
    monkeypatch.setattr(elastic_ingestion, "utcnow", lambda: NOW)
    await ingestion.fetch_alerts(start_time=NOW - timedelta(minutes=5))

    older_cursor = NOW - timedelta(minutes=3)
    monkeypatch.setattr(elastic_ingestion, "utcnow", lambda: NOW + timedelta(minutes=5))
    await ingestion.fetch_alerts(start_time=older_cursor)

    assert _range(_body(route), "@timestamp")["gte"] == older_cursor.isoformat() + "Z"
    await ingestion._get_elastic_service().close()


@respx.mock
@pytest.mark.asyncio
async def test_failed_search_keeps_the_window_end(monkeypatch):
    route = respx.post(SEARCH).mock(
        return_value=httpx.Response(
            200, json={"hits": {"total": {"value": 0}, "hits": []}}
        )
    )
    ingestion = _ingestion()
    monkeypatch.setattr(elastic_ingestion, "utcnow", lambda: NOW)
    await ingestion.fetch_alerts(start_time=NOW - timedelta(minutes=5))
    kept = ingestion._window_end
    assert kept == NOW - INDEXING_DELAY

    route.mock(return_value=httpx.Response(503, text="unavailable"))
    monkeypatch.setattr(elastic_ingestion, "utcnow", lambda: NOW + timedelta(minutes=5))
    with pytest.raises(RuntimeError, match="index search failed"):
        await ingestion.fetch_alerts(start_time=NOW)
    assert ingestion._window_end == kept
    await ingestion._get_elastic_service().close()


def _hit(ident: str, stamp: str) -> dict:
    return {
        "_index": "wazuh-alerts-4.x-2026.09.28",
        "_id": ident,
        "_source": {"@timestamp": stamp, "rule": {"level": 7, "description": ident}},
    }


@respx.mock
@pytest.mark.asyncio
async def test_a_full_batch_ends_the_window_at_its_newest_alert(monkeypatch):
    """Five alerts, limit 2, wall-clock cursor. The fake indexer honours the
    inclusive ``gte`` and ``size`` like a real one, so each full batch is
    followed by a re-read of its boundary alert (the runner dedups it) and
    nothing between the last returned alert and the query bound is lost."""
    # Stamped 11:55..11:59: inside the first window [11:54, 11:59].
    alerts = [_hit(f"a{i}", f"2026-09-28T11:5{5 + i}:00.000Z") for i in range(5)]

    def indexer(request):
        body = json.loads(request.content)
        gte = _range(body, "@timestamp")["gte"]
        # Compare to the second: the stamps are whole minutes, and a lexical
        # compare of "...00.000Z" against "...00Z" would drop the boundary.
        page = [h for h in alerts if h["_source"]["@timestamp"][:19] >= gte[:19]]
        page = page[: body["size"]]
        return httpx.Response(
            200, json={"hits": {"total": {"value": len(page)}, "hits": page}}
        )

    route = respx.post(SEARCH).mock(side_effect=indexer)
    ingestion = _ingestion()
    seen, windows = [], []
    for tick in range(6):
        now = NOW + timedelta(minutes=5 * tick)
        monkeypatch.setattr(elastic_ingestion, "utcnow", lambda now=now: now)
        # The runner persists the wall clock after every short or full batch.
        cursor = now - timedelta(minutes=5)
        batch = await ingestion.fetch_alerts(start_time=cursor, limit=2)
        seen += [h["_id"] for h in batch]
        windows.append(_range(_body(route), "@timestamp")["gte"])
        if len(batch) < 2:
            break

    # Full batches end the window at their newest alert; the next window
    # starts there and re-reads that one alert before moving on.
    assert windows == [
        "2026-09-28T11:54:00Z",
        "2026-09-28T11:56:00Z",
        "2026-09-28T11:57:00Z",
        "2026-09-28T11:58:00Z",
        "2026-09-28T11:59:00Z",
    ]
    assert seen == ["a0", "a1", "a1", "a2", "a2", "a3", "a3", "a4", "a4"]
    assert sorted(set(seen)) == ["a0", "a1", "a2", "a3", "a4"]
    assert ingestion._window_end == NOW + timedelta(minutes=20) - INDEXING_DELAY
    await ingestion._get_elastic_service().close()


@respx.mock
@pytest.mark.asyncio
async def test_a_full_batch_at_one_instant_steps_one_millisecond(frozen_now, caplog):
    """More alerts than fit at the very instant the window starts: the window
    must move past it rather than re-read the same page forever."""
    start = NOW - timedelta(minutes=5)
    since = start - INDEXING_DELAY  # first poll in the process
    stamp = since.isoformat(timespec="milliseconds") + "Z"
    respx.post(SEARCH).mock(
        return_value=httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 9},
                    "hits": [_hit("x", stamp), _hit("y", stamp)],
                }
            },
        )
    )
    ingestion = _ingestion()
    await ingestion.fetch_alerts(start_time=start, limit=2)
    assert ingestion._window_end == since + timedelta(milliseconds=1)
    assert "stepping to" in caplog.text
    await ingestion._get_elastic_service().close()


@respx.mock
@pytest.mark.asyncio
async def test_a_full_batch_without_readable_times_falls_back_to_the_bound(
    frozen_now, caplog
):
    respx.post(SEARCH).mock(
        return_value=httpx.Response(
            200,
            json={
                "hits": {"total": {"value": 9}, "hits": [{"_id": "n1", "_source": {}}]}
            },
        )
    )
    ingestion = _ingestion()
    await ingestion.fetch_alerts(start_time=NOW - timedelta(minutes=5), limit=1)
    assert ingestion._window_end == NOW - INDEXING_DELAY
    assert "no readable @timestamp" in caplog.text
    await ingestion._get_elastic_service().close()


def test_alert_time_parses_wazuh_and_aware_forms():
    from core.integrations.elastic.ingestion import _alert_time

    assert _alert_time(_hit("a", "2026-09-28T11:17:18.394Z")) == datetime(
        2026, 9, 28, 11, 17, 18, 394000
    )
    assert _alert_time(_hit("a", "2026-09-28T06:17:18.394-05:00")) == datetime(
        2026, 9, 28, 11, 17, 18, 394000
    )
    assert _alert_time(_hit("a", "garbage")) is None
    assert _alert_time({"_id": "a", "_source": {}}) is None


@respx.mock
@pytest.mark.asyncio
async def test_explicit_end_time_is_used_as_given(frozen_now):
    route = respx.post(SEARCH).mock(
        return_value=httpx.Response(
            200, json={"hits": {"total": {"value": 0}, "hits": []}}
        )
    )
    ingestion = _ingestion()
    start, end = NOW - timedelta(hours=2), NOW - timedelta(hours=1)
    await ingestion.fetch_alerts(start_time=start, end_time=end)
    assert _range(_body(route), "@timestamp") == {
        "gte": start.isoformat() + "Z",
        "lte": end.isoformat() + "Z",
    }
    # A caller-managed window does not move the poller's own window end.
    assert ingestion._window_end is None
    await ingestion._get_elastic_service().close()


@respx.mock
@pytest.mark.asyncio
async def test_a_full_batch_is_logged(frozen_now, caplog):
    caplog.set_level(logging.INFO, logger="core.integrations.elastic.ingestion")
    stamp = (NOW - timedelta(minutes=3)).isoformat(timespec="milliseconds") + "Z"
    respx.post(SEARCH).mock(
        return_value=httpx.Response(
            200, json={"hits": {"total": {"value": 250}, "hits": [_hit("f", stamp)]}}
        )
    )
    ingestion = _ingestion()
    hits = await ingestion.fetch_alerts(start_time=NOW - timedelta(minutes=5), limit=1)
    assert [h["_id"] for h in hits] == ["f"]
    assert "filled limit=1" in caplog.text
    assert ingestion._window_end == NOW - timedelta(minutes=3)
    await ingestion._get_elastic_service().close()


@pytest.mark.asyncio
async def test_with_kibana_the_detections_api_is_still_used():
    ingestion = _ingestion(kibana_url="https://kibana.test:5601")
    svc = ingestion._get_elastic_service()
    svc.fetch_detection_alerts = AsyncMock(return_value={"hits": {"hits": []}})
    svc.search = AsyncMock()
    await ingestion.fetch_alerts()
    svc.fetch_detection_alerts.assert_awaited_once()
    svc.search.assert_not_awaited()


@pytest.mark.asyncio
async def test_failed_index_search_reaches_the_runner_as_a_failure():
    ingestion = _ingestion()
    ingestion._get_elastic_service().search = AsyncMock(return_value=None)
    adapter = SIEMIngestionAdapter(
        name="elastic",
        integration_id="elastic-siem",
        default_interval=300,
        service_factory=lambda: ingestion,
        external_id_prefix="elastic",
    )
    with patch.object(adapter, "is_configured", return_value=True):
        with pytest.raises(RuntimeError):
            await adapter.fetch(since=None, cursor={}, max_items=10)


@pytest.mark.asyncio
async def test_status_sync_is_not_supported_without_kibana():
    ingestion = _ingestion()
    assert await ingestion.update_upstream_alert_status("abc123", "closed") is False


# -- transform: Wazuh schema -----------------------------------------------


def test_transform_maps_wazuh_fields():
    finding = _ingestion().transform_alert_to_finding(ALERT)

    assert finding["finding_id"] == "elastic-abc123"
    assert finding["data_source"] == "elastic"
    assert finding["severity"] == "high"
    assert finding["title"] == ALERT["_source"]["rule"]["description"]
    assert finding["description"].startswith("Sep 28 11:17:17 web01")
    assert finding["timestamp"] == "2026-09-28T11:17:18.394Z"
    assert finding["mitre_predictions"] == {"T1110": 0.9}
    assert finding["entity_context"] == {
        "src_ips": ["203.0.113.7"],
        "dest_ips": [],
        "hostnames": ["web01"],
        "usernames": ["root", "svc-backup"],
    }
    assert finding["anomaly_score"] == round(10 / 15, 2)
    meta = finding["metadata"]
    assert meta["elastic_alert_id"] == "abc123"
    assert meta["vendor"] == "wazuh"
    assert meta["wazuh_alert_id"] == "1790597838.2112422"
    assert meta["rule_id"] == "5712"
    assert meta["rule_level"] == 10
    assert meta["rule_groups"] == ["syslog", "sshd", "authentication_failures"]
    assert meta["mitre_tactics"] == ["Credential Access"]
    assert meta["mitre_techniques"] == ["Brute Force"]
    assert meta["agent_name"] == "web01"
    assert meta["index"] == "wazuh-alerts-4.x-2026.09.28"


@pytest.mark.asyncio
async def test_external_id_is_the_document_id_through_the_adapter():
    """The adapter strips the ``elastic-`` prefix, so the dedup key is the
    indexer's document id."""
    ingestion = _ingestion()
    ingestion._get_elastic_service().search = AsyncMock(
        return_value={"hits": {"total": {"value": 1}, "hits": [ALERT]}}
    )
    adapter = SIEMIngestionAdapter(
        name="elastic",
        integration_id="elastic-siem",
        default_interval=300,
        service_factory=lambda: ingestion,
        external_id_prefix="elastic",
    )
    with patch.object(adapter, "is_configured", return_value=True):
        result = await adapter.fetch(since=None, cursor={}, max_items=10)
    (finding,) = result.findings
    assert finding["external_id"] == "abc123"
    assert finding["finding_id"] == "elastic-abc123"
    assert finding["data_source"] == "elastic"


def test_transform_manager_syslog_and_windows_fields():
    alert = {
        "_id": "m1",
        "_source": {
            "agent": {"id": "000", "name": "wazuh-manager"},
            "predecoder": {"hostname": "fw01"},
            "data": {
                "srcuser": "mallory",
                "win": {
                    "eventdata": {"subjectUserName": "admin", "ipAddress": "10.1.2.3"},
                    "system": {"message": "An account failed to log on."},
                },
            },
            "rule": {"level": 5, "description": "Logon failure"},
        },
    }
    finding = _ingestion().transform_alert_to_finding(alert)
    entities = finding["entity_context"]
    assert entities["hostnames"] == ["wazuh-manager", "fw01"]
    assert entities["usernames"] == ["mallory", "admin"]
    assert entities["src_ips"] == ["10.1.2.3"]
    assert finding["description"] == "An account failed to log on."
    assert finding["severity"] == "low"


def test_transform_ignores_predecoder_host_for_remote_agents():
    alert = {
        "_id": "r1",
        "_source": {
            "agent": {"id": "001", "name": "web01"},
            "predecoder": {"hostname": "web01-alias"},
            "rule": {"level": 5},
        },
    }
    finding = _ingestion().transform_alert_to_finding(alert)
    assert finding["entity_context"]["hostnames"] == ["web01"]
    assert finding["title"] == "Wazuh Alert"
    assert finding["mitre_predictions"] == {}


def test_transform_scalar_mitre_id_and_missing_level_are_tolerated():
    alert = {
        "_id": "s1",
        "_source": {
            "rule": {"level": "junk", "description": "x", "mitre": {"id": "T1059"}},
        },
    }
    finding = _ingestion().transform_alert_to_finding(alert)
    assert finding["severity"] == "medium"
    assert finding["anomaly_score"] == 0.5
    assert finding["mitre_predictions"] == {"T1059": 0.9}


def test_elastic_security_alerts_still_take_the_kibana_path():
    """An ECS document with a named rule but no level is not a Wazuh alert."""
    alert = {
        "_id": "k1",
        "_source": {
            "kibana.alert.rule.name": "Suspicious PowerShell",
            "kibana.alert.severity": "high",
            "rule": {"name": "Suspicious PowerShell", "id": "r-1"},
            "host": {"name": "WS-01"},
        },
    }
    finding = _ingestion().transform_alert_to_finding(alert)
    assert finding["title"] == "Suspicious PowerShell"
    assert finding["severity"] == "high"
    assert finding["entity_context"]["hostnames"] == ["WS-01"]
    assert "vendor" not in finding["metadata"]
