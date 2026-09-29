"""Elastic ingestion without Kibana reads a Wazuh indexer's alert index.

A Wazuh indexer is OpenSearch with no Kibana: its alerts are documents in
``wazuh-alerts-4.x-*``. With the Kibana URL blank, ``ElasticIngestion`` polls
the configured index pattern for alerts at or above a rule level and maps the
Wazuh schema (``rule.level``, ``rule.description``, ``rule.mitre.id``,
``agent.name``, ``data.*``) onto a finding.
"""

import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from core.federation.adapters._base import cursor_at, parse_cursor_since
from core.federation.adapters._siem_base import SIEMIngestionAdapter
from core.integrations.elastic import ingestion as elastic_ingestion
from core.integrations.elastic.ingestion import (
    DEFAULT_MIN_RULE_LEVEL,
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
# The settle delay the Elastic federation adapter is built with.
SETTLE = timedelta(seconds=60)

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
    # The service reads exactly the window it is given; with no end_time it
    # has no upper bound. The indexing delay is the adapter's, not the
    # service's (see the adapter tests below).
    assert _range(body, "@timestamp") == {"gte": start.isoformat() + "Z"}
    await ingestion._get_elastic_service().close()


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
    await ingestion._get_elastic_service().close()


@pytest.mark.asyncio
async def test_the_service_keeps_no_window_state():
    """Two fetches with the same arguments send the same query: where the
    next window starts is the persisted federation cursor, nothing else."""
    ingestion = _ingestion()
    svc = ingestion._get_elastic_service()
    svc.search = AsyncMock(return_value={"hits": {"hits": [_hit("a", "x")]}})
    start, end = NOW - timedelta(minutes=5), NOW - timedelta(minutes=1)
    await ingestion.fetch_alerts(start_time=start, end_time=end, limit=1)
    await ingestion.fetch_alerts(start_time=start, end_time=end, limit=1)
    first, second = svc.search.await_args_list
    assert first.kwargs == second.kwargs


# -- through the Elastic federation adapter --------------------------------


def _hit(ident: str, stamp: str) -> dict:
    return {
        "_index": "wazuh-alerts-4.x-2026.09.28",
        "_id": ident,
        "_source": {"@timestamp": stamp, "rule": {"level": 7, "description": ident}},
    }


def _stamp(when: datetime) -> str:
    return when.isoformat(timespec="milliseconds") + "Z"


class _Indexer:
    """A fake indexer that honours ``gte``, ``lte``, ``size`` and the ascending
    sort like a real one, and only returns a document once it is indexed:
    ``indexed_at`` lets a test stamp an alert before the moment it becomes
    searchable, as Filebeat does."""

    def __init__(self, clock):
        self.clock = clock
        self.docs: list = []  # (hit, indexed_at)
        self.windows: list = []

    def add(self, ident: str, when: datetime, indexed_at: datetime = None) -> None:
        self.docs.append((_hit(ident, _stamp(when)), indexed_at or when))

    def __call__(self, request):
        body = json.loads(request.content)
        window = _range(body, "@timestamp")
        self.windows.append(window)
        gte = datetime.fromisoformat(window["gte"][:-1])
        lte = datetime.fromisoformat(window["lte"][:-1]) if "lte" in window else None
        now = self.clock()
        found = []
        for hit, indexed_at in self.docs:
            when = datetime.fromisoformat(hit["_source"]["@timestamp"][:-1])
            if indexed_at > now or when < gte or (lte is not None and when > lte):
                continue
            found.append((when, hit))
        found.sort(key=lambda pair: pair[0])
        hits = [hit for _, hit in found[: body["size"]]]
        return httpx.Response(200, json={"hits": {"hits": hits}})


class _Clock:
    def __init__(self, now: datetime):
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def _elastic_adapter(monkeypatch, clock: _Clock):
    """The real Elastic adapter factory, over an index-mode ingestion service.

    A new adapter per call, so a test can show that nothing but the persisted
    cursor carries over between ticks, as across a daemon restart."""
    from core.integrations.elastic import adapter as elastic_adapter

    monkeypatch.setattr("core.federation.adapters._siem_base.utcnow", clock)
    monkeypatch.setattr(elastic_adapter, "ElasticIngestion", lambda: _ingestion())
    adapter = elastic_adapter._factory()
    monkeypatch.setattr(adapter, "is_configured", lambda: True)
    return adapter


async def _tick(monkeypatch, clock, cursor, max_items=10):
    adapter = _elastic_adapter(monkeypatch, clock)
    result = await adapter.fetch(since=None, cursor=cursor, max_items=max_items)
    await adapter._get_service()._get_elastic_service().close()
    return result


@respx.mock
@pytest.mark.asyncio
async def test_a_short_batch_persists_now_minus_the_delay(monkeypatch):
    clock = _Clock(NOW)
    indexer = _Indexer(clock)
    indexer.add("a", NOW - timedelta(minutes=3))
    respx.post(SEARCH).mock(side_effect=indexer)
    start = NOW - timedelta(minutes=5)

    result = await _tick(monkeypatch, clock, cursor_at(start))

    assert [f["external_id"] for f in result.findings] == ["a"]
    assert indexer.windows[0] == {
        "gte": start.isoformat() + "Z",
        "lte": (NOW - SETTLE).isoformat() + "Z",
    }
    assert parse_cursor_since(result.cursor) == NOW - SETTLE


@respx.mock
@pytest.mark.asyncio
async def test_an_alert_indexed_after_its_timestamp_is_read_next_tick(monkeypatch):
    """Stamped 10 s before the poll, searchable only 5 s after it. Without the
    delay the cursor would move to the poll time and this alert would never be
    read. A fresh adapter per tick: the state is only the persisted cursor."""
    clock = _Clock(NOW)
    indexer = _Indexer(clock)
    indexer.add(
        "late", NOW - timedelta(seconds=10), indexed_at=NOW + timedelta(seconds=5)
    )
    respx.post(SEARCH).mock(side_effect=indexer)

    first = await _tick(monkeypatch, clock, cursor_at(NOW - timedelta(minutes=5)))
    assert first.findings == []

    clock.now = NOW + timedelta(minutes=5)
    second = await _tick(monkeypatch, clock, first.cursor)

    assert [f["external_id"] for f in second.findings] == ["late"]
    assert indexer.windows[1]["gte"] == (NOW - SETTLE).isoformat() + "Z"


@respx.mock
@pytest.mark.asyncio
async def test_a_full_batch_drains_oldest_first_without_losing_alerts(monkeypatch):
    """Seven alerts, max_items 3. Each full batch stops the cursor at its
    newest alert; the boundary alert is re-read and left to the runner's
    dedup; the last short batch moves the cursor to now minus the delay."""
    clock = _Clock(NOW)
    indexer = _Indexer(clock)
    for i in range(7):
        indexer.add(f"a{i}", NOW - timedelta(minutes=10 - i))
    respx.post(SEARCH).mock(side_effect=indexer)

    cursor = cursor_at(NOW - timedelta(minutes=11))
    seen, cursors = [], []
    for _ in range(6):
        result = await _tick(monkeypatch, clock, cursor, max_items=3)
        seen.extend(f["external_id"] for f in result.findings)
        cursor = result.cursor
        cursors.append(parse_cursor_since(cursor))
        if len(result.findings) < 3:
            break

    assert sorted(set(seen)) == [f"a{i}" for i in range(7)]
    # Oldest first, and each batch starts at the previous batch's newest alert.
    # The third batch is full too, so a fourth tick re-reads a6 and, short,
    # moves the cursor to now minus the delay.
    assert seen == ["a0", "a1", "a2", "a2", "a3", "a4", "a4", "a5", "a6", "a6"]
    assert cursors == [
        NOW - timedelta(minutes=8),
        NOW - timedelta(minutes=6),
        NOW - timedelta(minutes=4),
        NOW - SETTLE,
    ]


@respx.mock
@pytest.mark.asyncio
async def test_a_cursor_inside_the_settle_window_reads_nothing(monkeypatch):
    """A cursor stored as the wall clock by an earlier release is newer than
    now minus the delay: the tick has nothing settled to read, and the cursor
    must not move backwards or forwards."""
    clock = _Clock(NOW)
    indexer = _Indexer(clock)
    route = respx.post(SEARCH).mock(side_effect=indexer)
    stored = NOW - timedelta(seconds=20)

    result = await _tick(monkeypatch, clock, cursor_at(stored))

    assert result.findings == []
    assert not route.called
    assert parse_cursor_since(result.cursor) == stored


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
