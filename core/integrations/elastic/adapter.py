"""Elastic Security federation adapter."""

from __future__ import annotations

from datetime import timedelta

from core.federation.adapters._base import parse_alert_time
from core.federation.adapters._siem_base import SIEMIngestionAdapter
from core.federation.contract import FederationAdapter, register_adapter
from core.integrations.elastic.ingestion import ElasticIngestion


def _alert_time(alert):
    """Creation time of a raw Kibana detection hit, before transform."""
    return parse_alert_time((alert.get("_source") or {}).get("@timestamp"))


def _factory() -> FederationAdapter:
    def make_service():

        return ElasticIngestion()

    return SIEMIngestionAdapter(
        name="elastic",
        # Note: integration_id matches what core.config / settings UI use
        # ("elastic-siem"); the adapter name is shorter for the source_id PK.
        integration_id="elastic-siem",
        default_interval=300,  # SIEM cadence
        service_factory=make_service,
        external_id_prefix="elastic",
        alert_time=_alert_time,
        # Filebeat indexes an alert some seconds after its @timestamp, so each
        # tick reads up to a minute ago and the cursor stops there. Kibana
        # detection alerts have the same race in a milder form; they arrive a
        # minute later for it.
        settle_delay=timedelta(seconds=60),
    )


register_adapter("elastic", _factory)
