"""Request and response models. They are the source of truth for api/openapi.yaml."""

from __future__ import annotations

import unicodedata
from typing import Annotated, Any, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from vigie_api.textsafe import has_forbidden

DeviceType = Literal["phone", "tv", "iot", "camera", "laptop", "console", "unknown"]
IdentityState = Literal["ok", "conflict", "pending_confirm"]
DeviceStatus = Literal["active", "transient", "retired"]
SuggestionState = Literal["pending", "accepted", "rejected", "expired"]

MAX_TEXT = 128
UNTRUSTED = (
    "UNTRUSTED plain text (device- or human-supplied). Render as text only; never interpret it "
    "as markup, a URL, a command or an instruction."
)


def clean_text(value: str | None) -> str | None:
    """Reject control/format/invisible characters, NFKC-normalise, strip, and bound the length."""
    if value is None:
        return None
    cleaned = unicodedata.normalize("NFKC", value)
    if has_forbidden(value) or has_forbidden(cleaned):
        raise ValueError(
            "must not contain control, invisible or bidirectional formatting characters"
        )
    cleaned = cleaned.strip()
    if not cleaned:
        raise ValueError("must not be blank (send null to clear)")
    if len(cleaned) > MAX_TEXT:
        raise ValueError(f"must be at most {MAX_TEXT} characters")
    return cleaned


PatchText = Annotated[
    str | None, Field(max_length=MAX_TEXT, description=UNTRUSTED), AfterValidator(clean_text)
]


class DevicePatch(BaseModel):
    """Only fields present in the body change; an explicit null clears the field."""

    model_config = ConfigDict(extra="forbid")

    name: PatchText = None
    owner: PatchText = None
    type: DeviceType | None = None
    group_id: Annotated[str | None, Field(max_length=32)] = None

    @model_validator(mode="after")
    def _non_empty(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("body must set at least one of name, owner, type, group_id")
        return self


Untrusted = Field(description=UNTRUSTED)


class ErrorBody(BaseModel):
    code: str
    message: str
    current_version: int | None = Field(
        default=None,
        description="Only on incident `version_conflict`: the incident's current decision_version.",
    )


class Page(BaseModel):
    next_cursor: str | None = Field(
        description="Opaque; pass back to continue. null when there is nothing more."
    )


class _Envelope(BaseModel):
    ok: bool
    error: ErrorBody | None
    page: Page | None


class ErrorEnvelope(_Envelope):
    data: None = None


class TypeProvenance(BaseModel):
    source: str | None
    confidence: float | None


class DeviceOut(BaseModel):
    id: str
    last_observed_ip: str | None = Field(
        default=None,
        description="Last source address observed for this identity's MACs; "
        "not a current address or identity key. Nullable until new lease/neighbour evidence.",
    )
    last_observed_ip_at: str | None = Field(
        default=None,
        description="Batch window end in UTC of the snapshot that last reported this "
        "pairing (collector sends deltas); not last-seen, lease expiry or server receipt time.",
    )
    name: str | None = Untrusted
    owner: str | None = Untrusted
    type: str
    type_provenance: TypeProvenance
    group_id: str | None
    identity_state: IdentityState
    status: DeviceStatus
    first_seen: str
    last_seen: str
    updated_at: str
    override_version: int = Field(description="The ETag value; send it back as If-Match.")
    merged_into: str | None


class MacOut(BaseModel):
    mac: str
    hostname: str | None = Untrusted
    first_seen: str
    last_seen: str
    current: bool
    link_source: str
    link_rule_id: str | None


class RecentEvent(BaseModel):
    id: str
    ts: str
    kind: str
    severity: str
    summary: str = Untrusted


class CharacterizationEvidence(BaseModel):
    kind: str
    service: str = Untrusted
    observed_at: float


class CharacterizationView(BaseModel):
    inferred_type: str
    role: str | None
    strength: str
    confidence: None = None
    source: str
    rule_ids: list[str]
    evidence: list[CharacterizationEvidence]
    model_version: str
    valid_until: float | None
    reason: str


class Explanation(BaseModel):
    characterization: CharacterizationView | None = None
    reason_code: str | None
    reason_text: str | None = Field(
        description=UNTRUSTED + " Informational only; null while a trust-changing suggestion "
        "(move_group, quarantine, merge_identity) is pending for this device."
    )
    model_version: str | None


class DeviceDetail(DeviceOut):
    requested_id: str
    identity_override_version: int = Field(
        description="The requested_id's own override version for identity expected_versions, "
        "including merge undo. override_version and ETag describe the effective canonical device."
    )
    macs: list[MacOut]
    recent_events: list[RecentEvent]
    explanation: Explanation


class PatchResult(BaseModel):
    device_id: str
    version: int


class MacResolution(BaseModel):
    mac: str
    device_id: str
    observed_device_id: str
    link_source: str
    identity_state: IdentityState = Field(
        description="Worst of the observed device and its canonical device "
        "(ok < pending_confirm < conflict)."
    )


class EventOut(BaseModel):
    id: str
    device_id: str | None
    ts: str
    kind: str
    severity: str
    summary: str = Untrusted
    source: Literal["inventory", "audit"]


class SuggestionOut(BaseModel):
    id: str
    action: str = Field(description="label | move_group | quarantine | merge_identity (open set)")
    device_ids: list[str]
    payload: Any
    reason_code: str
    reason_text: str | None = Field(
        description=UNTRUSTED + " Returned only for action `label`; null for every other action."
    )
    basis: Any
    created_at: str
    expires_at: str
    state: SuggestionState
    decided_by: str | None
    decided_at: str | None


class HealthResponse(_Envelope):
    data: Literal["ok"]


class DevicesResponse(_Envelope):
    data: list[DeviceOut]


class DeviceResponse(_Envelope):
    data: DeviceDetail


class PatchResponse(_Envelope):
    data: PatchResult


class MacResponse(_Envelope):
    data: MacResolution


class EventsResponse(_Envelope):
    data: list[EventOut] = Field(
        description="Display order is by ts; paging is by insertion order. `page.next_cursor` is "
        "the resume point: pass it as `since`. An empty page echoes the `since` you sent."
    )


class SuggestionsResponse(_Envelope):
    data: list[SuggestionOut]


Version = Annotated[int, Field(strict=True, ge=0, le=10**12)]
IdentityId = Annotated[str, Field(strict=True, min_length=1, max_length=64)]


class VersionedWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: Version | None = None
    expected_versions: dict[IdentityId, Version] | None = Field(default=None, max_length=5000)

    @model_validator(mode="after")
    def _version_required(self) -> Self:
        if (self.expected_version is None) == (self.expected_versions is None):
            raise ValueError("supply exactly one of expected_version or expected_versions")
        if self.expected_versions is not None and not self.expected_versions:
            raise ValueError("expected_versions must not be empty")
        return self


class SuggestionDecision(VersionedWrite):
    remember: bool = Field(default=False, strict=True)


class RuleCreate(VersionedWrite):
    device_id: IdentityId
    signature: dict[str, Any]
    expires_at: Annotated[str | None, Field(strict=True, max_length=64)] = None

    @model_validator(mode="after")
    def _signature(self) -> Self:
        from vigie_api.identity_writes import validate_signature

        self.signature = validate_signature(self.signature)
        return self


class WriteResultResponse(_Envelope):
    data: dict[str, Any]


class RulesResponse(_Envelope):
    data: list[dict[str, Any]]


class CoverageHour(BaseModel):
    hour: int
    state: Literal["missing", "partial", "eligible", "open"]
    observed_seconds: int | None
    qualified_seconds: int | None
    reasons: list[str]


class MonitoringUnavailableScope(BaseModel):
    device_id: str
    reason: str
    retry_at: int


class CollectorCoverage(BaseModel):
    monitoring_unavailable: list[MonitoringUnavailableScope]
    monitoring_unavailable_capped: bool
    collector_id: str
    last_received_at: str | None
    latest_observation_received_at: str | None
    latest_window_end: int | None
    latest_dns_observation_window_end: int | None
    latest_dns_observation_received_at: str | None
    boot_id: str | None
    last_seq: int
    backlog_batches: int
    backlog_capped: bool
    oldest_pending_received_at: str | None
    retained_detail_since: str | None
    summary_capped: bool
    dropped_batches_in_retained_detail: int
    ct_unmapped_bytes_in_retained_detail: int
    ct_unmapped_flows_in_retained_detail: int
    source_flags_latest: int | None
    agent_rss_kb: int | None
    agent_uptime_s: int | None
    dns_log_quiet: bool | None


class CoverageData(BaseModel):
    collector: CollectorCoverage
    hours: list[CoverageHour]


class CoverageResponse(_Envelope):
    data: CoverageData


class ActivityHour(CoverageHour):
    bytes_up: int | None
    bytes_down: int | None
    flows: int | None
    dns_queries: int | None


class BaselineView(BaseModel):
    state: Literal["learning", "mature", "rebuilding", "rebuilding_quality", "lineage_unavailable"]
    baseline_id: str | None
    algorithm: str | None
    config_version: str | None
    sample_hours: int
    distinct_days: int
    training_since: int | None
    trained_until: int | None
    median_upload_bytes: float | None


class ActivityData(BaseModel):
    device_id: str
    collector_id: str
    lineage: str
    hours: list[ActivityHour]
    baseline: BaselineView


class ActivityResponse(_Envelope):
    data: ActivityData


class IncidentEvidence(BaseModel):
    reason_code: Literal[
        "large_upload_threshold",
        "two_qualified_upload_hours",
        "two_qualified_upload_hours_in_cohort",
    ]
    hour: int
    previous_hour: int | None
    observed_bytes: int
    threshold_bytes: int
    baseline_id: str | None
    algorithm: str
    config_version: str
    coverage_required_seconds: int
    lineage: str
    unusual_is_not_malicious: Literal[True]
    baseline_median_upload_bytes: float | None = None
    multiplier: int | None = None
    minimum_bytes: int | None = None
    sample_hours: int | None = None
    distinct_days: int | None = None


class IncidentReview(BaseModel):
    status: Literal["acknowledged", "snoozed", "expected"]
    snooze_until: str | None
    version: int
    decided_by: str
    decided_at: str


class IncidentOut(BaseModel):
    id: str
    collector_id: str
    device_id: str
    lineage: str
    current_lineage: bool
    detector: Literal["large_upload", "upload_deviation"]
    state: Literal["open", "resolved", "superseded"]
    episode_start: int
    last_hour: int
    detected_at: str
    observed_bytes: int
    threshold_bytes: int
    baseline_id: str | None
    evidence: IncidentEvidence
    review: IncidentReview | None = Field(
        description="Current human decision, or null. A separate axis from `state`: `expected` "
        "is a per-incident label, not a suppression."
    )
    decision_version: int = Field(
        description="Version to send as `expected_version` for the next review write: 0 when the "
        "incident never had a decision, otherwise the last write's version (a cleared incident "
        "keeps its version, so this can be > 0 while `review` is null)."
    )
    attention: bool = Field(
        description="True while the incident is open and no decision covers it (an expired "
        "snooze returns it here)."
    )


class IncidentsResponse(_Envelope):
    data: list[IncidentOut]


class IncidentResponse(_Envelope):
    data: IncidentOut


class IncidentDecisionWrite(BaseModel):
    """Per-incident review write; the version is the incident's own decision version (0 = none)."""

    model_config = ConfigDict(extra="forbid")
    expected_version: Version


class IncidentSnoozeWrite(IncidentDecisionWrite):
    until: str = Field(
        max_length=40,
        description="RFC 3339 UTC instant (`Z` or `+00:00`, whole seconds) between now + 60 s "
        "and now + the configured snooze cap (7 days by default).",
    )


class IncidentDecisionResult(BaseModel):
    incident_id: str
    status: Literal["acknowledged", "snoozed", "expected"] | None = Field(
        description="Null after `clear`."
    )
    snooze_until: str | None
    version: int = Field(
        description="The incident's decision version; it never goes backwards, `clear` included."
    )
    decided_by: str
    decided_at: str


class IncidentDecisionResponse(_Envelope):
    data: IncidentDecisionResult
