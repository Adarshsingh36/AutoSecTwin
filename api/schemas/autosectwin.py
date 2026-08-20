from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    name: str
    asset_type: str

    owner: str | None = None
    environment: str | None = None

    hostname: str | None = None
    ip_address: str | None = None
    operating_system: str | None = None
    software: str | None = None
    version: str | None = None

    exposure: float = Field(default=0.0, ge=0.0, le=1.0)
    criticality: float = Field(default=0.0, ge=0.0, le=1.0)

    description: str | None = None
    metadata_json: dict[str, Any] | None = None


class AssetResponse(AssetCreate):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}


class VulnerabilityCreate(BaseModel):
    asset_id: int | None = None
    cve_id: str
    title: str | None = None
    description: str | None = None
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: str = "UNKNOWN"
    exposure_score: float = Field(default=0.0, ge=0.0, le=1.0)
    asset_criticality: float = Field(default=0.0, ge=0.0, le=1.0)
    kev_listed: bool = False
    metadata_json: dict[str, Any] | None = None


class VulnerabilityResponse(VulnerabilityCreate):
    id: int
    exploitability_probability: float
    threat_intelligence_score: float
    created_at: datetime

    model_config = {"from_attributes": True}


class ExploitCreate(BaseModel):
    vulnerability_id: int
    source: str
    external_id: str | None = None
    module_name: str | None = None
    title: str
    description: str | None = None
    reliability_score: float = Field(default=0.0, ge=0.0, le=1.0)
    requires_auth: bool = False
    metadata_json: dict[str, Any] | None = None


class ExploitResponse(ExploitCreate):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}


class TwinCreate(BaseModel):
    asset_id: int | None = None
    name: str
    provider: str
    topology: dict[str, Any] | None = None
    endpoint: str | None = None
    notes: str | None = None


class TwinResponse(TwinCreate):
    id: int
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ValidationCreate(BaseModel):
    vulnerability_id: int
    exploit_id: int | None = None
    twin_id: int | None = None
    evidence: dict[str, Any] | None = None


class ValidationResponse(ValidationCreate):
    id: int
    status: str
    validation_score: float
    analysis: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ConfidenceRequest(BaseModel):
    vulnerability_id: int
    exploitability_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    validation_score: float | None = Field(default=None, ge=0.0, le=1.0)
    exposure_score: float | None = Field(default=None, ge=0.0, le=1.0)
    threat_intelligence_score: float | None = Field(default=None, ge=0.0, le=1.0)
    asset_criticality: float | None = Field(default=None, ge=0.0, le=1.0)
    classifier_uncertainty: float | None = Field(default=None, ge=0.0, le=1.0)
    twin_exploit_success_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    network_exposure: float | None = Field(default=None, ge=0.0, le=1.0)
    historical_ai_agreement: float | None = Field(default=None, ge=0.0, le=1.0)
    legacy_penalty: float = Field(default=0.0, ge=0.0, le=1.0)


class ConfidenceResponse(ConfidenceRequest):
    id: int
    fused_confidence: float
    weights: dict[str, float]
    created_at: datetime

    model_config = {"from_attributes": True}


class ConfidenceCalculateResponse(BaseModel):
    vulnerability_id: int | None = None
    confidence: float
    weights: dict[str, float]
    components: dict[str, float]
    explanation: str


class TrustCompareRequest(BaseModel):
    vulnerability_id: int | None = None
    prediction_score: float = Field(ge=0.0, le=1.0)
    validation_score: float = Field(ge=0.0, le=1.0)
    shap_explanation: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None


class TrustCompareResponse(BaseModel):
    agreement: bool
    hallucination: bool
    trust_score: float
    agreement_rate: float
    drift_score: float
    retraining_recommended: bool
    reason: str


class TrustStatisticsResponse(BaseModel):
    total_comparisons: int
    hallucinations: int
    agreement_rate: float


class DriftResponse(BaseModel):
    model_name: str
    drift_score: float
    baseline_agreement: float
    current_agreement: float
    retraining_recommended: bool
    created_at: datetime

    model_config = {"from_attributes": True, "protected_namespaces": ()}


class LegacyProfileRequest(BaseModel):
    asset_id: int | None = None
    vendor: str | None = None
    product: str | None = None
    service: str | None = None
    name: str | None = None
    version: str | None = None
    metadata: dict[str, Any] | None = None


class LegacyProfileResponse(BaseModel):
    id: int
    asset_id: int | None = None
    vendor: str
    product: str
    version: str | None = None
    fingerprint: str
    unsupported: bool
    eol: bool
    support_status: str
    legacy_penalty: float
    compensating_controls: list[str]
    route_to_specialist: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class RecommendationGenerateRequest(BaseModel):
    vulnerability_id: int
    recommendation_type: str = "patch"
    context: dict[str, Any] | None = None


class RecommendationResponse(BaseModel):
    id: int
    vulnerability_id: int
    recommendation_type: str
    title: str
    content: str
    provider: str
    metadata_json: dict[str, Any] | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ApprovalCreate(BaseModel):
    vulnerability_id: int
    requested_action: str
    requested_by: str | None = None
    context: dict[str, Any] | None = None


class ApprovalDecision(BaseModel):
    status: str
    decided_by: str
    decision_reason: str | None = None


class ApprovalResponse(ApprovalCreate):
    id: int
    status: str
    decided_by: str | None = None
    decision_reason: str | None = None
    created_at: datetime
    decided_at: datetime | None = None

    model_config = {"from_attributes": True}


class RemediationCreate(BaseModel):
    vulnerability_id: int
    recommendation_id: int | None = None
    action: str
    applied_by: str | None = None


class RemediationResponse(RemediationCreate):
    id: int
    status: str
    verification_score: float
    evidence: dict[str, Any] | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportCreate(BaseModel):
    vulnerability_id: int | None = None
    report_type: str
    title: str
    format: str = "json"
    metadata_json: dict[str, Any] | None = None


class ReportResponse(ReportCreate):
    id: int
    content: str
    created_at: datetime

    model_config = {"from_attributes": True}


class LearningEventCreate(BaseModel):
    event_type: str
    source: str
    label: str | None = None
    confidence_before: float | None = None
    confidence_after: float | None = None
    payload: dict[str, Any] | None = None
    notes: str | None = None


class LearningEventResponse(LearningEventCreate):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}

class TwinProvisionRequest(BaseModel):
    vulnerability_id: int
    ttl_seconds: int | None = None

class TwinProvisionResponse(BaseModel):
    id: int
    asset_id: int | None

    external_twin_id: int | None
    external_uuid: str | None

    name: str
    provider: str
    status: str

    environment: str | None
    ip_address: str | None
    network: str | None

    twin_image: str | None
    vm_name: str | None

    health: str | None
    legacy_flag: str | None

    endpoint: str | None

    destroy_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True} 

class TwinDestroyResponse(BaseModel):
    id: int
    status: str
    destroyed: bool
    message: str