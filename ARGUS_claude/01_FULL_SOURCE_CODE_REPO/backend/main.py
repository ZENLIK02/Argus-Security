from pathlib import Path
from datetime import datetime, timezone
import json
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


SUSPICIOUS_MIN_SCORE = 35
HIGH_RISK_MIN_SCORE = 70
LOCAL_WARNING_THRESHOLD = 35
LOCAL_MODEL_NAME = "PROJECT_ARGUS_LOCAL_MODEL"

app = FastAPI(title="Project Argus Local Demo Server", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
    ],
    allow_origin_regex=r"chrome-extension://.*",
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Argus-Source"],
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_SITE_DIR = PROJECT_ROOT / "test-site"
WEBSITE_TESTONLY_DIR = PROJECT_ROOT / "Website_testonly"
FEEDBACK_DIR = Path(__file__).resolve().parent / "data"
FALSE_POSITIVE_LOG = FEEDBACK_DIR / "false_positive_reports.jsonl"
BLOCKLIST_FILE = FEEDBACK_DIR / "phishing_blocklist.txt"
BLOCKLIST_DIR = FEEDBACK_DIR / "blocklists"


def _read_domains(path: Path, domains: set[str]) -> None:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            entry = line.strip().lower().rstrip(".")
            if entry and not entry.startswith("#"):
                domains.add(entry)


def load_blocklist() -> set[str]:
    """Load the local phishing/malware blocklist (one domain per line, # comments).

    Sources merged: the bundled seed `phishing_blocklist.txt` plus every `*.txt` in
    `data/blocklists/` (real feeds refreshed by scripts/refresh_blocklists.js —
    URLhaus / OpenPhish; PhishTank / Safe Browsing need API keys). Domains match
    exactly or by parent suffix, so listing example.com also flags login.example.com.
    """
    domains: set[str] = set()
    if BLOCKLIST_FILE.exists():
        _read_domains(BLOCKLIST_FILE, domains)
    if BLOCKLIST_DIR.exists():
        for feed_file in sorted(BLOCKLIST_DIR.glob("*.txt")):
            _read_domains(feed_file, domains)
    return domains


def blocklist_sources() -> list[str]:
    sources: list[str] = []
    if BLOCKLIST_FILE.exists():
        sources.append(BLOCKLIST_FILE.name)
    if BLOCKLIST_DIR.exists():
        sources.extend(sorted(f.name for f in BLOCKLIST_DIR.glob("*.txt")))
    return sources


BLOCKLIST_DOMAINS = load_blocklist()


def blocklist_match(domain: str) -> str | None:
    host = str(domain or "").strip().lower().rstrip(".")
    if not host:
        return None
    labels = host.split(".")
    # Check the full host and each parent domain (login.evil.com -> evil.com -> com).
    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index:])
        if candidate in BLOCKLIST_DOMAINS:
            return candidate
    return host if host in BLOCKLIST_DOMAINS else None

if TEST_SITE_DIR.exists():
    app.mount("/test-site", StaticFiles(directory=str(TEST_SITE_DIR), html=True), name="test-site")

if WEBSITE_TESTONLY_DIR.exists():
    app.mount("/Website_testonly", StaticFiles(directory=str(WEBSITE_TESTONLY_DIR), html=True), name="website-testonly")


RiskLevel = Literal["SAFE", "SUSPICIOUS", "HIGH_RISK"]
ResultSource = Literal["LOCAL_MODEL"]


class DataLeakSignals(BaseModel):
    formCount: int = 0
    sensitiveFormCount: int = 0
    formActionUrls: list[str] = Field(default_factory=list)
    emptyFormActionCount: int = 0
    httpFormActionCount: int = 0
    crossDomainFormActionCount: int = 0
    passwordCrossDomainForm: bool = False
    otpOrPaymentCrossDomainForm: bool = False
    passwordHttpForm: bool = False
    otpOrPaymentHttpForm: bool = False
    sameOriginSensitiveHttpForm: bool = False
    httpPageWithSensitiveForm: bool = False
    hiddenInputCount: int = 0
    hiddenIframeCount: int = 0
    externalScriptCount: int = 0
    thirdPartyIframeCount: int = 0
    redirectAwayLinkCount: int = 0
    thirdPartyApkLinks: list[str] = Field(default_factory=list)
    httpApkLinks: list[str] = Field(default_factory=list)
    fakeDownloadButtonNearEmbed: bool = False
    externalScriptDomains: list[str] = Field(default_factory=list)
    thirdPartyIframeDomains: list[str] = Field(default_factory=list)
    redirectAwayDomains: list[str] = Field(default_factory=list)
    inlineScriptCount: int = 0
    scriptNetworkSinkCount: int = 0
    dynamicEndpointAssemblyCount: int = 0
    externalUrlHints: list[str] = Field(default_factory=list)
    delayedRelayIndicator: bool = False
    popupMessageTrapIndicator: bool = False
    clipboardReadIndicator: bool = False
    fileMetadataHarvestIndicator: bool = False
    guardedNetworkToggleIndicator: bool = False
    preventedSubmitIndicator: bool = False
    localFormWithJsSinkIndicator: bool = False
    credentialLikeTextFieldCount: int = 0
    sensitiveTextareaCount: int = 0
    deceptiveLowFrictionContent: bool = False


class NetworkSignals(BaseModel):
    totalRequests: int = 0
    thirdPartyRequests: int = 0
    thirdPartyScriptRequests: int = 0
    thirdPartyFrameRequests: int = 0
    thirdPartyXHRRequests: int = 0
    insecureHttpRequests: int = 0
    writeRequests: int = 0
    thirdPartyWriteRequests: int = 0
    insecureWriteRequests: int = 0
    suspiciousRequestDomains: list[str] = Field(default_factory=list)
    requestsAfterFormSubmit: int = 0
    requestsAfterPasswordFocus: int = 0
    writeRequestsAfterFormSubmit: int = 0
    insecureWriteRequestsAfterFormSubmit: int = 0
    thirdPartyWriteRequestsAfterFormSubmit: int = 0
    sensitiveWriteRequestsAfterFormSubmit: int = 0
    insecureSensitiveWriteRequests: int = 0
    crossDomainSensitiveWriteRequests: int = 0
    beaconOrPingAfterSensitiveInput: int = 0
    queryBearingGetAfterSensitiveForm: int = 0


class PageSignals(BaseModel):
    url: str
    domain: str
    pageProtocol: str = ""
    isTrustedDomain: bool = False
    isSearchEnginePage: bool = False
    hasPasswordField: bool = False
    hasOTP: bool = False
    hasLoginKeyword: bool = False
    apkLinks: list[dict[str, Any]] = Field(default_factory=list)
    foundStoreKeywords: list[str] = Field(default_factory=list)
    suspiciousDomainSignals: list[str] = Field(default_factory=list)
    contentRiskSignals: list[str] = Field(default_factory=list)
    foundGamblingKeywords: list[str] = Field(default_factory=list)
    foundAdultKeywords: list[str] = Field(default_factory=list)
    foundBankingKeywords: list[str] = Field(default_factory=list)
    foundInvestmentKeywords: list[str] = Field(default_factory=list)
    foundTechSupportKeywords: list[str] = Field(default_factory=list)
    foundPopupAbuseKeywords: list[str] = Field(default_factory=list)
    foundFakeShoppingKeywords: list[str] = Field(default_factory=list)
    foundPrizeKeywords: list[str] = Field(default_factory=list)
    foundPiratedKeywords: list[str] = Field(default_factory=list)
    hasAdHeavySignal: bool = False
    adHeavySignals: list[str] = Field(default_factory=list)
    foundAdKeywords: list[str] = Field(default_factory=list)
    largeImageCount: int = 0
    linkedLargeImageCount: int = 0
    fixedOrStickyElementCount: int = 0
    iframeCount: int = 0
    externalLinkCount: int = 0
    dataLeakSignals: DataLeakSignals = Field(default_factory=DataLeakSignals)
    networkSignals: NetworkSignals = Field(default_factory=NetworkSignals)
    ruleBasedScore: float = 0
    ruleBasedLevel: str = "SAFE"
    ruleBasedCategory: str = "SAFE"
    ruleBasedReasons: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    riskScore: int = Field(ge=0, le=100)
    level: RiskLevel
    category: str
    reasons: list[str]
    shouldWarn: bool
    source: ResultSource = "LOCAL_MODEL"


class FalsePositiveReport(BaseModel):
    reportId: str = Field(min_length=8, max_length=80)
    domain: str = Field(max_length=180)
    score: int = Field(ge=0, le=100)
    level: str = Field(max_length=40)
    category: str = Field(max_length=80)
    reasons: list[str] = Field(default_factory=list, max_length=8)
    timestamp: str
    decisionTier: str = Field(default="UNKNOWN", max_length=60)
    policyVersion: str = Field(default="unknown", max_length=40)
    source: str = Field(default="LOCAL_MODEL", max_length=60)
    popularDomainContext: dict[str, Any] = Field(default_factory=dict)
    privacy: str = Field(default="", max_length=240)
    delivery: dict[str, Any] = Field(default_factory=dict)
    reportSchemaVersion: str = "2"
    userLabel: str = "FALSE_POSITIVE_UNREVIEWED"
    scoreBeforePolicy: int = 0
    scoreAfterPolicy: int = 0
    finalStatus: str = "UNKNOWN"
    evidenceIds: list[str] = Field(default_factory=list)
    evidenceGroups: list[str] = Field(default_factory=list)
    modelScore: int = 0
    modelOnly: bool = False
    warningAllowed: bool = False
    overlayAllowed: bool = False
    scanPhase: str = "UNKNOWN"
    navigationId: str = "unknown"
    frameId: int = 0
    featureVector: dict[str, Any] = Field(default_factory=dict)
    destinationRoles: list[str] = Field(default_factory=list)
    interactionTimeline: list[dict[str, Any]] = Field(default_factory=list)
    shadowComparison: dict[str, Any] | None = None
    reviewRequired: bool = True
    poisoningRiskNote: str = "User labels must be reviewed before retraining."


class ReputationRequest(BaseModel):
    # Canonical field is `host`; `domain` is accepted as a backward-compatible alias.
    # Only a hostname (metadata) is ever accepted — never a URL, path, query, or body.
    host: str | None = Field(default=None, max_length=253)
    domain: str | None = Field(default=None, max_length=253)

    def hostname(self) -> str:
        return str(self.host or self.domain or "").strip().lower().rstrip(".")


def build_reputation_result(host: str) -> dict[str, Any]:
    matched = blocklist_match(host)
    listed = matched is not None
    return {
        "ok": True,
        "host": host,
        "domain": host,  # backward-compatible echo
        "listed": listed,
        "verdict": "malicious" if listed else "unknown",
        "source": "LOCAL_BLOCKLIST" if listed else "NONE",
        "matchedDomain": matched or "",
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "model": LOCAL_MODEL_NAME,
        "externalAi": False,
        "blocklistDomains": len(BLOCKLIST_DOMAINS),
        "blocklistSources": blocklist_sources(),
    }


def _reload() -> dict[str, Any]:
    global BLOCKLIST_DOMAINS
    BLOCKLIST_DOMAINS = load_blocklist()
    return {"ok": True, "blocklistDomains": len(BLOCKLIST_DOMAINS), "blocklistSources": blocklist_sources()}


@app.post("/v1/reputation/reload")
@app.post("/reputation/reload")
def reload_blocklist() -> dict[str, Any]:
    """Reload the blocklist from disk after refreshing feeds — no server restart."""
    return _reload()


@app.post("/v1/reputation/check")
@app.post("/reputation")
def reputation(request: ReputationRequest) -> dict[str, Any]:
    """Domain reputation lookup (P1). Canonical route: POST /v1/reputation/check;
    /reputation is a backward-compatible alias. Only the hostname (metadata) is
    received — no URL, path, query, cookies, or page content. Returns whether the
    host is on the local blocklist. Later this proxies Safe Browsing / feed lookups
    behind the same shape.
    """
    return build_reputation_result(request.hostname())


@app.post("/analyze", response_model=AnalysisResult)
def analyze(signals: PageSignals) -> AnalysisResult:
    return build_local_model_result(signals)


@app.post("/demo-collect")
async def demo_collect(request: Request) -> dict[str, Any]:
    body = await request.body()
    return {
        "ok": True,
        "receivedBytes": len(body),
        "stored": False,
        "message": "Dummy plaintext demo payload received and discarded.",
    }


@app.post("/feedback/false-positive")
def collect_false_positive(report: FalsePositiveReport) -> dict[str, Any]:
    FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
    record = report.model_dump() if hasattr(report, "model_dump") else report.dict()
    record["receivedAt"] = datetime.now(timezone.utc).isoformat()
    record.pop("delivery", None)
    with FALSE_POSITIVE_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n")
    return {"ok": True, "reportId": report.reportId, "stored": True}


@app.get("/feedback/stats")
def feedback_stats() -> dict[str, Any]:
    count = 0
    if FALSE_POSITIVE_LOG.exists():
        with FALSE_POSITIVE_LOG.open("r", encoding="utf-8") as handle:
            count = sum(1 for line in handle if line.strip())
    return {"ok": True, "falsePositiveReports": count, "path": str(FALSE_POSITIVE_LOG)}


def build_local_model_result(signals: PageSignals) -> AnalysisResult:
    score = clamp_score(signals.ruleBasedScore)

    if score == 0:
        score = estimate_score_from_metadata(signals)

    category = signals.ruleBasedCategory if signals.ruleBasedCategory and signals.ruleBasedCategory != "SAFE" else category_from_signals(signals)
    if category in {"GAMBLING", "ADULT_CONTENT", "CONTENT_RISK", "MALVERTISING"} and not has_critical_evidence(signals):
        category = "SAFE"
        score = min(score, 12)

    reasons = signals.ruleBasedReasons or local_reasons(signals, category)

    return AnalysisResult(
        riskScore=score,
        level=level_from_score(score),
        category=category or "SAFE",
        reasons=dedupe(reasons) or ["Project Argus local model found no concrete high-risk indicators."],
        shouldWarn=score >= LOCAL_WARNING_THRESHOLD,
        source="LOCAL_MODEL",
    )


def estimate_score_from_metadata(signals: PageSignals) -> int:
    data_leak = signals.dataLeakSignals
    network = signals.networkSignals

    if signals.isSearchEnginePage and not has_critical_evidence(signals):
        return 0
    if signals.isTrustedDomain and not has_critical_evidence(signals):
        return 0

    if network.insecureSensitiveWriteRequests:
        return 92
    if network.crossDomainSensitiveWriteRequests:
        return 84
    if network.beaconOrPingAfterSensitiveInput or network.queryBearingGetAfterSensitiveForm:
        return 76
    if data_leak.passwordHttpForm or data_leak.otpOrPaymentHttpForm or data_leak.sameOriginSensitiveHttpForm or data_leak.httpPageWithSensitiveForm:
        return 88
    if data_leak.passwordCrossDomainForm or data_leak.otpOrPaymentCrossDomainForm or (
        data_leak.sensitiveFormCount and data_leak.crossDomainFormActionCount
    ):
        return 80
    if network.insecureWriteRequestsAfterFormSubmit:
        return 40

    score = 0
    score += 4 if signals.hasPasswordField else 0
    score += 4 if signals.hasOTP else 0
    score += 2 if signals.hasLoginKeyword else 0
    score += 14 if signals.apkLinks else 0
    score += 10 if data_leak.httpFormActionCount or data_leak.crossDomainFormActionCount else 0
    score += 20 if data_leak.scriptNetworkSinkCount and data_leak.externalUrlHints else 0
    score += 18 if data_leak.dynamicEndpointAssemblyCount and data_leak.scriptNetworkSinkCount else 0
    score += 15 if data_leak.popupMessageTrapIndicator and data_leak.scriptNetworkSinkCount else 0
    score += 4 if data_leak.clipboardReadIndicator or data_leak.fileMetadataHarvestIndicator else 0
    score += 6 if signals.hasAdHeavySignal else 0
    score += 3 if signals.foundGamblingKeywords or signals.foundAdultKeywords else 0
    return min(clamp_score(score), 60)


def local_reasons(signals: PageSignals, category: str) -> list[str]:
    reasons: list[str] = []
    data_leak = signals.dataLeakSignals
    network = signals.networkSignals

    if signals.isSearchEnginePage:
        reasons.append("Official search-result page without concrete danger signals.")
    if signals.isTrustedDomain:
        reasons.append("Trusted domain without concrete high-risk behavior.")
    if signals.hasPasswordField:
        reasons.append("Password field metadata detected.")
    if signals.hasOTP:
        reasons.append("OTP or verification-code metadata detected.")
    if signals.apkLinks:
        reasons.append("Direct APK link metadata detected.")
    if data_leak.passwordCrossDomainForm or data_leak.otpOrPaymentCrossDomainForm:
        reasons.append("Sensitive form metadata may submit to a different domain.")
    if data_leak.passwordHttpForm or data_leak.otpOrPaymentHttpForm:
        reasons.append("Sensitive form metadata may submit over insecure HTTP.")
    if data_leak.sameOriginSensitiveHttpForm or data_leak.httpPageWithSensitiveForm:
        reasons.append("A sensitive form can submit over an unencrypted HTTP page.")
    if data_leak.thirdPartyApkLinks or data_leak.httpApkLinks:
        reasons.append("APK link metadata points to third-party or insecure HTTP source.")
    if data_leak.credentialLikeTextFieldCount and data_leak.localFormWithJsSinkIndicator:
        reasons.append("Credential-like fields are handled by local-looking JavaScript network logic.")
    if data_leak.dynamicEndpointAssemblyCount and data_leak.scriptNetworkSinkCount:
        reasons.append("Script appears to assemble an endpoint dynamically before sending metadata.")
    if data_leak.popupMessageTrapIndicator and data_leak.scriptNetworkSinkCount:
        reasons.append("Popup consent flow can pass messages into network-send logic.")
    if data_leak.clipboardReadIndicator or data_leak.fileMetadataHarvestIndicator:
        reasons.append("Page can inspect clipboard or uploaded-file metadata.")
    if network.requestsAfterFormSubmit >= 3 or network.requestsAfterPasswordFocus >= 3:
        reasons.append("Third-party network activity increased after form or password interaction.")
    if network.insecureSensitiveWriteRequests:
        reasons.append("An unencrypted write request followed a sensitive form submission.")
    if network.crossDomainSensitiveWriteRequests:
        reasons.append("A cross-domain write request followed a sensitive form submission.")
    if network.beaconOrPingAfterSensitiveInput or network.queryBearingGetAfterSensitiveForm:
        reasons.append("Beacon-like network activity followed sensitive input interaction.")
    if category == "CONTENT_RISK":
        reasons.append("Adult/gambling category detected with minimal score impact and no stronger behavior.")

    return reasons


def has_critical_evidence(signals: PageSignals) -> bool:
    data_leak = signals.dataLeakSignals
    network = signals.networkSignals
    return (
        network.insecureSensitiveWriteRequests > 0
        or network.crossDomainSensitiveWriteRequests > 0
        or network.beaconOrPingAfterSensitiveInput > 0
        or network.queryBearingGetAfterSensitiveForm > 0
        or data_leak.passwordCrossDomainForm
        or data_leak.otpOrPaymentCrossDomainForm
        or (data_leak.sensitiveFormCount > 0 and data_leak.crossDomainFormActionCount > 0)
        or data_leak.passwordHttpForm
        or data_leak.otpOrPaymentHttpForm
        or data_leak.sameOriginSensitiveHttpForm
        or data_leak.httpPageWithSensitiveForm
    )


def category_from_signals(signals: PageSignals) -> str:
    data_leak = signals.dataLeakSignals
    network = signals.networkSignals
    if network.insecureSensitiveWriteRequests or data_leak.passwordHttpForm or data_leak.otpOrPaymentHttpForm or data_leak.sameOriginSensitiveHttpForm or data_leak.httpPageWithSensitiveForm:
        return "INSECURE_FORM_SUBMISSION"
    if (
        network.crossDomainSensitiveWriteRequests
        or network.beaconOrPingAfterSensitiveInput
        or network.queryBearingGetAfterSensitiveForm
        or data_leak.passwordCrossDomainForm
        or data_leak.otpOrPaymentCrossDomainForm
        or (data_leak.sensitiveFormCount > 0 and data_leak.crossDomainFormActionCount > 0)
        or (data_leak.credentialLikeTextFieldCount > 0 and data_leak.localFormWithJsSinkIndicator)
        or (data_leak.scriptNetworkSinkCount > 0 and data_leak.dynamicEndpointAssemblyCount > 0)
        or (data_leak.popupMessageTrapIndicator and data_leak.scriptNetworkSinkCount > 0)
        or network.requestsAfterFormSubmit >= 3
        or network.requestsAfterPasswordFocus >= 3
    ):
        return "DATA_EXFILTRATION"
    if signals.apkLinks and signals.foundStoreKeywords:
        return "FAKE_APP_STORE"
    if signals.apkLinks:
        return "MALICIOUS_APK"
    if signals.foundBankingKeywords and (signals.hasPasswordField or signals.hasOTP):
        return "FAKE_BANKING"
    if signals.hasPasswordField or signals.hasOTP:
        return "PHISHING_LOGIN"
    if signals.foundGamblingKeywords or signals.foundAdultKeywords:
        return "CONTENT_RISK"
    if signals.hasAdHeavySignal or signals.foundPopupAbuseKeywords:
        return "MALVERTISING"
    return signals.ruleBasedCategory or "SAFE"


def level_from_score(score: int | float) -> RiskLevel:
    if score >= HIGH_RISK_MIN_SCORE:
        return "HIGH_RISK"
    if score >= SUSPICIOUS_MIN_SCORE:
        return "SUSPICIOUS"
    return "SAFE"


def clamp_score(score: int | float) -> int:
    return max(0, min(100, round(float(score or 0))))


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output
