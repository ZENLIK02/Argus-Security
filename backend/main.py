from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI
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

if TEST_SITE_DIR.exists():
    app.mount("/test-site", StaticFiles(directory=str(TEST_SITE_DIR), html=True), name="test-site")

if WEBSITE_TESTONLY_DIR.exists():
    app.mount("/Website_testonly", StaticFiles(directory=str(WEBSITE_TESTONLY_DIR), html=True), name="website-testonly")


RiskLevel = Literal["SAFE", "SUSPICIOUS", "HIGH_RISK"]
ResultSource = Literal["LOCAL_MODEL"]


class DataLeakSignals(BaseModel):
    formCount: int = 0
    formActionUrls: list[str] = Field(default_factory=list)
    emptyFormActionCount: int = 0
    httpFormActionCount: int = 0
    crossDomainFormActionCount: int = 0
    passwordCrossDomainForm: bool = False
    otpOrPaymentCrossDomainForm: bool = False
    passwordHttpForm: bool = False
    otpOrPaymentHttpForm: bool = False
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


class NetworkSignals(BaseModel):
    totalRequests: int = 0
    thirdPartyRequests: int = 0
    thirdPartyScriptRequests: int = 0
    thirdPartyFrameRequests: int = 0
    thirdPartyXHRRequests: int = 0
    insecureHttpRequests: int = 0
    suspiciousRequestDomains: list[str] = Field(default_factory=list)
    requestsAfterFormSubmit: int = 0
    requestsAfterPasswordFocus: int = 0


class PageSignals(BaseModel):
    url: str
    domain: str
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


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "model": LOCAL_MODEL_NAME,
        "externalAi": False,
    }


@app.post("/analyze", response_model=AnalysisResult)
def analyze(signals: PageSignals) -> AnalysisResult:
    return build_local_model_result(signals)


def build_local_model_result(signals: PageSignals) -> AnalysisResult:
    score = clamp_score(signals.ruleBasedScore)

    if score == 0:
        score = estimate_score_from_metadata(signals)

    category = signals.ruleBasedCategory if signals.ruleBasedCategory and signals.ruleBasedCategory != "SAFE" else category_from_signals(signals)
    if category in {"GAMBLING", "ADULT_CONTENT"} and not has_critical_evidence(signals):
        category = "CONTENT_RISK"
        score = min(max(score, SUSPICIOUS_MIN_SCORE), 60)

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
    score = 0
    data_leak = signals.dataLeakSignals
    network = signals.networkSignals

    if signals.isSearchEnginePage and not has_critical_evidence(signals):
        return 0
    if signals.isTrustedDomain and not has_critical_evidence(signals):
        return 0
    if signals.hasPasswordField:
        score += 25
    if signals.hasOTP:
        score += 25
    if signals.hasLoginKeyword:
        score += 15
    if signals.apkLinks:
        score += 35
    if data_leak.crossDomainFormActionCount:
        score += 25
    if data_leak.passwordCrossDomainForm:
        score += 50
    if data_leak.otpOrPaymentCrossDomainForm:
        score += 60
    if data_leak.httpFormActionCount:
        score += 60
    if data_leak.passwordHttpForm or data_leak.otpOrPaymentHttpForm:
        score += 80
    if data_leak.thirdPartyApkLinks:
        score += 35
    if data_leak.httpApkLinks:
        score += 50
    if network.requestsAfterFormSubmit >= 3:
        score += 40
    if network.requestsAfterPasswordFocus >= 3:
        score += 35
    if signals.foundGamblingKeywords or signals.foundAdultKeywords:
        score = max(score, SUSPICIOUS_MIN_SCORE)

    return clamp_score(score)


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
    if data_leak.thirdPartyApkLinks or data_leak.httpApkLinks:
        reasons.append("APK link metadata points to third-party or insecure HTTP source.")
    if network.requestsAfterFormSubmit >= 3 or network.requestsAfterPasswordFocus >= 3:
        reasons.append("Third-party network activity increased after form or password interaction.")
    if category == "CONTENT_RISK":
        reasons.append("Adult/gambling category detected, capped below high risk without stronger behavior.")

    return reasons


def has_critical_evidence(signals: PageSignals) -> bool:
    data_leak = signals.dataLeakSignals
    network = signals.networkSignals
    has_real_apk_link = len(signals.apkLinks) > 0
    has_fake_store_apk_combo = has_real_apk_link and len(signals.foundStoreKeywords) > 0
    has_credential_combo = signals.hasPasswordField and (signals.hasOTP or signals.hasLoginKeyword)
    has_banking_credential_combo = bool(signals.foundBankingKeywords) and signals.hasPasswordField and signals.hasOTP
    has_cross_domain_sensitive_form = data_leak.passwordCrossDomainForm or data_leak.otpOrPaymentCrossDomainForm
    has_insecure_sensitive_form = data_leak.passwordHttpForm or data_leak.otpOrPaymentHttpForm
    has_insecure_form_context = data_leak.httpFormActionCount > 0 and (signals.hasPasswordField or signals.hasOTP or signals.hasLoginKeyword)
    has_apk_leak = bool(data_leak.thirdPartyApkLinks) or bool(data_leak.httpApkLinks)
    has_hidden_iframe_credential_combo = data_leak.hiddenIframeCount > 0 and (signals.hasPasswordField or signals.hasOTP)
    has_network_exfiltration_pattern = network.requestsAfterFormSubmit >= 3 or network.requestsAfterPasswordFocus >= 3

    return (
        not signals.isTrustedDomain
        and (
            has_fake_store_apk_combo
            or has_credential_combo
            or has_banking_credential_combo
            or has_cross_domain_sensitive_form
            or has_insecure_sensitive_form
            or has_insecure_form_context
            or has_apk_leak
            or has_hidden_iframe_credential_combo
            or has_network_exfiltration_pattern
        )
    )


def category_from_signals(signals: PageSignals) -> str:
    data_leak = signals.dataLeakSignals
    network = signals.networkSignals
    if data_leak.passwordHttpForm or data_leak.otpOrPaymentHttpForm or (
        data_leak.httpFormActionCount > 0 and (signals.hasPasswordField or signals.hasOTP or signals.hasLoginKeyword)
    ):
        return "INSECURE_FORM_SUBMISSION"
    if (
        data_leak.passwordCrossDomainForm
        or data_leak.otpOrPaymentCrossDomainForm
        or data_leak.crossDomainFormActionCount > 0
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
