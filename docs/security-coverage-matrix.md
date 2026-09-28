# Security Coverage Integration Matrix

This matrix is based on the analyzer, finding, validation, scanner, and pipeline
modules present in `m_hunter/` (not on filenames alone). A component existing in
the repository does not mean it is enabled by default or that a finding is
confirmed. Registry adapters make legacy `analyze(...)` objects executable via
`AnalysisContext → AnalysisResult`; semantic validation is a separate gate.

## Runtime contract

| Component | Runtime status |
|---|---|
| `AnalyzerRegistry` | Keeps `BaseAnalyzer` identity; adapts legacy objects with `analyze` using `LegacyAnalyzerAdapter`; `register_legacy(..., invoke=...)` supports explicit nonstandard mappings. |
| Analysis capabilities | Adapters report passive/active mode, authorization, request/response/context requirements. Repository analyzers are passive analyzers of supplied data; active requests remain the ApplicationService/ScopeManager boundary. |
| Unified Finding validation | `security_headers_baseline`, `http_cookie_security`, and `cache_control_security` reuse their existing indicator validators and metadata catalogs through `LegacyIndicatorValidator`; each eligible indicator becomes a separate `AnalysisValidation`, then the central converter creates `core.Finding`. |
| Other specialized validators | Most remain legacy pipeline contracts. They are not implicitly treated as unified validation and do not create findings through the AnalysisFindingPipeline unless explicitly adapted/configured. |
| Evidence/report | Validated findings receive EvidenceService records; reports read only sanitized evidence. The converter sanitizes Finding text and metadata, and evidence capture sanitizes the Finding evidence field before returning it. |
| `ScannerRegistry` | Still registers `BaseScanner` implementations. ApplicationService runs scanners only for explicitly active, authorized scans, checks scope, captures legacy scanner evidence, and keeps ExampleScanner behind explicit opt-in. Scanner findings are a legacy scanner path, not analyzer validation output. |
| Default CLI analyzers | Security headers, security-header baseline, cookie, cache-control, and metadata analysis are configured. Other vulnerability analyzers remain opt-in/configuration-driven. |

## Category inventory

“Adapter” means the analyzer can be registered through the automatic legacy
adapter; custom mandatory inputs are supplied through `ScanRequest.analyzer_options`
or an explicit `register_legacy` invocation. “Specialized” means a legacy
validator/pipeline or Finding catalog exists, but is not yet the generic unified
AnalysisValidation contract. End-to-end status refers to tested full-path
coverage in `tests/application/test_security_coverage_e2e.py`.

| Security area | Analysis modules found | Validation / Finding modules found | State and capability notes |
|---|---|---|---|
| XSS | `analyzers/xss.py`, `xss_finding.py` | `validation/xss.py`, `xss_pipeline.py` | Adapter available; input marker is context-required; specialized validation; request/response E2E tested. Passive analysis only. |
| SQL Injection | `analyzers/sqli.py`, `sqli_finding.py` | `validation/sqli.py`, `sqli_pipeline.py` | Adapter available; response analysis passive; specialized validation; no unified E2E confirmation. |
| SSRF | `analyzers/ssrf.py`, `ssrf_finding.py` | `validation/ssrf.py`, `ssrf_pipeline.py` | Adapter available; response indicators are passive; active validation must be separately authorized; specialized validation. |
| File Upload | `analyzers/file_upload.py`, `file_upload_finding.py` | `validation/file_upload.py`, `file_upload_pipeline.py` | Adapter available; requires supplied upload/request context; specialized validation. |
| CSRF | `analyzers/csrf.py`, `csrf_finding.py` | `validation/csrf.py`, `csrf_pipeline.py` | Adapter available; context-dependent analysis; specialized validation. |
| SSTI | `analyzers/ssti.py`, `ssti_finding.py` | `validation/ssti.py`, `ssti_pipeline.py` | Adapter available; response indicators passive; active confirmation remains opt-in; specialized validation. |
| XXE | `analyzers/xxe.py`, `xxe_finding.py` | `validation/xxe.py`, `xxe_pipeline.py` | Content adapter available; content analysis passive; specialized validation. |
| HTTP Request Smuggling | `analyzers/request_smuggling.py`, `request_smuggling_finding.py` | `validation/request_smuggling.py`, `request_smuggling_pipeline.py` | Adapter available; requires request/response context; active confirmation must be separately scoped; specialized validation. |
| Insecure Deserialization | `analyzers/deserialization.py`, `deserialization_finding.py` | `validation/deserialization.py`, `deserialization_pipeline.py` | Adapter available; request/body context required; specialized validation. |
| GraphQL | `analyzers/graphql.py`, `graphql_finding.py` | `validation/graphql.py`, `graphql_pipeline.py` | Adapter available; response/request context; active introspection/probing is not implicit; specialized validation. |
| API Security | `analyzers/api_security.py`, `api_security_finding.py` | `validation/api_security.py`, `api_security_pipeline.py` | Adapter available; request/response context; specialized validation. |
| OAuth | `analyzers/oauth.py`, `oauth_finding.py` | `validation/oauth.py`, `oauth_pipeline.py` | Adapter available; protocol/context input required; specialized validation. |
| SAML | `analyzers/saml.py`, `saml_finding.py` | `validation/saml.py`, `saml_pipeline.py` | Adapter available; assertion/context input required; specialized validation. |
| MFA | `analyzers/mfa.py`, `mfa_finding.py` | `validation/mfa.py`, `mfa_pipeline.py` | Adapter available; workflow/context input required; specialized validation. |
| Session Security | `analyzers/session.py`, `session_finding.py` | `validation/session.py`, `session_pipeline.py` | Adapter available; response/session context; cookie values are redacted in evidence/report. |
| Authentication | `analyzers/authentication.py`, `authentication_finding.py` | `validation/authorization.py` | Adapter available; workflow context required; authentication observations are not confirmed findings without configured validation. |
| JWT / Advanced JWT | `analyzers/jwt.py`, `jwt_finding.py` | `validation/jwt.py`, `jwt_pipeline.py` | Adapter available; supplied token/context required; evidence/report redaction applies; specialized validation. |
| Race Conditions | `analyzers/race_condition.py`, `race_condition_finding.py` | `validation/race_condition.py`, `race_condition_pipeline.py` | Adapter available; active concurrency is not implicit and requires scoped authorization; specialized validation. |
| HPP | `analyzers/hpp.py`, `hpp_finding.py` | `validation/hpp.py`, `hpp_pipeline.py` | Adapter available; request parameter context; active probes remain gated. |
| Open Redirect | `analyzers/open_redirect.py`, `open_redirect_finding.py` | `validation/open_redirect.py`, `open_redirect_pipeline.py` | Adapter available; response/request context; active validation remains gated. |
| Command Injection | `analyzers/command_injection.py`, `command_injection_finding.py` | `validation/command_injection.py`, `command_injection_pipeline.py` | Adapter available; response indicators passive; active validation remains gated. |
| LDAP Injection | `analyzers/ldap_injection.py`, `ldap_injection_finding.py` | `validation/ldap_injection.py`, `ldap_injection_pipeline.py` | Adapter available; request/response context; specialized validation. |
| CRLF / Header Injection | `analyzers/crlf_injection.py`, `crlf_injection_finding.py` | `validation/crlf_injection.py`, `crlf_injection_pipeline.py` | Adapter available; response/request context; active confirmation remains gated. |
| Host Header Injection | `analyzers/host_header_injection.py`, `host_header_injection_finding.py` | `validation/host_header_injection.py`, `host_header_injection_pipeline.py` | Adapter available; request context; active validation remains gated. |
| Cache Poisoning | `analyzers/cache_poisoning.py`, `cache_poisoning_finding.py` | `validation/cache_poisoning.py`, `cache_poisoning_pipeline.py` | Adapter available; request/response context; specialized validation; active variants remain gated. |
| Web Cache Deception | `analyzers/web_cache_deception.py`, `web_cache_deception_finding.py` | `validation/web_cache_deception.py`, `web_cache_deception_pipeline.py` | Adapter available; request/response context; specialized validation. |
| Web Cache Key Security | `analyzers/web_cache_key_security.py` | No matching unified validator/Finding catalog | `BaseAnalyzer`-compatible and runnable; informational unless an explicit validator is supplied; no Finding by default. |
| Prototype Pollution | `analyzers/prototype_pollution.py`, `prototype_pollution_finding.py` | `validation/prototype_pollution.py`, `prototype_pollution_pipeline.py` | Adapter available; response/input context; specialized validation. |
| NoSQL Injection | `analyzers/nosql_injection.py`, `nosql_injection_finding.py` | `validation/nosql_injection.py`, `nosql_injection_pipeline.py` | Adapter available; request/response context; specialized validation. |
| WebSocket Security | `analyzers/websocket_security.py`, `websocket_security_finding.py` | `validation/websocket_security.py`, `websocket_security_pipeline.py` | Adapter available; handshake/context required; active connection testing remains gated. |
| HTTP/2 Security | `analyzers/http2_security.py`, `http2_security_finding.py` | `validation/http2_security.py`, `http2_security_pipeline.py` | Adapter available; protocol metadata required; specialized validation. |
| HTTP/3 Security | `analyzers/http3_security.py`, `http3_security_finding.py` | `validation/http3_security.py`, `http3_security_pipeline.py` | Adapter available; protocol/TLS context required; specialized validation. |
| HTTP Method Security | `analyzers/http_method_security.py`, `http_method_security_finding.py` | `validation/http_method_security.py`, `http_method_security_pipeline.py` | Adapter available; response/method context; any active method probes must be explicitly authorized. |
| General HTTP / Metadata | `analyzers/http.py`, `metadata.py` | No matching security Finding validator | Extraction/normalization utilities; informational data, not vulnerability detectors. |
| LFI / RFI | `analyzers/file_inclusion.py`, `file_inclusion_finding.py` | `validation/file_inclusion.py`, `file_inclusion_pipeline.py` | Adapter available; request/response context; active confirmation remains gated. |
| Subdomain Takeover | `analyzers/subdomain_takeover.py`, `subdomain_takeover_finding.py` | `validation/subdomain_takeover.py`, `subdomain_takeover_pipeline.py` | Adapter available; recon/DNS context required; scope filtering precedes active follow-up. |
| IDOR / BOLA / Broken Access Control | `analyzers/idor.py`, `idor_finding.py`, `authorization.py`, `authorization_finding.py` | `validation/idor.py`, `idor_pipeline.py`, `validation/authorization.py` | Adapter available; comparative identity/request context required; active account testing requires authorization. |
| Clickjacking | `analyzers/clickjacking.py`, `clickjacking_finding.py` | `validation/clickjacking.py`, `clickjacking_pipeline.py` | Adapter available; passive response analysis; specialized validation. |
| CORS / Advanced CORS | `analyzers/cors.py`, `cors_finding.py`, `cors_advanced.py`, `cors_advanced_finding.py` | `validation/cors_advanced.py`, `cors_advanced_pipeline.py` | Adapter available; response/request context; advanced validation remains specialized. |
| CSP | `analyzers/csp_security.py`, `csp_security_finding.py` | `validation/csp_security.py`, `csp_security_pipeline.py` | Adapter available; passive response analysis; specialized validation. |
| Referrer-Policy | `analyzers/referrer_policy.py`, `referrer_policy_finding.py` | `validation/referrer_policy.py`, `referrer_policy_pipeline.py` | Adapter available; passive response analysis; specialized validation. |
| Permissions-Policy | `analyzers/permissions_policy.py`, `permissions_policy_finding.py` | `validation/permissions_policy.py`, `permissions_policy_pipeline.py` | Adapter available; passive response analysis; specialized validation. |
| COOP / COEP / CORP | `analyzers/coop.py`, `coep.py`, `corp.py` and corresponding `*_finding.py` | Matching `validation/coop.py`, `coep.py`, `corp.py` pipelines | Adapter available; passive response analysis; legacy specialized validators; COOP adapter path covered by end-to-end compatibility tests where configured. |
| Security Policy Reporting | `analyzers/security_reporting.py`, `security_reporting_finding.py` | `validation/security_reporting.py`, `security_reporting_pipeline.py` | Adapter available; passive policy/header analysis; specialized validation. |
| TLS/SSL | `analyzers/tls_security.py`, `tls_security_finding.py` | `validation/tls_security.py`, `tls_security_pipeline.py` | Adapter available; requires TLS observation/context; active handshake collection requires scoped execution. |
| Security Headers Baseline | `analyzers/security_headers_baseline.py`, `security_headers.py`, related finding modules | `validation/security_headers_baseline.py`; `pipelines/security_headers_baseline.py` | Unified legacy validator adapter; passive; Finding/Evidence/Report E2E tested. |
| HTTP Response Security | `analyzers/http_response_security.py`, `http_response_security` Finding module | matching validation and pipeline modules | Adapter available; passive response analysis; specialized validation. |
| HTTP Cookie Security | `analyzers/http_cookie_security.py`, `cookies.py`, `cookie_findings.py`, `set_cookie.py` | `validation/http_cookie_security.py`; matching Finding/pipeline modules | Unified adapter parses Set-Cookie attributes without exposing values; passive; Finding/Evidence E2E tested. |
| Cache-Control Security | `analyzers/cache_control_security.py` | `validation/cache_control_security.py`, `findings/cache_control_security.py`, matching pipeline | Unified legacy validator adapter; passive; requires explicit sensitive-content context for that classification; Finding/Evidence E2E tested. |

## Deliberate limits

The existing specialized per-vulnerability pipelines are retained as
pipeline-only compatibility paths. This stage does not claim every listed
category is a production-ready detector or automatically enable active probes.
Only the three mapped passive validators above are bridged to the unified
AnalysisValidation contract by default. Other categories need a category-specific
validator adapter and representative end-to-end evidence before they should be
classified as integrated.
