/**
 * The scanners that need something to run: the generated app itself (DAST), its test suite, npm, and any external
 * security tools installed on this computer. The pipeline imports them from here.
 *
 * They are kept apart from the static scanners because they are the ones that can be skipped for honest reasons
 * (the app would not start, the packages are not installed, this computer is offline) — each returns a
 * ToolCoverage row that says so in plain language instead of reporting a silent pass.
 */
export { runDast, DAST_COVERS, hasCertificates } from './dast/index.js';
export type { DastOptions, DastDetails } from './dast/index.js';
export { formAuthBootstrap, startupTokenAuthBootstrap, CONTRACT_SEEDED_USERS } from './dast/auth.js';
export type { DastAuthBootstrap, AuthBootstrapContext, StartupTokenAuthOptions } from './dast/auth.js';
export { ALL_PROBES, probeById, probesForPhase } from './dast/probes/index.js';
export { startApp, AppStartError, generateAppEnv, resolveEntry, freePort } from './dast/harness.js';
export { buildProbeContext, runProbes, derivePaths, notAttemptedForPhase } from './dast/runner.js';
export { evidenceForResult, findingsForResult, evidenceRef } from './dast/findings.js';
export { CookieJar, HttpClient, extractCsrfToken, parseSetCookie, multipart, sendOverNodeHttp, collectResponse } from './dast/http.js';
export type { HttpResponse, RequestOptions, RawHttpResponse } from './dast/http.js';
export { totp, base32Encode, base32Decode, randomTotpSeed } from './dast/totp.js';
export type {
  AppInstance,
  EntityInfo,
  ProbeContext,
  ProbeGroup,
  ProbeModule,
  ProbeOutcome,
  ProbePhase,
  ProbeResult,
  RouteInfo,
  RoutesExport,
  SecurityEvent,
  SeededUser,
  Session,
} from './dast/types.js';
export { PROBE_GROUPS } from './dast/types.js';

export { runTests, TESTS_COVERS, parseTap, requirementIdOf, evidenceForTests, findingsForTests, findTestFiles, testPatterns } from './tests-runner/index.js';
export type { RunTestsOptions, TestsDetails, TestResult, TapSummary, TapParseResult } from './tests-runner/index.js';

export { runDeps, DEPS_COVERS } from './deps/index.js';
export type { RunDepsOptions, DepsDetails } from './deps/index.js';
export { parseLockfile, purlFor } from './deps/lockfile.js';
export type { Lockfile, LockedPackage } from './deps/lockfile.js';
export { runAudit, parseAuditJson, readAuditCache, writeAuditCache } from './deps/audit.js';
export type { Advisory, AuditReport, AuditOutcome } from './deps/audit.js';
export { collectLicenses, isCopyleft, summarizeLicenses } from './deps/licenses.js';
export type { LicenseEntry } from './deps/licenses.js';
export { generateSbom, buildFallbackSbom, cyclonedxCli } from './deps/sbom.js';
export type { Sbom, SbomResult } from './deps/sbom.js';

export { runExternal, detectTool, findOnPath, parseVersion, externalCoverageRows, EXTERNAL_TOOLS } from './external/index.js';
export type { ExternalDetails, ExternalToolResult, ExternalToolName, RunExternalOptions } from './external/index.js';
