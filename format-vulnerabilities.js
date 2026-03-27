// format-vulnerabilities.js
// Dynatrace Workflow JavaScript Action
// Transforms raw vulnerability data from fetch-vulnerabilities.js
// into the Vulnerability Finding Events format per the Semantic Dictionary.
// Reference: https://docs.dynatrace.com/docs/semantic-dictionary/model/security-events#vulnerability-finding-events
// Findings app deduplication uses: object.id + vulnerability.id + component.name + component.version + product.name + product.vendor
// Findings app display requires: dt.security.risk.level, dt.security.risk.score, object.*, component.*

import { result } from "@dynatrace-sdk/automation-utils";

// Native UUID generator (no libraries)
function generateUUID() {
  const hex = (n) =>
    Array.from(crypto.getRandomValues(new Uint8Array(n)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  return `${hex(4)}-${hex(2)}-${hex(2)}-${hex(2)}-${hex(6)}`;
}

// Map risk level to a normalized 0-10 score for dt.security.risk.score
// following the same mapping as the Qualys integration
function riskLevelToNormalizedScore(riskLevel, riskScore) {
  if (typeof riskScore === "number" && riskScore > 0) return riskScore;
  switch ((riskLevel || "").toUpperCase()) {
    case "CRITICAL": return 9.5;
    case "HIGH":     return 7.5;
    case "MEDIUM":   return 5.0;
    case "LOW":      return 2.5;
    case "NONE":     return 0.0;
    default:         return null;
  }
}

// Normalize risk level to the allowed enum values for dt.security.risk.level
function normalizeRiskLevel(riskLevel) {
  const level = (riskLevel || "").toUpperCase();
  const allowed = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "NOT_AVAILABLE"];
  return allowed.includes(level) ? level : "NOT_AVAILABLE";
}

export default async function () {
  const fetchResult = await result("fetch-vulnerabilities");
  const rawVulnerabilities = fetchResult?.vulnerabilities || [];

  if (rawVulnerabilities.length === 0) {
    console.log("No vulnerabilities to format.");
    return { findings: [], batches: [], count: 0 };
  }

  const now = Date.now();
  // Timestamp in nanoseconds as required by the Semantic Dictionary
  const nowNanos = BigInt(now) * 1000000n;
  const scanId = generateUUID();
  const scanTimeISO = new Date(now).toISOString();
  const findings = [];

  for (const vuln of rawVulnerabilities) {
    const eventId = generateUUID();
    const findingId = generateUUID();

    const componentName =
      vuln.component?.displayName || vuln.packageName || "";
    const componentVersion = vuln.component?.shortName || "";

    const remediationStatus = vuln.remediation?.available
      ? "AVAILABLE"
      : "NOT_AVAILABLE";

    const isThirdParty =
      (vuln.vulnerabilityType || "").toUpperCase() === "THIRD_PARTY";

    // Compute dt.security.risk.level and dt.security.risk.score
    // These are required by the Findings app for severity display
    const dtRiskLevel = normalizeRiskLevel(vuln.riskAssessment?.riskLevel);
    const dtRiskScore = riskLevelToNormalizedScore(
      vuln.riskAssessment?.riskLevel,
      vuln.riskAssessment?.riskScore
    );

    const finding = {
      // ---- Metadata (required for all vulnerability finding events) ----
      timestamp: Number(nowNanos),
      "event.id": eventId,
      "event.kind": "SECURITY_EVENT",
      "event.type": "VULNERABILITY_FINDING",
      "event.name": "Vulnerability finding event",
      "event.provider": "Dynatrace Managed",
      "event.description":
        vuln.description || vuln.title || "",

      // ---- Finding data ----
      "finding.id": findingId,

      // ---- Dynatrace normalized risk (required for Findings app severity) ----
      "dt.security.risk.level": dtRiskLevel,
      "dt.security.risk.score": dtRiskScore,

      // ---- Vulnerability data ----
      "vulnerability.id":
        vuln.externalVulnerabilityId || vuln.securityProblemId || "",
      "vulnerability.title": vuln.title || "",
      "vulnerability.references.cve": vuln.cveIds || [],
      "vulnerability.cvss.base_score":
        vuln.riskAssessment?.baseRiskScore ?? null,
      "vulnerability.cvss.vector":
        vuln.riskAssessment?.baseRiskVector || "",
      "vulnerability.risk.level":
        vuln.riskAssessment?.riskLevel || "",
      "vulnerability.risk.score":
        vuln.riskAssessment?.riskScore ?? null,
      "vulnerability.remediation.status": remediationStatus,
      "vulnerability.technology": vuln.technology || "",
      "vulnerability.type": vuln.title || "",
      "vulnerability.url": vuln.url || "",

      // ---- Affected object (required for Findings app display & deduplication) ----
      "object.id": vuln.affectedEntity?.pgiId || "",
      "object.name": vuln.affectedEntity?.pgiDisplayName || vuln.affectedEntity?.pgiId || "",
      "object.type": "process_group_instance",

      // ---- Component data (required for Findings app deduplication & display) ----
      "component.name": componentName,
      "component.version": componentVersion,

      // ---- Product data ----
      "product.name": "DT Managed Connector",
      "product.vendor": "Dynatrace",
      "product.feature": isThirdParty
        ? "Third-party Vulnerability Analytics"
        : "Code-level Vulnerability Analytics",

      // ---- Scan data ----
      "scan.id": scanId,
      "scan.time.completed": scanTimeISO,
      "scan.time.started": scanTimeISO,

      // ---- Entity linkage (Extensions) ----
      "dt.source_entity": vuln.affectedEntity?.pgiId || "",
      "dt.source_entity.type": "process_group_instance",
      "dt.entity.process_group_instance":
        vuln.affectedEntity?.pgiId || "",
      "dt.entity.process_group":
        vuln.affectedEntity?.processGroupId || "",
      "dt.entity.host": vuln.affectedEntity?.hostId || "",
      "dt.entity.software_component":
        vuln.component?.softwareComponentId || "",

      // ---- Software component data (Extensions) ----
      "software_component.version": componentVersion,
      "software_component.purl": vuln.component?.fileName || "",
    };

    // software_component.type only for third-party libraries
    if (isThirdParty) {
      finding["software_component.type"] = "library";
    }

    // Remove empty/null fields to keep payload clean, but always keep required fields
    const alwaysKeep = new Set([
      "timestamp",
      "event.id",
      "event.kind",
      "event.type",
      "event.name",
      "event.provider",
      "vulnerability.id",
      "vulnerability.references.cve",
      "finding.id",
      "dt.security.risk.level",
      "dt.security.risk.score",
      "dt.source_entity",
      "dt.source_entity.type",
      "dt.entity.process_group_instance",
      "object.id",
      "object.type",
      "component.name",
      "product.name",
      "product.vendor",
      "scan.id",
    ]);
    for (const [key, value] of Object.entries(finding)) {
      if (alwaysKeep.has(key)) continue;
      if (value === "" || value === null || value === undefined) {
        delete finding[key];
      }
    }

    findings.push(finding);
  }

  console.log(
    `Formatted ${findings.length} vulnerability findings for ingestion.`
  );

  // Split into batches of 1000 for payload size limits
  const BATCH_SIZE = 1000;
  const batches = [];
  for (let i = 0; i < findings.length; i += BATCH_SIZE) {
    batches.push(findings.slice(i, i + BATCH_SIZE));
  }

  console.log(`Split into ${batches.length} batch(es) for ingestion.`);

  return { findings, batches, count: findings.length };
}
