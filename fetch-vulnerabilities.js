// fetch-vulnerabilities.js
// Dynatrace Workflow JavaScript Action
// Fetches vulnerabilities from Dynatrace Managed securityProblems API,
// enriches with entity info (PGI name, Host ID, Process Group ID),
// vulnerable component details, and remediation status.

export default async function () {
  // -- Configuration --
  const MANAGED_API_URL = "https://jak10854.live.dynatrace.com/api/v2";
  const MANAGED_TOKEN = "<CREDENTIAL_VAULT_REF>"; // Replace with credential vault reference
  const PAGE_SIZE = 500;

  const headers = {
    "Authorization": `Api-Token ${MANAGED_TOKEN}`,
    "Accept": "application/json; charset=utf-8",
  };

  // -- Step 1: Fetch all security problems (list) --
  let allSecurityProblems = [];
  let nextPageKey = null;

  do {
    const params = new URLSearchParams({
      pageSize: String(PAGE_SIZE),
      fields: "+riskAssessment,+managementZones",
    });
    if (nextPageKey) {
      params.set("nextPageKey", nextPageKey);
    }

    const url = `${MANAGED_API_URL}/securityProblems?${params.toString()}`;
    const response = await fetch(url, { method: "GET", headers });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(
        `Failed to fetch security problems: ${response.status} - ${errorBody}`
      );
    }

    const data = await response.json();
    if (data.securityProblems) {
      allSecurityProblems = allSecurityProblems.concat(data.securityProblems);
    }
    nextPageKey = data.nextPageKey || null;
  } while (nextPageKey);

  console.log(
    `Fetched ${allSecurityProblems.length} security problems from Managed.`
  );

  // -- Step 2: For each security problem, get details + vulnerable components + remediation items --
  const detailedProblems = [];

  for (const sp of allSecurityProblems) {
    // Detail endpoint: include riskAssessment, affectedEntities, vulnerableComponents
    const detailUrl = `${MANAGED_API_URL}/securityProblems/${encodeURIComponent(
      sp.securityProblemId
    )}?fields=+riskAssessment,+affectedEntities,+vulnerableComponents`;
    const detailResp = await fetch(detailUrl, { method: "GET", headers });

    if (!detailResp.ok) {
      console.log(
        `Warning: Could not fetch details for ${sp.securityProblemId}: ${detailResp.status}`
      );
      continue;
    }

    const detail = await detailResp.json();

    // Fetch remediation items for remediation status + per-entity assessment
    const remItemsUrl = `${MANAGED_API_URL}/securityProblems/${encodeURIComponent(
      sp.securityProblemId
    )}/remediationItems`;
    const remItemsResp = await fetch(remItemsUrl, { method: "GET", headers });

    let remediationItems = [];
    if (remItemsResp.ok) {
      const remData = await remItemsResp.json();
      remediationItems = remData.remediationItems || [];
    } else {
      console.log(
        `Warning: Could not fetch remediation items for ${sp.securityProblemId}: ${remItemsResp.status}`
      );
    }

    // Build map: entityId -> remediation data (per-entity assessment + remediation availability)
    const entityRemediationMap = {};
    for (const item of remediationItems) {
      const remInfo = {
        vulnerabilityState: item.vulnerabilityState || "",
        remediationAvailable:
          item.vulnerableComponents && item.vulnerableComponents.length > 0,
        remediationItemName: item.name || "",
      };

      const entityIds = [
        ...(item.remediationProgress?.affectedEntities || []),
        ...(item.entityIds || []),
      ];
      for (const entityId of entityIds) {
        if (!entityRemediationMap[entityId]) {
          entityRemediationMap[entityId] = remInfo;
        }
      }
    }

    // Build map: entityId -> software component info from vulnerableComponents
    const entityComponentMap = {};
    if (detail.vulnerableComponents) {
      for (const comp of detail.vulnerableComponents) {
        const compInfo = {
          softwareComponentId: comp.id || "",
          componentDisplayName: comp.displayName || "",
          componentFileName: comp.fileName || "",
          componentShortName: comp.shortName || "",
        };
        const compEntities = comp.affectedEntities || [];
        for (const entityId of compEntities) {
          if (!entityComponentMap[entityId]) {
            entityComponentMap[entityId] = compInfo;
          }
        }
      }
    }

    detail._entityRemediationMap = entityRemediationMap;
    detail._entityComponentMap = entityComponentMap;
    detailedProblems.push(detail);
  }

  console.log(
    `Retrieved details for ${detailedProblems.length} security problems.`
  );

  // -- Step 3: Collect all unique PGI IDs --
  const pgiIds = new Set();
  for (const problem of detailedProblems) {
    if (problem.affectedEntities) {
      for (const entityId of problem.affectedEntities) {
        if (entityId.startsWith("PROCESS_GROUP_INSTANCE-")) {
          pgiIds.add(entityId);
        }
      }
    }
  }

  console.log(`Found ${pgiIds.size} unique affected PGIs. Enriching...`);

  // -- Step 4: Fetch PGI entity details (display name, host, process group) in batches --
  // The entities API defaults to from=-72h which misses inactive PGIs.
  // Use a wide time range to ensure all entities are found.
  const pgiDetails = {};
  const pgiArray = Array.from(pgiIds);
  const ENTITY_BATCH_SIZE = 20;

  for (let i = 0; i < pgiArray.length; i += ENTITY_BATCH_SIZE) {
    const batch = pgiArray.slice(i, i + ENTITY_BATCH_SIZE);
    const entitySelector = `entityId(${batch
      .map((id) => `"${id}"`)
      .join(",")})`;
    const entityParams = new URLSearchParams({
      entitySelector: entitySelector,
      from: "now-365d",
      fields: "+fromRelationships.runsOnHost,+fromRelationships.isInstanceOf",
      pageSize: String(ENTITY_BATCH_SIZE),
    });

    const entityUrl = `${MANAGED_API_URL}/entities?${entityParams.toString()}`;
    const entityResp = await fetch(entityUrl, { method: "GET", headers });

    if (!entityResp.ok) {
      const errBody = await entityResp.text();
      console.log(
        `Warning: Could not fetch entity batch starting at index ${i}: ${entityResp.status} - ${errBody}`
      );
      continue;
    }

    const entityData = await entityResp.json();
    const returned = entityData.entities || [];
    console.log(
      `Entity batch ${i / ENTITY_BATCH_SIZE + 1}: requested ${batch.length}, got ${returned.length}`
    );
    for (const entity of returned) {
      const hostRelations = entity.fromRelationships?.runsOnHost || [];
      const pgRelations = entity.fromRelationships?.isInstanceOf || [];
      pgiDetails[entity.entityId] = {
        displayName: entity.displayName || entity.entityId,
        hostId: hostRelations.length > 0 ? hostRelations[0].id : null,
        processGroupId: pgRelations.length > 0 ? pgRelations[0].id : null,
      };
    }
  }

  console.log(`Enriched ${Object.keys(pgiDetails).length} / ${pgiArray.length} PGI entities.`);

  // -- Step 5: Build output - one record per (securityProblem, PGI) pair --
  const output = [];

  for (const problem of detailedProblems) {
    const affectedPGIs = (problem.affectedEntities || []).filter((e) =>
      e.startsWith("PROCESS_GROUP_INSTANCE-")
    );
    const entityRemediationMap = problem._entityRemediationMap || {};
    const entityComponentMap = problem._entityComponentMap || {};

    for (const pgiId of affectedPGIs) {
      const pgiInfo = pgiDetails[pgiId] || {
        displayName: pgiId,
        hostId: null,
        processGroupId: null,
      };
      const remInfo = entityRemediationMap[pgiId] || {};
      const compInfo = entityComponentMap[pgiId] || {};

      output.push({
        securityProblemId: problem.securityProblemId,
        externalVulnerabilityId: problem.externalVulnerabilityId || "",
        title: problem.title || "",
        description: problem.description || "",
        vulnerabilityType: problem.vulnerabilityType || "THIRD_PARTY",
        cveIds: problem.cveIds || [],
        url: problem.url || "",
        technology: problem.technology || "",
        packageName: problem.packageName || "",
        firstSeenTimestamp: problem.firstSeenTimestamp || null,
        lastUpdatedTimestamp: problem.lastUpdatedTimestamp || null,
        status: problem.status || "",
        muted: problem.muted || false,
        // Davis risk assessment (problem-level)
        riskAssessment: {
          riskScore: problem.riskAssessment?.riskScore ?? null,
          riskLevel: problem.riskAssessment?.riskLevel ?? "",
          baseRiskScore: problem.riskAssessment?.baseRiskScore ?? null,
          baseRiskLevel: problem.riskAssessment?.baseRiskLevel ?? "",
          baseRiskVector: problem.riskAssessment?.baseRiskVector ?? "",
        },
        // Remediation status for this entity
        remediation: {
          available: remInfo.remediationAvailable || false,
          vulnerabilityState: remInfo.vulnerabilityState || "",
          remediationItemName: remInfo.remediationItemName || "",
        },
        // Software component info for this entity
        component: {
          softwareComponentId: compInfo.softwareComponentId || "",
          displayName: compInfo.componentDisplayName || "",
          fileName: compInfo.componentFileName || "",
          shortName: compInfo.componentShortName || "",
        },
        // Affected entity info
        affectedEntity: {
          pgiId: pgiId,
          pgiDisplayName: pgiInfo.displayName,
          hostId: pgiInfo.hostId,
          processGroupId: pgiInfo.processGroupId,
        },
      });
    }
  }

  console.log(`Produced ${output.length} vulnerability-entity records.`);

  return { vulnerabilities: output };
}
