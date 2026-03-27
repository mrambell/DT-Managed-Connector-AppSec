---
description: "Generate Vulnerability import Workflow from Managed to SaaS"
agent: "agent"
tools: [dynatrace-oss/dynatrace-mcp/*]
---

# Prepare 

1. Read the documentation about the Dynatrace securityProblems API on Dynatarce Managed
2. Read the documentation on the entities API in dynatrace managed
3. Read the documentation about the open pipeline ingestion for security events in Dynatrace SaaS
4. Read about the required format for security events ingestion in Dynatrace SaaS, with a focus on the required and optional fields, and the ones relevant for vulnerability findings.


# Scenario
In Dynatrace SaaS, we need to ingest Vulnerabilities found by Dynatrace One Agent in the Managed environment. The ingestion will be done using the Open Pipeline, and the source of the data will be a workflow running in the SaaS environment that will fetch vulnerability information using the securityProblems API from the Managed Side, enrich it with the entities API, and then send it to the Open Pipeline endpoint for ingestion in SaaS.
The assumption is that the saas environment can communicate with the managed environment using the APIs, and that the workflow can be scheduled to run every X minutes to keep the vulnerability information in SaaS up to date.
You will have to suggest the best synchronisation time.
Do not worry about duplicate findings, we will handle that in a later step. The focus of this step is to create the workflow that can fetch the data, enrich it, and send it to SaaS in the correct format.

## URLs used to contact and tokens.
- Dynatrace Managed API URL: https://tenantid.live.dynatrace.com/api/v2
- Dynatrace Managed TOKEN: <TOKEN>
- Authorization header format: "Authorization: Api-Token <TOKEN>"



## Instructions for the deliverables

Make 3 Javascript files
1. the first file will be using the securityProblems API to fetch the vulnerabilities for each PGI, and their Davis security score, and save the output in a JSON format to be used in later step. It will also use the Entites API to enrich the information with the PGI name and the HostID. Save this file as "fetch-vulnerabilities.js"
2. the second file will make sure that the vulnerability finding format for ingestion is exactly correct and can be ingested in the open pipeline. It will take the output from the first file, and transform it into the correct format, making sure to add any missing information, and to format the fields correctly. Save this file as "format-vulnerabilities.js"
3. the third step is to use an HTTP Workflow Action to ingest the findings, and you will save instructions on how to configure the HTTP action so to ingest information correctly in the open pipeline. Save this file as ingest-vulnerabilities.md and I will configure it manually.

## Output
the javascript files:
- fetch-vulnerabilities.js
- format-vulnerabilities.js
the md file:
- ingest-vulnerabilities.md
