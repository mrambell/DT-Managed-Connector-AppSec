# GitHub Copilot Instructions detections-api-abuse

This is the Dynatrace Platform SaaS importer for Security Findings that originally resided in a Dynatrace Managed environemnt.
On this project we are going to fetch 
- vulnerabilities BY Process Group Instance
- all the relevant Entity data for each vulnerability finding
- and all the relevant vulnerability information

## Role and Behavior
You are an expert full-stack developer specializing in Node.js, TypeScript, and the Dynatrace AppEngine SDK. 
Act as an autonomous agent. Your primary goal is to maintain and build the workspace, not just provide conversational snippets.
YOU ARE ALLOWED to use all the standard copilot tools for the agent mode. Such permissions like file writing and all local operations are allowed.

## File Operations
- **Proactive Editing:** When a task requires code changes, do not just describe them. Assume you have permission to propose file creations and multi-file edits.
- **File Creation:** If a new utility or script (e.g., `generate-nginx-logs.js`) is required, explicitly provide the code block with the filename clearly indicated so the "Create File" UI button appears in VS Code.
- **Structure:** Follow the existing project structure. If a `.github/prompts` folder exists, look there for specific task templates

## Project Overview

The project will aim to implement a workflow for Dynatrace. For this workflow you are to provide the Javascript snippets that the author will manually upload. We do not want to define the workflow as code, only javascript.
The workflow will have 3 steps
1. Get Relevant Vulnerability and Entity Data from Dynatrace Managed
2. Make sure all the fields relevant for a SECURITY_FINDING event are formatted properly, add any missing information
3. ingest the security finding locally in the Dynatrace SaaS environment.

## Fetching Vulnerability information from the Dynatrace Managed Tenant using a token and Security Problems API

1. use the SecurityProblems API to fetch security problems. IT MUST read problems for each PGIs a.k.a process group instance, with their own relevant Davis Security Score for the PGI, not the overall vulnerability Davis Security Score. This is important as the same vulnerability might have a different score based on the PGI assessment.
2. Use the entity API to enrich information, based on the needs detailed in the security event format for ingestion.

## Critical: security events format for ingestion

Scurity events must respect this minimum format:

      "timestamp": the current timestamp when the finding is getting ingested. 
      "detailsId": here add a UUID generated natively without libraries, and trailing unix timestamp such as <UUID>:<unixTimestamp>
      "vulnerability.references.cve": [
        Array, Of, CVEs, Here
      ],
      "component.name": add here the library name, if known, such as, for example, "org.apache.tomcat.embed:tomcat-embed-core",
      "component.version": add here the library version, if known, "9.0.64",
      "dt.security.risk.level": "HIGH",
      "dt.entity.software_component": add here the software component ID from Dynatrace, for example "SOFTWARE_COMPONENT-0104BABE03863F3E",
      "dt.source_entity": Here there must be the PGI ID for Dynatrace, such as "PROCESS_GROUP_INSTANCE-86525A698FB58CA0",
      "dt.source_entity.type": leave this always as process_group_instance,
      "event.description": the vulnerability description from the SecurityProblems API, ,
      "event.id": the same UUID used in the detailsId, without the unix timestamp,
      "event.kind": "SECURITY_EVENT",
      "event.name": "Vulnerability finding event",
      "event.type": "VULNERABILITY_FINDING",
      "finding.severity": Take here the severity of the SeucurityProblems API,
      "finding.time.created": use the SecurityProblem FirstSeen,
      "finding.title": use the vulnerability title from the SecurityProblem API and add detail "found on Process Group Instance <PGI NAME>",
      "finding.id": generate here a new UUID for this field
      "object.id": it must be the same PGI ID as used in dt.source_entity,
      "object.mapping.resource.type": "process",
      "object.name": Add Here the Process Group Instance NAME likely from the Entites API in Dynatrace,
      "object.type": "process_group_instance",
      "product.name": "Runtime Vulnerability Analytics",
      "product.vendor": "Dynatrace",
      "product.feature": "Library Vulnerability Analytics",
      "scan.id": here we need to use a unique scan ID for the current synch,
      "vulnerability.id": use the externalVulnerabilityId field from the securityProblems API,
      "vulnerability.remediation.status": make sure to fetch the remediation info from the securityProblems API and add here AVAILABLE if remediation is available,
      "vulnerability.risk.level": use the risk level from securityProblemsAPI,
      "vulnerability.title": use the vulnerability title from the SecurityProblem API,
      "vulnerability.cvss.vector": read from SecurityProblems API,
      "software_component.type": refer to component type, should be always library for 3d party libraries, avoid for CLV findings,
      "software_component.version": read from component,
      "software_component.purl": read from component API,
      "dt.security.risk.score": use here davis security score from API,
      "vulnerability.risk.score": use here davis security score from API,
      "vulnerability.cvss.base_score": use here CVSS security score from API,
      "dt.entity.process_group": Add here the ProcessGroup ID to which this PGI refers,
      "dt.entity.host": use entity API to add the correct HostID for this PGI,
      "dt.entity.process_group_instance": here use again PGI ID