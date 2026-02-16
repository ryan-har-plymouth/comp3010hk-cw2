# COMP3010HK Incident Analysis – Boss of the SOC v3 Investigation Report

This report presents a security investigation conducted using Splunk’s Boss of the SOC version 3 (BOTSv3) dataset. BOTSv3 is a publicly available, pre-indexed security dataset and Capture The Flag (CTF) platform created by Splunk to simulate a realistic security incident within a fictitious brewing company, Frothly. The dataset contains network, endpoint, email, and cloud service data from environments such as Amazon AWS and Microsoft Azure, which analysts investigate using Splunk’s Search Processing Language (SPL) in accordance with incident response and kill-chain methodologies.

### Objectives

The objectives of this investigation are to:
- Apply SOC-oriented analysis techniques to identify compromised assets and misconfigurations;
- Answer a defined set of 200-level BOTSv3 questions focused on AWS and endpoint events; and
- Reflect on how SOC roles, tiers, and incident handling practices apply to this exercise.

### Scope and assumptions

The scope is limited to the BOTSv3 dataset ingested into a single Splunk index (`botsv3`) on an Ubuntu VM. The analysis uses the AWS and endpoint question set provided in the coursework brief (Questions 1–8). It is assumed that the dataset has been correctly ingested and that source types such as `aws:cloudtrail`, `aws:s3:accesslogs`, `hardware`, and `winhostmon` are available and populated. The report does not cover other BOTSv3 question sets (e.g. 300-level) unless referenced for context.

### Report structure

The report is organised as follows:

- SOC roles and incident handling reflection
- Installation and data preparation
- Guided questions
- Conclusion, references and presentation


## SOC Roles and Incident Handling Reflection

Security Operations Centres (SOCs) are responsible for continuous monitoring, detection, and response to security events. SOC tiers typically range from Tier 1 (initial triage and alert handling) through Tier 2 (deeper investigation) to Tier 3 (advanced threat analysis and escalation). In the BOTSv3 scenario, the analyst performs work that spans these tiers: triaging AWS and endpoint data (Tier 1), correlating IAM, S3, and host data to understand an incident (Tier 2), and drawing conclusions about misconfigurations and exposure (Tier 3).

Incident handling is often described in phases: prevention, detection, response, and recovery. In BOTSv3, **prevention** is reflected in the questions around MFA monitoring and S3 bucket configuration—controls that, if applied, would reduce the likelihood of credential misuse and public data exposure. **Detection** is exercised through CloudTrail, S3 access logs, and endpoint data (e.g. hardware and OS inventory), which mirror the telemetry a SOC would use to spot anomalous API calls, bucket access, or host outliers. **Response** is demonstrated by identifying the affected principals (e.g. IAM users), resources (e.g. the exposed bucket), and endpoints (e.g. the host with a different OS edition), which would inform containment and remediation. **Recovery** is implied by the need to revoke exposed credentials, lock down bucket ACLs, and harden endpoints—all of which would be documented in a real post-incident report. This exercise therefore reinforces how SOC structures and incident phases map onto a structured log-based investigation.