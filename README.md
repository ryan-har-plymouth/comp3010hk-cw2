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

## Installation and Data Preparation

### Environment

Splunk Enterprise was installed on an Ubuntu virtual machine in line with the BOTSv3 documentation. The VM was provisioned with sufficient CPU and memory to support indexing and searching the BOTSv3 dataset. A single-node deployment was used.

### Dataset ingestion

The BOTSv3 dataset was obtained from the official repository (https://github.com/splunk/botsv3). The repository’s instructions were followed to download the data and ingest it into Splunk. Data was indexed under the index name `botsv3` as specified in the BOTSv3 documentation, ensuring compatibility with standard SPL examples and source type names.

### Validation

After ingestion, validation was performed to confirm that the index `botsv3` was populated and that the source types required for this report were present. Searches were run to verify events for `aws:cloudtrail`, `aws:s3:accesslogs`, `hardware`, and `winhostmon`. Screenshots of the index summary and sample source type listings are retained as evidence of a successful setup. This step is important in a SOC context to ensure that data pipelines are functioning before analysts rely on them for investigations.

### Justification

The choice of a single index for BOTSv3 aligns with the dataset’s design and keeps the lab environment simple while still reflecting how a SOC might dedicate an index to a specific data source or exercise.

## Guided Questions

Supporting evidence (screenshots of queries and results) is included in the final submission to demonstrate the analysis performed in Splunk. 

### Question 1

List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment?

#### SPL

```spl
index="botsv3" sourcetype="aws:cloudtrail" userIdentity.type=IAMUser | 
stats values(userIdentity.userName) as userName_list | 
eval userNames = mvjoin(userName_list, ",") | 
fields userNames
```

#### Answer
bstoll,btun,splunk_access,web_admin

#### Evidence
![Q1 evidence](evidence/E1_iam_users.png)

#### SOC relevance
Enumerating IAM users from CloudTrail establishes a baseline of who can act in the environment and supports access reviews and detection of unauthorised accounts.

---

### Question 2

What field would you use to alert that AWS API activity has occurred without MFA (multi-factor authentication)?

#### Answer
userIdentity.sessionContext.attributes.mfaAuthenticated

#### Evidence
![Q2 evidence](evidence/E2_mfa_attribute.png)

#### SOC relevance
Alerting on this field supports detection of high-risk actions performed without MFA and is aligned with AWS best practices and compliance requirements.

---

### Question 3

What is the processor number used on the web servers?

#### SPL

```spl
index=botsv3 sourcetype=hardware | table cpu_type | dedup cpu_type
```

#### Answer
E5-2676

#### Evidence
![Q3 evidence](evidence/E3_processor_number.png)

#### SOC relevance
Hardware inventory supports asset management and baselining; anomalies in CPU type or utilisation can indicate unauthorised or compromised systems.

---

### Question 4

Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access?

#### SPL

```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl | search *AllUsers*
```

#### Answer
ab45689d-69cd-41e7-8705-5350402cf7ac

#### Evidence
![Q4 evidence](evidence/E4_enabled_public_access.png)

#### SOC relevance
Identifying the exact event that changed ACLs supports incident timelines and accountability and can feed into automated alerting on dangerous S3 API calls.

---

### Question 5

What is Bud's username?

#### Answer
bstoll

#### Evidence
![Q5 evidence](evidence/E5_buds_username.png)

#### SOC relevance
Associating the misconfiguration with a specific identity is essential for accountability, user awareness training, and access review.

---

### Question 6

What is the name of the S3 bucket that was made publicly accessible?

#### Answer
frothlywebcode

#### Evidence
![Q6 evidence](evidence/E6_s3_bucket.png)

#### SOC relevance
The bucket name is required to scope remediation, for example, removing public ACLs, checking object exposure, and correlating with access logs.

---

### Question 7

What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible?

#### SPL

```spl
index=botsv3 sourcetype=aws:s3:accesslogs http_method=PUT *frothlywebcode* |
search *.txt |
table _time bucket_name key status
```

#### Answer
OPEN_BUCKET_PLEASE_FIX.txt

#### Evidence
![Q7 evidence](evidence/E7_uploaded_text_file.png)

#### SOC relevance
Identifying objects uploaded during the exposure window is critical for assessing data breach scope.

---

### Question 8

What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?

#### SPL 1

```spl
index=botsv3 sourcetype=winhostmon | stats count by host, OS | dedup host | sort host
```

#### SPL 2

```spl
index=botsv3 sourcetype="wineventlog" host="BSTOLL-L"
```

#### Answer
BSTOLL-L.froth.ly

#### Evidence
![Q8 evidence](evidence/E8_different_windows_operating_system.png)
![Q8 evidence](evidence/E9_FQDN.png)

#### SOC relevance
Identifying outliers in OS inventory supports change management, licence compliance, and detection of unsanctioned or compromised systems.