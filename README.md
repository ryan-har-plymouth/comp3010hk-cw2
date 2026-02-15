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