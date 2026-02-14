# Windows Security Architecture Research Lab

<p align="center">
  <img src="https://img.shields.io/badge/Purpose-Educational-blue">
  <img src="https://img.shields.io/badge/Focus-Defensive%20Security-green">
  <img src="https://img.shields.io/badge/Type-Research%20Lab-orange">
  <img src="https://img.shields.io/badge/Environment-Isolated-lightgrey">
</p>

---

## Overview

This repository documents a structured research lab focused on analyzing Windows security mechanisms, privilege architecture, and defensive detection strategies.

The primary objective is to understand:

- Windows privilege boundaries  
- User Account Control (UAC) behavior  
- Registry trust relationships  
- Security service dependencies  
- Defensive detection engineering  

This project is strictly educational and intended for controlled lab environments only.

---

## Research Areas

### 1. Privilege Architecture

- Windows Integrity Levels
- UAC design and auto-elevation behavior
- Trusted signed binaries concept
- HKCU vs HKLM trust boundaries
- Registry-based execution flow

---

### 2. Windows Security Components Studied

The lab analyzes the defensive role of:

- Microsoft Defender
- Windows Firewall
- Windows Recovery Environment (WinRE)
- SmartScreen
- Security Center
- Windows Update
- Event Logging
- Device Guard
- Exploit Guard
- Windows Script Host

For each component, the focus is:

- Security objective  
- Risk exposure surface  
- Detection opportunities  
- Hardening recommendations  

---

## Defensive Detection Strategy

This research emphasizes blue team visibility and monitoring.

### Key Indicators

- Suspicious registry key creation
- Unexpected child process behavior
- Integrity level anomalies
- Security service state changes
- Persistence location modifications
- Unusual execution chains involving trusted binaries

---

## Log Sources for Analysis

- Windows Security Log  
- Sysmon  
- PowerShell Operational Log  
- Defender Security Logs  
- Task Scheduler Logs  

---

## Lab Environment Requirements

All testing must be conducted in an isolated virtual environment.

Recommended setup:

- Dedicated Virtual Machine
- Snapshot before experimentation
- Network isolation
- Full logging enabled
- Baseline comparison before and after testing

Recommended platforms:

- VMware Workstation  
- VirtualBox  
- Hyper-V  

---

## Learning Objectives

By completing this lab, learners should understand:

- How Windows enforces privilege separation  
- Why registry-based configurations can introduce risk  
- How misconfigurations weaken security posture  
- How defenders detect suspicious system modifications  
- How to design monitoring strategies aligned with real-world SOC practices  

---

## Ethical & Legal Notice

This repository is intended strictly for:

- Academic research  
- Defensive cybersecurity training  
- Authorized lab experimentation  
- Professional portfolio development  

Any misuse against systems without explicit authorization is illegal and unethical.

---

## Contributing

Contributions are welcome in the following areas:

- Defensive detection improvements
- Log analysis methodologies
- Hardening documentation
- Blue Team playbooks
- Educational refinements

All contributions must align with responsible security research principles.
