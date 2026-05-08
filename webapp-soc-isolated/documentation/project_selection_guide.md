# Final Project Selection Guide

You now have two independent SOC projects:

## Option A: Windows SOC (Sysmon)

Path:
- [README.md](README.md)

Best when:
- your professor prefers host-level security
- focus is Windows event telemetry and tampering
- emphasis on endpoint defense

Strengths:
- Sysmon + Winlogbeat + ML + Grafana
- process/file/registry analysis
- direct log tampering simulation

## Option B: WebApp SOC (Isolated)

Path:
- [webapp-soc-isolated/README.md](webapp-soc-isolated/README.md)

Best when:
- your professor prefers application security
- focus is brute force, scans, endpoint abuse
- emphasis on modern web SOC use-cases

Strengths:
- custom structured web logs
- behavioral anomalies per IP/path
- advanced SOC dashboard focused on web threats
- phase 2 threat-intelligence dashboard with risk and severity layers

## Recommendation for Final Submission

Choose Windows SOC if your department expects OS-level cybersecurity projects.
Choose WebApp SOC if your department prefers practical full-stack security engineering.

If needed, you can present both briefly and then say:
- primary submission: one project
- extension work: second isolated SOC project
