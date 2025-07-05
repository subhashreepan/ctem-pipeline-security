# CTEM Pipeline Security

This project aims to build a **Continuous Threat Exposure Management (CTEM)** framework for securing CI/CD pipelines. Unlike traditional tools that forget past issues, CTEM adds a memory layer to detect recurring vulnerabilities like leaked secrets or outdated dependencies.

It uses open-source tools such as **GitLeaks** (for secrets detection) and **Trivy** (for vulnerability scanning), and stores scan results in a custom-built memory system. Future scans are compared against this memory to flag reintroduced threats.

An interactive dashboard (using Streamlit) will be used to visualize repeated exposures and trends in your pipeline security.