# Cloud Security Engineer – Malware Protection System

This repository contains a working implementation of the home assignment:

- An **npm registry proxy** that blocks installation of known-malicious npm packages.
- A **Kubernetes admission webhook** that scans newly created Pods for malicious dependencies and reports findings to CSV on a PVC.

Both components run entirely inside Kubernetes and share a cached malware list fetched from a throttled external API.

## Architecture Overview

### Components

- **Malware API (external)**  
  Provides a JSON list of malicious packages.

- **Malware Cache (in proxy)**

  - Fetches from external API with TTL and exponential backoff.
  - Exposes the current cached list via `/malware` for in-cluster consumers.

- **npm Registry Proxy**

  - Implements a drop-in npm/yarn registry (HTTP).
  - Parses requested package name + version (for tarball downloads).
  - Checks the malware list; blocks any matching package/version.
  - Proxies all other requests to `https://registry.npmjs.org`.

- **Admission Webhook**
  - ValidatingAdmissionWebhook on `pods/create`.
  - Always returns `allowed: true` (and `failurePolicy: Ignore`).
  - Asynchronously:
    - Fetches the malware list from the proxy’s `/malware` endpoint.
    - Scans Pod images (stubbed via annotations for local demo).
    - Appends findings to CSV on a PVC.

### Architecture Diagram

```text
External Malware JSON API
             ^
             | (HTTPS, throttled)
             v
   +-----------------------------+
   | npm Registry Proxy (cache) |
   |  - /malware                |
   |  - /healthz                |
   +-----------------------------+
      ^                   ^
      | npm/yarn traffic  | in-cluster HTTP
      |                   |
Dev / CI              Admission Webhook
                        |
                        v
               PVC: findings.csv
```
