# opa-policy-package
Rucio policy package integrating Open Policy Agent for experiment-specific permission and schema customisation

**TODO**:

- Define integration plan: select target permission actions from generic.py (e.g. RSE management, replication rules, DIDs) to delegate to OPA as PDP
- Add docker-compose.yml with Rucio server and OPA container (AuthZ)
- Ingest Rego policies into OPA via available interfaces covering the selected permission actions (Refer to: https://github.com/federicaagostini/opa-ri-scale/tree/main)
- Develop rucio-opa-policy package overriding has_permission() to delegate selected actions to OPA
- Add e2e tests covering OPA communication and allow/deny scenarios per selected permission action
