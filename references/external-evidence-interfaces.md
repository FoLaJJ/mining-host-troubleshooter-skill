# External Evidence Interfaces

Use this checklist when host-local evidence is insufficient to close the initial-access path or upstream attribution chain.

## Cloud and Platform Sources

1. cloud audit trails for instance start, stop, role attach, snapshot, and metadata-token events
2. cloud IAM logs for API key, role, or temporary credential abuse
3. cloud load balancer, NAT gateway, and flow logs for inbound and outbound pivots
4. cloud-init or provisioning-system records for unexpected bootstrap commands

## Kubernetes and Container Sources

1. Kubernetes audit logs for `exec`, `port-forward`, `create`, `patch`, `apply`, `CronJob`, and `DaemonSet`
2. image registry pull history and tag mutation history
3. admission controller or runtime security alerts
4. node-agent and CNI logs when reachable

## Identity and Access Sources

1. bastion or jump-host authentication logs
2. identity-provider authentication and MFA failure logs
3. PAM central logging or SIEM records
4. SSH CA or certificate issuance logs if the environment uses them

## CI/CD and Supply-Chain Sources

1. pipeline execution logs
2. secret-store access logs
3. artifact registry download history
4. config-management deployment records

## Network and Boundary Sources

1. firewall logs
2. proxy logs
3. DNS logs
4. IDS, NDR, or boundary packet metadata

## Reporting Rule

If an external source is unavailable, state that explicitly.
Do not fill the gap with inference presented as fact.
