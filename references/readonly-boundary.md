# Read-Only Boundary

This skill defaults to evidence collection and reporting only.

## Allowed by Default

1. Read commands, metadata inspection, hashing, version checks, log reading, process listing, socket listing, service metadata reading, config reading, and package-version inspection.
2. Writing the local case bundle under `reports/<case>/`.
3. Read-only vulnerability exposure checks based on kernel/package/config state.

## Not Allowed by Default

1. `kill`, `pkill`, `killall`
2. `systemctl stop|restart|disable`
3. `rm`, `mv`, `truncate`, `shred`
4. config edits
5. firewall or route changes
6. package install/remove/upgrade
7. reboot, shutdown, isolation, quarantine
8. exploit validation or proof-of-concept execution

## If the User Mixes Investigation and Remediation

If the request contains both “investigate” and “kill/stop/delete/fix” intent:

1. Continue with read-only investigation only.
2. Record remediation wishes as follow-up actions requiring separate approval.
3. Do not silently transition into mutation.

## Required Response Pattern

When remediation is requested during investigation:

1. State that the current step remains read-only.
2. Collect and correlate evidence first.
3. Present any remediation only as a later approval-gated proposal.
