# Blackbox 0.10.1 to 0.10.4: test results, 2–5 Oct 2026

Ubuntu 26.04 sender and Windows Server 2025 collector tested live (the Windows 11 VM never got past OOBE under nested KVM). Delivery went over SFTP (sshfs) because the test VMs are isolated from each other; the SMB route between machines is still untested. 0.10.4 (the worker's fixes for the first work list) was verified on 5 Oct, including SCAP results from a real OpenSCAP scan: see the "v0.10.4 verification" section of findings.md.

- [findings.md](findings.md): every finding by ID: 0.10.0 fixes re-checked, new findings, the Linux sender run, and an ISSO/ISSM review of audit coverage (AU-2/AU-6/AU-12) with Splunk-style roadmap items.
- [worker-prompt.md](worker-prompt.md): the first work list (done in 0.10.2), including the proposal to read SCAP (SCC/OpenSCAP) results into the report.
- [worker-prompt-2.md](worker-prompt-2.md): the second work list: what 0.10.4 didn't fix, what it introduced, the collector and delivery findings, SCAP, and STIG-image compatibility.
- [worker-prompt-3.md](worker-prompt-3.md): the third work list, from the 0.11.0 re-test and the Windows 11 standalone tests (clock changes, noise on a fresh Windows 11, SC3).
- [test-plan.md](test-plan.md): what was planned, including the collector tests still to run.
- [test-activity.log](test-activity.log): every test action, timestamped (UTC).
- [scripts/](scripts/): the scripts typed into the VMs (test passwords come from environment variables and aren't stored).
- [shots/](shots/): screenshots. One test password in `ubu-09` is blacked out.
- [v0.10.4/](v0.10.4/): 0.10.4 evidence: the Ubuntu activity rows and report summary, the Windows upgrade screens, the SCAP results summary and CSV, and raw records for U5 (OpenSSH 10) and O1 (sudo-rs) to use as test fixtures.
