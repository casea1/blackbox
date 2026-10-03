# Blackbox 0.10.1: test results, 2–3 Oct 2026

Ubuntu 26.04 sender tested live; Windows items tested offline. The Windows 11 collector VM (Umbrel, software emulation) never finished installing, so delivery to a collector and the collector's report are still to be tested.

- [findings.md](findings.md): every finding by ID: 0.10.0 fixes re-checked, new findings, the Linux sender run, and an ISSO/ISSM review of audit coverage (AU-2/AU-6/AU-12) with Splunk-style roadmap items.
- [worker-prompt.md](worker-prompt.md): the findings as a prioritised work list, including a proposal to read SCAP (SCC/OpenSCAP) results into the report.
- [test-plan.md](test-plan.md): what was planned, including the collector tests still to run.
- [test-activity.log](test-activity.log): every test action, timestamped (UTC).
- [scripts/](scripts/): the scripts typed into the VMs (test passwords come from environment variables and aren't stored).
- [shots/](shots/): screenshots. One test password in `ubu-09` is blacked out.
