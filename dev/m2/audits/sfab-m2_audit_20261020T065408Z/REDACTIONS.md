# Redactions

Some recorded text in this result set was replaced after the set was recorded, with `common/audit/redact_tree.py`. Each replacement is the marker `[redacted: <class>]` on the line that held the text, so every line keeps its number and the rest of the line reads as recorded. This file names no replaced text.

| Class | What it replaced |
|---|---|
| host-cpuid | the CPU signature the PA-VM passes through from the lab host's processor (its vm-cpuid) |
| host-kernel | the lab host's kernel release, which a container prints as its own |
| host-search-domain | the lab host's own DNS search domain, which Docker copies from the lab host's resolv.conf into each container's |

| File | Line | Class |
|---|---|---|
| bastion/02_bonding.txt | 1 | host-kernel |
| commands.txt | 18626 | host-cpuid |
| commands.txt | 22640 | host-kernel |
| commands.txt | 54089 | host-kernel |
| commands.txt | 54225 | host-search-domain |
| fw/04_system_info.txt | 22 | host-cpuid |
| op-client/07_resolv_conf.txt | 6 | host-search-domain |
| raw/fw-panos-cli-opFtAH.txt | 47 | host-cpuid |
| uplink-rtr/01_frr_version.txt | 1 | host-kernel |
