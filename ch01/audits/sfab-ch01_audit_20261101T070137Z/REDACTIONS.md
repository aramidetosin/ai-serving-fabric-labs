# Redactions

Some recorded text in this result set was replaced while the set was recorded, by `common/audit/redact.py`. Each replacement is the marker `[redacted: <class>]` on the line that held the text, so every line keeps its number and the rest of the line reads as recorded. This file names no replaced text.

| Class | What it replaced |
|---|---|
| host-cpuid | the CPU signature the PA-VM passes through from the lab host's processor (its vm-cpuid) |
| host-kernel | the lab host's kernel release, which a container prints as its own |

| File | Line | Class |
|---|---|---|
| bastion/02_bonding.txt | 1 | host-kernel |
| commands.txt | 21392 | host-cpuid |
| commands.txt | 75821 | host-kernel |
| commands.txt | 76039 | host-kernel |
| commands.txt | 76212 | host-kernel |
| commands.txt | 76394 | host-kernel |
| commands.txt | 76571 | host-kernel |
| commands.txt | 76738 | host-kernel |
| dns-auth1/04_bonding.txt | 1 | host-kernel |
| dns-auth2/04_bonding.txt | 1 | host-kernel |
| dns-res1/04_bonding.txt | 1 | host-kernel |
| dns-res2/04_bonding.txt | 1 | host-kernel |
| fw/04_system_info.txt | 22 | host-cpuid |
| raw/fw-panos-cli-iQUjNz.txt | 53 | host-cpuid |
| uplink-rtr/01_frr_version.txt | 1 | host-kernel |
