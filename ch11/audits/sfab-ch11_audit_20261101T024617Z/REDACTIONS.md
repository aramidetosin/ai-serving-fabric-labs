# Redactions

Some recorded text in this result set was replaced while the set was recorded, by `common/audit/redact.py`. Each replacement is the marker `[redacted: <class>]` on the line that held the text, so every line keeps its number and the rest of the line reads as recorded. This file names no replaced text.

| Class | What it replaced |
|---|---|
| host-cpuid | the CPU signature the PA-VM passes through from the lab host's processor (its vm-cpuid) |
| host-kernel | the lab host's kernel release, which a container prints as its own |
| throughput | a measured throughput figure, which the repository does not publish |

| File | Line | Class |
|---|---|---|
| bastion/02_bonding.txt | 1 | host-kernel |
| commands.txt | 21369 | host-cpuid |
| commands.txt | 76481 | host-kernel |
| commands.txt | 76699 | host-kernel |
| commands.txt | 76872 | host-kernel |
| commands.txt | 77054 | host-kernel |
| commands.txt | 77231 | host-kernel |
| commands.txt | 77398 | host-kernel |
| commands.txt | 78512 | host-kernel |
| commands.txt | 90470 | throughput |
| dns-auth1/04_bonding.txt | 1 | host-kernel |
| dns-auth2/04_bonding.txt | 1 | host-kernel |
| dns-res1/04_bonding.txt | 1 | host-kernel |
| dns-res2/04_bonding.txt | 1 | host-kernel |
| fw/04_system_info.txt | 22 | host-cpuid |
| isp-rtr/01_frr_version.txt | 1 | host-kernel |
| raw/fw-panos-cli-21n86F.txt | 53 | host-cpuid |
| raw/fw-panos-cli-sg53Mf.txt | 41 | throughput |
| uplink-rtr/01_frr_version.txt | 1 | host-kernel |
| zone-nat/session-info-held.txt | 23 | throughput |
