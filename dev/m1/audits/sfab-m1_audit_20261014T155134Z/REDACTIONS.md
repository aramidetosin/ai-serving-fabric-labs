# Redactions

Some recorded text in this result set was replaced after the set was recorded, with `common/audit/redact_tree.py`. Each replacement is the marker `[redacted: <class>]` on the line that held the text, so every line keeps its number and the rest of the line reads as recorded. Each file in the last table was cut to fewer lines, so its lines were renumbered: the table gives its length as recorded and the recorded numbers of the lines it kept, in order, the first of which is now line 1. This file names no replaced text.

| Class | What it replaced |
|---|---|
| host-cpuid | the CPU signature the PA-VM passes through from the lab host's processor (its vm-cpuid) |
| namecheck-summary | the set's saved namecheck output, cut to the lines the audit saves today (common/lib.sh audit_clean): its warn lines, each of which quoted the text it matched, are dropped, a fail line keeps its path, line, severity and kind but not its text, and the summary line is kept as recorded |

| File | Line | Class |
|---|---|---|
| commands.txt | 18211 | host-cpuid |
| fw/04_system_info.txt | 22 | host-cpuid |
| raw/fw-panos-cli-VVOhiE.txt | 47 | host-cpuid |

| File | Lines as recorded | Lines kept, by recorded number | Class |
|---|---|---|---|
| repo/namecheck.txt | 285 | 285 | namecheck-summary |
