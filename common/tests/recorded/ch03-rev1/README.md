# Two PA-VM outputs from chapter 3's revision 1 recording

Copied byte for byte on 2026-10-29 from chapter 3's revision 1 result sets when they left the repository (`ch03/audits/INDEX.md`, "Superseded sets"), so that the parsers' tests keep reading the PA-VM 12.1.2's own output:

| File | From |
|---|---|
| `fw-traffic-log.txt` | `ch03/audits/sfab-ch03_trace_20261020T171802Z/fw-traffic-log.txt` |
| `12_running_nat.txt` | `ch03/audits/sfab-ch03_audit_20261020T165906Z/fw/12_running_nat.txt` |

They carry revision 1's rule names and addresses. `common/tests/test_ch04.py` reads them through `common/audit/panos_parse.py`.
