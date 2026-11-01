## Top-25 CVE

This shows the top-25 vulnerabilities that have more than 50.00% chance of being exploited in the next 30 days.

### EPSS Priority Report (Top 25 of 3992 Total CVEs)

| CVE | Vulnerability | Percentage (Probability) | Percentile | CVSS Score |
| :-- | :------------ | :----------------------: | ---------: | :--------: |
| CVE-2026-93616 | Check Point Multiple Products Path Traversal Vulnerability | 91.61% | 99.81th | 9.8 |
| CVE-2026-9082 | Drupal Core SQL Injection Vulnerability | 89.38% | 99.78th | 9.8 |
| CVE-2026-88772 | Citrix NetScaler Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability | 78.16% | 99.58th | 8.1 |
| CVE-2026-88771 | Citrix NetScaler Improper Input Validation Vulnerability | 82.16% | 99.66th | 9.8 |
| CVE-2026-87902 | WordPress Core Remote File Inclusion Vulnerability | 95.77% | 99.87th | 8.1 |
| CVE-2026-85706 | GitLab Community Edition and Enterprise Edition Path Traversal Vulnerability | 97.36% | 99.90th | 10.0 |
| CVE-2026-85102 | Check Point Multiple Products Improper Certificate Validation Vulnerability | 54.14% | 99.01th | 9.8 |
| CVE-2026-82078 | PaperCut NG/MF Unsafe Reflection Vulnerability | 63.05% | 99.20th | 9.1 |
| CVE-2026-81578 | PaperCut NG/MF Missing Authentication for Critical Function Vulnerability | 84.73% | 99.71th | 9.8 |
| CVE-2026-8037 | Progress LoadMaster Command Injection Vulnerability | 99.79% | 99.96th | 9.6 |
| CVE-2026-76460 | Cisco Identity Services Engine Incorrect Use of Privileged APIs Vulnerability | 75.60% | 99.52th | 10.0 |
| CVE-2026-73570 | Zimbra Collaboration Suite (ZCS) OS Command Injection Vulnerability | 71.66% | 99.42th | 8.9 |
| CVE-2026-72898 | n/a | 98.81% | 99.93th | Error |
| CVE-2026-71362 | n/a | 90.49% | 99.80th | Error |
| CVE-2026-63077 | n/a | 93.56% | 99.84th | Error |
| CVE-2026-55040 | Microsoft SharePoint Weak Authentication Vulnerability | 69.54% | 99.36th | 9.1 |
| CVE-2026-50751 | Check Point Security Gateway Improper Authentication Vulnerability | 85.34% | 99.72th | 9.3 |
| CVE-2026-49160 | *Description: Uncontrolled resource consumption in HTTP/2 allows an unauthorized attacker to deny service over a network.* | 56.59% | 99.06th | 7.5 |
| CVE-2026-48908 | JoomShaper SP Page Builder Unrestricted Upload of File with Dangerous Type Vulnerability | 88.51% | 99.77th | 9.8 |
| CVE-2026-48907 | Widget Factory Joomla Content Editor Improper Access Control Vulnerability | 85.44% | 99.72th | 9.8 |
| CVE-2026-48710 | Kludex Starlette HTTP Request/Response Smuggling Vulnerability | 70.29% | 99.38th | 6.5 |
| CVE-2026-48558 | SimpleHelp Authentication Bypass Vulnerability | 77.66% | 99.56th | 10.0 |
| CVE-2026-45659 | Microsoft SharePoint Server Deserialization of Untrusted Data Vulnerability | 80.24% | 99.62th | 8.8 |
| CVE-2026-45498 | Microsoft Defender Denial of Service Vulnerability | 63.08% | 99.20th | 4.0 |
| CVE-2026-43500 | *Description: In the Linux kernel, the following vulnerability has been resolved:

rxrpc: Also unshare DATA/RESPONSE packets when paged frags are present

The DATA-packet handler in rxrpc_input_call_event() and the RESPONSE
handler in rxrpc_verify_response() copy the skb to a linear one before
calling into the security ops only when skb_cloned() is true.  An skb
that is not cloned but still carries externally-owned paged fragments
(e.g. SKBFL_SHARED_FRAG set by splice() into a UDP socket via
__ip_append_data, or a chained skb_has_frag_list()) falls through to
the in-place decryption path, which binds the frag pages directly into
the AEAD/skcipher SGL via skb_to_sgvec().

Extend the gate to also unshare when skb_has_frag_list() or
skb_has_shared_frag() is true.  This catches the splice-loopback vector
and other externally-shared frag sources while preserving the
zero-copy fast path for skbs whose frags are kernel-private (e.g. NIC
page_pool RX, GRO).  The OOM/trace handling already in place is reused.* | 94.12% | 99.85th | 7.8 |

*Last update:* ***2026-11-01*** *(completed in 11.7748s)*
