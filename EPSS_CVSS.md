## Top-25 CVE

This shows the top-25 vulnerabilities that have more than 50.00% chance of being exploited in the next 30 days.

### EPSS Priority Report (Top 25 of 4117 Total CVEs)

| CVE | Vulnerability | Percentage (Probability) | Percentile | CVSS Score |
| :-- | :------------ | :----------------------: | ---------: | :--------: |
| CVE-2026-98432 | *Description: In the Linux kernel, the following vulnerability has been resolved:

ipv4: free inet_opt and ireq_opt after an RCU grace period

tcp_v4_syn_recv_sock() transfers ownership of ireq->ireq_opt to the
child socket (newinet->inet_opt) without copying it.

Another cpu can concurrently process a retransmitted SYN for the same
request socket, and send a SYNACK from tcp_check_req().
tcp_v4_send_synack() and inet_csk_route_req() read ireq->ireq_opt
under rcu_read_lock() only, and ip_build_and_send_pkt() and
ip_options_build() then read opt->optlen twice.

Note that the SYNACK timer itself is not an issue: it holds a
reference on its request socket, and inet_csk_reqsk_queue_drop()
calls timer_delete_sync() before the child can be freed.

Since commit 079096f103fa ("tcp/dccp: install syn_recv requests
into ehash table"), request sockets are processed without holding
the listener lock, so nothing prevents the child socket from being
freed while the SYNACK is still being built. TCP child sockets do
not have SOCK_RCU_FREE, and inet_sock_destruct() frees inet_opt
with a plain kfree(), leading to a use-after-free in
ip_options_build().

A similar issue exists with request socket migration
(net.ipv4.tcp_migrate_req=1, or a BPF_SK_REUSEPORT_SELECT_OR_MIGRATE
program). reqsk_timer_handler() clones the request socket with
inet_reqsk_clone(), so that the old request socket and its clone
share the same ireq_opt, then reqsk_migrate_reset() clears the
pointer in the old one. Another cpu holding a reference on the old
request socket can still be using these options (sending a SYNACK,
or creating a child in tcp_v4_syn_recv_sock()) when the clone is
freed, and tcp_v4_reqsk_destructor() also uses a plain kfree().

Readers already use RCU, and other paths replacing inet_opt
(do_ip_setsockopt(), cipso_v4_sock_setattr()...) already use
kfree_rcu(). Use kfree_rcu() in inet_sock_destruct() and
tcp_v4_reqsk_destructor() as well.

IPv6 is not affected by the first issue, because tcp_v6_syn_recv_sock()
duplicates the options. tcp_v6_reqsk_destructor() has the same
migration issue with ipv6_opt, which is only set by CALIPSO. This
will be addressed in a separate patch.* | 82.13% | 99.66th | 9.8 |
| CVE-2026-97229 | GitLab Community Edition and Enterprise Edition Integer Overflow or Wraparound Vulnerability | 74.31% | 99.50th | 10.0 |
| CVE-2026-93616 | Check Point Multiple Products Path Traversal Vulnerability | 91.61% | 99.82th | 9.8 |
| CVE-2026-9082 | Drupal Core SQL Injection Vulnerability | 89.38% | 99.79th | 9.8 |
| CVE-2026-88772 | Citrix NetScaler Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability | 76.57% | 99.55th | 8.1 |
| CVE-2026-88771 | Citrix NetScaler Improper Input Validation Vulnerability | 81.89% | 99.66th | 9.8 |
| CVE-2026-87902 | WordPress Core Remote File Inclusion Vulnerability | 95.77% | 99.87th | 8.1 |
| CVE-2026-85706 | GitLab Community Edition and Enterprise Edition Path Traversal Vulnerability | 97.36% | 99.90th | 10.0 |
| CVE-2026-85102 | Check Point Multiple Products Improper Certificate Validation Vulnerability | 54.14% | 99.03th | 9.8 |
| CVE-2026-82078 | PaperCut NG/MF Unsafe Reflection Vulnerability | 60.89% | 99.17th | 9.1 |
| CVE-2026-81578 | PaperCut NG/MF Missing Authentication for Critical Function Vulnerability | 84.29% | 99.70th | 9.8 |
| CVE-2026-8037 | Progress LoadMaster Command Injection Vulnerability | 99.79% | 99.96th | 9.6 |
| CVE-2026-76460 | n/a | 75.60% | 99.53th | Error |
| CVE-2026-75650 | n/a | 99.38% | 99.94th | Error |
| CVE-2026-73570 | n/a | 76.62% | 99.55th | Error |
| CVE-2026-72898 | n/a | 98.51% | 99.92th | Error |
| CVE-2026-71362 | n/a | 91.68% | 99.82th | Error |
| CVE-2026-6875 | n/a | 78.46% | 99.59th | Error |
| CVE-2026-63077 | n/a | 93.94% | 99.85th | Error |
| CVE-2026-61511 | n/a | 74.27% | 99.50th | Error |
| CVE-2026-59310 | n/a | 61.67% | 99.19th | Error |
| CVE-2026-55040 | n/a | 69.54% | 99.38th | Error |
| CVE-2026-5430 | n/a | 78.84% | 99.60th | Error |
| CVE-2026-50751 | n/a | 85.35% | 99.72th | Error |
| CVE-2026-50522 | n/a | 81.87% | 99.66th | Error |

*Last update:* ***2026-11-23*** *(completed in 10.2572s)*
