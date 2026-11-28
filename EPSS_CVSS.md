## Top-25 CVE

This shows the top-25 vulnerabilities that have more than 50.00% chance of being exploited in the next 30 days.

### EPSS Priority Report (Top 25 of 3420 Total CVEs)

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
will be addressed in a separate patch.* | 84.84% | 99.80th | 9.8 |
| CVE-2026-97229 | GitLab Community Edition and Enterprise Edition Integer Overflow or Wraparound Vulnerability | 74.31% | 99.64th | 10.0 |
| CVE-2026-93616 | Check Point Multiple Products Path Traversal Vulnerability | 91.61% | 99.88th | 9.8 |
| CVE-2026-8037 | Progress LoadMaster Command Injection Vulnerability | 70.02% | 99.55th | 9.6 |
| CVE-2026-59310 | Broadcom VMware vCenter Path Traversal Vulnerability | 88.46% | 99.85th | 9.8 |
| CVE-2026-56291 | Balbooa Forms Unrestricted Upload of File with Dangerous Type Vulnerability | 81.42% | 99.75th | 9.8 |
| CVE-2026-48939 | iCagenda Unrestricted Upload of File with Dangerous Type Vulnerability | 91.20% | 99.88th | 9.8 |
| CVE-2026-41089 | *Description: Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.* | 78.33% | 99.71th | 9.8 |
| CVE-2026-16232 | Check Point SmartConsole Improper Authentication Vulnerability | 78.94% | 99.72th | 9.8 |
| CVE-2026-123158 | OpenBSD OpenSSH Unexpected Status Code or Return Value Vulnerability | 89.63% | 99.86th | 8.1 |
| CVE-2026-115560 | *Description: Session serializer mismatch can lead to remote code execution.

Session upload progress, when enabled, can store attacker-controlled data in a session key using the php_binary or php_serialize session serializer. If the same session is later read with the php serializer, because session.serialize_handler is changed at runtime or differs between applications sharing a session store, bytes inside the key can be passed to the unserializer. A remote attacker able to submit a multipart upload can inject objects, which may lead to code execution when the reading application contains a suitable gadget chain, or to session corruption or denial of service.

This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.* | 86.58% | 99.83th | 0.0 |
| CVE-2026-114938 | *Description: Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3 and  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).* | 72.54% | 99.60th | 8.1 |
| CVE-2026-111497 | n/a | 99.99% | 99.99th | Error |
| CVE-2026-110264 | n/a | 54.05% | 99.25th | Error |
| CVE-2026-10520 | n/a | 61.05% | 99.37th | Error |
| CVE-2026-105134 | n/a | 54.97% | 99.27th | Error |
| CVE-2025-59528 | n/a | 53.57% | 99.24th | Error |
| CVE-2025-5777 | n/a | 99.92% | 99.98th | Error |
| CVE-2025-55182 | n/a | 53.81% | 99.25th | Error |
| CVE-2025-53770 | n/a | 86.53% | 99.82th | Error |
| CVE-2025-49132 | n/a | 58.49% | 99.33th | Error |
| CVE-2025-49113 | n/a | 72.80% | 99.61th | Error |
| CVE-2025-47916 | n/a | 59.28% | 99.34th | Error |
| CVE-2025-47812 | n/a | 60.23% | 99.36th | Error |
| CVE-2025-4427 | n/a | 69.19% | 99.53th | Error |

*Last update:* ***2026-11-28*** *(completed in 10.4680s)*
