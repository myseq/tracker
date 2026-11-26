## Top-25 CVE

This shows the top-25 vulnerabilities that have more than 50.00% chance of being exploited in the next 30 days.

### EPSS Priority Report (Top 25 of 3412 Total CVEs)

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
| CVE-2026-8037 | Progress LoadMaster Command Injection Vulnerability | 70.02% | 99.55th | 9.6 |
| CVE-2026-59310 | Broadcom VMware vCenter Path Traversal Vulnerability | 88.46% | 99.85th | 9.8 |
| CVE-2026-56291 | Balbooa Forms Unrestricted Upload of File with Dangerous Type Vulnerability | 81.42% | 99.75th | 9.8 |
| CVE-2026-48939 | iCagenda Unrestricted Upload of File with Dangerous Type Vulnerability | 91.20% | 99.88th | 9.8 |
| CVE-2026-41089 | *Description: Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.* | 78.33% | 99.71th | 9.8 |
| CVE-2026-16232 | Check Point SmartConsole Improper Authentication Vulnerability | 80.11% | 99.74th | 9.8 |
| CVE-2026-115560 | *Description: Session serializer mismatch can lead to remote code execution.

Session upload progress, when enabled, can store attacker-controlled data in a session key using the php_binary or php_serialize session serializer. If the same session is later read with the php serializer, because session.serialize_handler is changed at runtime or differs between applications sharing a session store, bytes inside the key can be passed to the unserializer. A remote attacker able to submit a multipart upload can inject objects, which may lead to code execution when the reading application contains a suitable gadget chain, or to session corruption or denial of service.

This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.* | 86.58% | 99.83th | 0.0 |
| CVE-2026-114938 | *Description: Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3 and  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).* | 59.27% | 99.34th | 8.1 |
| CVE-2026-10520 | Ivanti Sentry OS Command Injection Vulnerability | 61.05% | 99.37th | 10.0 |
| CVE-2026-105134 | Ahsay AhsayCBS Command Injection Vulnerability | 54.97% | 99.27th | 10.0 |
| CVE-2025-59528 | *Description: Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.* | 53.57% | 99.24th | 10.0 |
| CVE-2025-5777 | Citrix NetScaler ADC and Gateway Out-of-Bounds Read Vulnerability | 99.92% | 99.98th | 7.5 |
| CVE-2025-55182 | Meta React Server Components Remote Code Execution Vulnerability | 53.81% | 99.25th | 10.0 |
| CVE-2025-53770 | Microsoft SharePoint Deserialization of Untrusted Data Vulnerability | 86.53% | 99.83th | 9.8 |
| CVE-2025-49132 | *Description: Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.* | 58.49% | 99.33th | 10.0 |
| CVE-2025-49113 | RoundCube Webmail Deserialization of Untrusted Data Vulnerability | 72.80% | 99.61th | 9.9 |
| CVE-2025-47916 | *Description: Invision Community 5.0.0 before 5.0.7 allows remote code execution via crafted template strings to themeeditor.php. The issue lies within the themeeditor controller (file: /applications/core/modules/front/system/themeeditor.php), where a protected method named customCss can be invoked by unauthenticated users. This method passes the value of the content parameter to the Theme::makeProcessFunction() method; hence it is evaluated by the template engine. Accordingly, this can be exploited by unauthenticated attackers to inject and execute arbitrary PHP code by providing crafted template strings.* | 59.28% | 99.34th | 10.0 |
| CVE-2025-47812 | Wing FTP Server Improper Neutralization of Null Byte or NUL Character Vulnerability | 60.23% | 99.36th | 10.0 |
| CVE-2025-4427 | Ivanti Endpoint Manager Mobile (EPMM) Authentication Bypass Vulnerability | 69.19% | 99.53th | 5.3 |
| CVE-2025-34117 | *Description: A remote code execution vulnerability exists in multiple Netcore and Netis routers models with firmware released prior to August 2014 due to the presence of an undocumented backdoor listener on UDP port 53413. Exact version boundaries remain undocumented. An unauthenticated remote attacker can send specially crafted UDP packets to execute arbitrary commands on the affected device. This backdoor uses a hardcoded authentication mechanism and accepts shell commands post-authentication. Some device models include a non-standard implementation of the `echo` command, which may affect exploitability.* | 69.35% | 99.54th | 0.0 |
| CVE-2025-34037 | *Description: An OS command injection vulnerability exists in various models of E-Series Linksys routers via the /tmUnblock.cgi and /hndUnblock.cgi endpoints over HTTP on port 8080. The CGI scripts improperly process user-supplied input passed to the ttcp_ip parameter without sanitization, allowing unauthenticated attackers to inject shell commands. This vulnerability was reported to be exploited in the wild by the "TheMoon" worm  in 2014 to deploy a MIPS ELF payload, enabling arbitrary code execution on the router. Additionally, this vulnerability may affect other Linksys products to include, but not limited to, WAG/WAP/WES/WET/WRT-series router models and Wireless-N access points and routers. Exploitation evidence was observed by the Shadowserver Foundation on 2025-02-06 UTC.* | 54.36% | 99.26th | 0.0 |
| CVE-2025-3248 | n/a | 80.62% | 99.74th | Error |
| CVE-2025-32432 | n/a | 66.27% | 99.47th | Error |
| CVE-2025-31161 | n/a | 60.72% | 99.37th | Error |

*Last update:* ***2026-11-26*** *(completed in 10.1038s)*
