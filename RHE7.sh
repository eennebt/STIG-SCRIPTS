#!/bin/sh


echo "V-100023" > RHE7findings.txt
echo "Rule: The Red Hat Enterprise Linux operating system must disable the graphical user interface automounter unless required" >> RHE7findings.txt
echo "Discussion: Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
cat /etc/dconf/db/local.d/00-No-Automount &> RHE7findings.txt 
cat /etc/dconf/db/local.d/locks/00-No-Automount &>> RHE7findings.txt 
echo "Group Title: SRG-OS-000114-GPOS-00059" >> RHE7findings.txt
echo "Finding: if the output does not match the example above, this is a  finding." >> RHE7findings.txt
echo "Finding: If the output does not match the example, this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt


echo "V-94843" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule: The Red Hat Enterprise Linux operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled in the Graphical User Interface." >> RHE7findings.txt
echo "Discussion: A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
grep logout /etc/dconf/db/local.d/* &>> RHE7findings.txt 
echo "Finding: If logout is not set to use two single quotations, or is missing, this is a finding." >> RHE7findings.txt
grep logout /etc/dconf/db/local.d/* &>> RHE7findings.txt 
echo "Finding: If logout is not set to use two single quotations, or is missing, this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt

echo "V-92255" >> RHE7findings.txt
echo "Group Title: SRG-OS-000196" >> RHE7findings.txt
echo "Rule: The Red Hat Enterprise Linux operating system must have a host-based intrusion detection tool installed." >> RHE7findings.txt
echo "Discussion: Adding host-based intrusion detection tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of the system, which may not otherwise exist in an organizations systems management regime. " >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
rpm -qa | grep MFEhiplsm &>> RHE7findings.txt
echo "Finding: Verify that the McAfee HIPS module is active on the system:" >> RHE7findings.txt
ps -ef | grep -i “hipclient” &>> RHE7findings.txt
echo "Finding: If the MFEhiplsm package is not installed, check for another intrusion detection system:" >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt


echo "V-92253" >> RHE7findings.txt
echo "Group Title:SRG-OS-000480-GPOS-00227 " >> RHE7findings.txt
echo "Rule: The Red Hat Enterprise Linux operating system must use a reverse-path filter for IPv4 network traffic when possible by default." >> RHE7findings.txt
echo "Discussion: Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
grep net.ipv4.conf.default.rp_filter /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
echo "Finding: If net.ipv4.conf.default.rp_filter is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of 1, this is a finding." >> RHE7findings.txt
/sbin/sysctl -a | grep net.ipv4.conf.default.rp_filter &>> RHE7findings.txt
echo"Finding: If the returned line does not have a value of 1, this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt


echo "V-92251" >> RHE7findings.txt
echo "Finding: If the returned line does not have a value of 1, this is a finding." >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227 " >> RHE7findings.txt
echo "Rule:  The Red Hat Enterprise Linux operating system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces." >> RHE7findings.txt
echo "Discussion: Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
grep net.ipv4.conf.all.rp_filter /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
echo "Finding: If net.ipv4.conf.all.rp_filter is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of 1, this is a finding." >> RHE7findings.txt
/sbin/sysctl -a | grep net.ipv4.conf.all.rp_filter &>> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt




echo "V-81021" >> RHE7findings.txt
echo "Group Title: SRG-OS-000342-GPOS-00133 " >> RHE7findings.txt
echo "Rule: The Red Hat Enterprise Linux operating system must label all off-loaded audit logs before sending them to the central log server." >> RHE7findings.txt
echo "Discussion:rmation stored in one location is vulnerable to accidental or incidental deletion or alteration.
Off-loading is a common process in information systems with limited audit storage capacity.
When audit logs are not labeled before they are sent to a central log server, the audit data will not be able to be analyzed and tied back to the correct system." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
grep "name_format" /etc/audisp/audispd.conf &>> RHE7findings.txt
echo "Finding: If the name_format option is not hostname, fqd, or numeric, or the line is commented out, this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt


echo "V-81019" >> RHE7findings.txt
echo "Group Title: " >> RHE7findings.txt
echo "Rule:  The Red Hat Enterprise Linux operating system must take appropriate action when the audisp-remote buffer is full." >> RHE7findings.txt
echo "Discussion: Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
Off-loading is a common process in information systems with limited audit storage capacity.
When the remote buffer is full, audit logs will not be collected and sent to the central log server." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
grep "overflow_action" /etc/audisp/audispd.conf &>> RHE7findings.txt
echo "Finding: If the 'overflow_action' option is not 'syslog', 'single' or 'halt', or the line is commented out, this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt



echo "V-81017" >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
cat /etc/audisp/plugins.d/au-remote.conf | grep -v "^#" &>> RHE7findings.txt
echo "Finding: If the 'direction' setting is not set to 'out', or the line is commented out, this is a finding.
If the 'path' setting is not set to '/sbin/audisp-remote', or the line is commented out, this is a finding.
If the 'type' setting is not set to 'always', or the line is commented out, this is a finding" >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt


echo "V-81015" >> RHE7findings.txt
echo "Group Title: SRG-OS-000342-GPOS-00133" >> RHE7findings.txt
echo "Rule: The Red Hat Enterprise Linux operating system must configure the au-remote plugin to off-load audit logs using the audisp-remote daemon." >> RHE7findings.txt
echo "Discussion: Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
Off-loading is a common process in information systems with limited audit storage capacity.
Without the configuration of the 'au-remote' plugin, the audisp-remote daemon will not off load the logs from the system being audited." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
grep "active" /etc/audisp/plugins.d/au-remote.conf &>> RHE7findings.txt
echo "Finding: If the 'active' setting is not set to 'yes', or the line is commented out, this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt


echo "V-81013" >> RHE7findings.txt
echo "Group Title: SRG-OS-000342-GPOS-00133 " >> RHE7findings.txt
echo "Rule:  The Red Hat Enterprise Linux operating system must be configured to use the au-remote plugin." >> RHE7findings.txt
echo "Discussion: Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
Off-loading is a common process in information systems with limited audit storage capacity.
Without the configuration of the 'au-remote' plugin, the audisp-remote daemon will not off-load the logs from the system being audited." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
cat /etc/fstab | grep /dev/shm &>> RHE7findings.txt
echo "Finding: If any results are returned and the 'noexec' option is not listed, this is a finding." >> RHE7findings.txt
mount | grep "/dev/shm" | grep noexec &>> RHE7findings.txt
echo "Finding: If no results are returned, this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt



echo "V-81011" >> RHE7findings.txt
echo "Group Title: SRG-OS-000368-GPOS-00154" >> RHE7findings.txt
echo "Rule: The Red Hat Enterprise Linux operating system must mount /dev/shm with the noexec option." >> RHE7findings.txt
echo "Discussion: The 'noexec' mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
cat /etc/fstab | grep /dev/shm &>> RHE7findings.txt
echo "Finding: If any results are returned and the "nosuid" option is not listed, this is a finding." >> RHE7findings.txt
mount | grep "/dev/shm" | grep nosuid &>> RHE7findings.txt
echo "Finding: If no results are returned, this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt


echo "V-81009" >> RHE7findings.txt
echo "Group Title: SRG-OS-000368-GPOS-00154" >> RHE7findings.txt
echo "Rule: The Red Hat Enterprise Linux operating system must mount /dev/shm with the nosuid option." >> RHE7findings.txt
echo "Discussion: The 'nosuid' mount option causes the system to not execute 'setuid' and 'setgid' files with owner privileges. This option must be used for mounting any file system not containing approved 'setuid' and 'setguid' files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
cat /etc/fstab | grep /dev/shm &>> RHE7findings.txt
echo "Finding: If any results are returned and the "nodev" option is not listed, this is a finding." >> RHE7findings.txt
mount | grep "/dev/shm" | grep nodev &>> RHE7findings.txt
echo "Finding: If no results are returned, this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt

echo "V-81007" >> RHE7findings.txt
echo "Group Title:SRG-OS-000368-GPOS-00154" >> RHE7findings.txt
echo "Rule: The Red Hat Enterprise Linux operating system must mount /dev/shm with the nodev option." >> RHE7findings.txt
echo "Discussion: The 'nodev' mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg &>> RHE7findings.txt
echo "Finding: If the root password does not begin with 'grub.pbkdf2.sha512', this is a finding. " >> RHE7findings.txt
grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg &>> RHE7findings.txt
echo "Finding: If 'superusers' is not set to 'root', this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt



echo "V-81005" >> RHE7findings.txt
echo "Group Title: SRG-OS-000080-GPOS-00048" >> RHE7findings.txt
echo "Rule: Red Hat Enterprise Linux operating systems version 7.2 or newer with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes." >> RHE7findings.txt
echo "Discussion: If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
grep -iw grub2_password /boot/grub2/user.cfg &>> RHE7findings.txt
echo "Finding: If the root password does not begin with 'grub.pbkdf2.sha512', this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
grep -iw "superusers" /boot/grub2/grub.cfg &>> RHE7findings.txt
echo "Finding: If 'superusers' is not set to 'root', this is a finding" >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt


echo "V-81003" >> RHE7findings.txt
echo "Group Title: SRG-OS-000069-GPOS-00037" >> RHE7findings.txt
echo "Rule: The Red Hat Enterprise Linux operating system must be configured so that /etc/pam.d/passwd implements /etc/pam.d/system-auth when changing passwords." >> RHE7findings.txt
echo "Discussion: Pluggable authentication modules (PAM) allow for a modular approach to integrating authentication methods. PAM operates in a top-down processing model and if the modules are not listed in the correct order, an important security function could be bypassed if stack entries are not centralized." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt
cat /etc/pam.d/passwd | grep -i substack | grep -i system-auth &>> RHE7findings.txt
echo "Finding: If no results are returned, the line is commented out, this is a finding." >> RHE7findings.txt
echo "|--------------------------------------------------------|" >> RHE7findings.txt




echo "V-79001" >> RHE7findings.txt
echo "Group Title: SRG-OS-000471-GPOS-00216" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the finit_module syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw finit_module /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'finit_module' syscall, this is a finding." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-78999" >> RHE7findings.txt
echo "Group Title: SRG-OS-000471-GPOS-00216 " >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the create_module syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. " >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw create_module /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'create_module' syscall, this is a finding." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-78997" >> RHE7findings.txt
echo "Group Title: SRG-OS-000029-GPOS-00010" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver idle-activation-enabled setting for the graphical user interface." >> RHE7findings.txt
echo "Discussion: A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.
The session lock is implemented at the point where session activity can be determined.
The ability to enable/disable a session lock is given to the user by default. Disabling the user's ability to disengage the graphical user interface session lock provides the assurance that all sessions will lock after the specified period of time." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep system-db /etc/dconf/profile/user &>> RHE7findings.txt
echo "Finding: Check for the idle-activation-enabled setting with the following command" 
grep -i idle-activation-enabled /etc/dconf/db/local.d/locks/* &>> RHE7findings.txt
echo "Finding: If the command does not return a result, this is a finding. " >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-78995" >> RHE7findings.txt
echo "Group Title: SRG-OS-000029-GPOS-00010" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface." >> RHE7findings.txt
echo "Discussion: A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.
The session lock is implemented at the point where session activity can be determined.
The ability to enable/disable a session lock is given to the user by default. Disabling the user’s ability to disengage the graphical user interface session lock provides the assurance that all sessions will lock after the specified period of time." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep system-db /etc/dconf/profile/user &>> RHE7findings.txt
echo "Finding: Check for the lock-enabled setting with the following command:" 
grep -i lock-enabled /etc/dconf/db/local.d/locks/* &>> RHE7findings.txt
echo "Finding: If the command does not return a result, this is a finding." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-77825" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must implement virtual address space randomization." >> RHE7findings.txt
echo "Discussion: Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code he or she has introduced into a process's address space during an attempt at exploitation. Additionally, ASLR also makes it more difficult for an attacker to know the location of existing code in order to repurpose it using return-oriented programming (ROP) techniques." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep kernel.randomize_va_space /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
echo "Finding: If 'kernel.randomize_va_space' is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of '2', this is a finding." 
/sbin/sysctl -a | grep kernel.randomize_va_space &>> RHE7findings.txt
echo "Finding: If 'kernel.randomize_va_space' does not have a value of '2', this is a finding." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-77823" >> RHE7findings.txt
echo "Group Title: SRG-OS-000080-GPOS-00048" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must require authentication upon booting into single-user and maintenance modes." >> RHE7findings.txt
echo "Discussion: If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i execstart /usr/lib/systemd/system/rescue.service | grep -i sulogin &>> RHE7findings.txt
echo "Finding: If 'ExecStart' does not have '/usr/sbin/sulogin' as an option, this is a finding." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-77821" >> RHE7findings.txt
echo "Group Title: SRG-OS-000378-GPOS-00163" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the Datagram Congestion Control Protocol (DCCP) kernel module is disabled unless required." >> RHE7findings.txt
echo "Discussion: Disabling DCCP protects the system against exploitation of any flaws in the protocol implementation." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -r dccp /etc/modprobe.d/* | grep -i "/bin/true" | grep -v "^#" &>> RHE7findings.txt
echo "Finding: If the command does not return any output, or the line is commented out, and use of DCCP is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding." >> RHE7findings.txt

grep -i dccp /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#" &>> RHE7findings.txt
echo "Finding: If the command does not return any output or the output is not 'blacklist dccp', and use of the dccp kernel module is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-77819" >> RHE7findings.txt
echo "Group Title:SRG-OS-000375-GPOS-00160" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must uniquely identify and must authenticate users using multifactor authentication via a graphical user logon." >> RHE7findings.txt
echo "Discussion: To assure accountability and prevent unauthenticated access, users must be identified and authenticated to prevent potential misuse and compromise of the system.
Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep system-db /etc/dconf/profile/user &>> RHE7findings.txt
echo "Finding: Note: The example is using the database local for the system, so the path is '/etc/dconf/db/local.d'. This path must be modified if a database other than local is being used." >> RHE7findings.txt
grep enable-smartcard-authentication /etc/dconf/db/local.d/* &>> RHE7findings.txt
echo "Finding: If 'enable-smartcard-authentication' is set to 'false' or the keyword is missing, this is a finding. " >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-73177" >> RHE7findings.txt
echo "Group Title:SRG-OS-000424-GPOS-00188" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all wireless network adapters are disabled." >> RHE7findings.txt
echo "Discussion: The use of wireless networking can introduce many different attack vectors into the organization's network. Common attack vectors such as malicious association and ad hoc networks will allow an attacker to spoof a wireless access point (AP), allowing validated systems to connect to the malicious AP and enabling the attacker to monitor and record network traffic. These malicious APs can also serve to create a man-in-the-middle attack or be used to create a denial of service to valid network resources." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
nmcli device &>> RHE7findings.txt
echo "Finding: If a wireless interface is configured and its use on the system is not documented with the Information System Security Officer (ISSO), this is a finding." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-73175" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages." >> RHE7findings.txt
echo "Discussion: ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep 'net.ipv4.conf.all.accept_redirects' /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
echo "Finding: If ' net.ipv4.conf.all.accept_redirects ' is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of '0', this is a finding." >> RHE7findings.txt
/sbin/sysctl -a | grep 'net.ipv4.conf.all.accept_redirects' &>> RHE7findings.txt
echo "Finding: If the returned line does not have a value of "0", this is a finding." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-73173" >> RHE7findings.txt
echo "Group Title: SRG-OS-000004-GPOS-00004" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep /etc/security/opasswd /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return a line, or the line is commented out, this is a finding." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt



echo "V-73171" >> RHE7findings.txt
echo "Group Title: SRG-OS-000004-GPOS-00004" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep /etc/shadow /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return a line, or the line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-73167" >> RHE7findings.txt
echo "Group Title: SRG-OS-000004-GPOS-00004" >> RHE7findings.txt
echo "Rule Title:  The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep /etc/gshadow /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return a line, or the line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V- 73165" >> RHE7findings.txt
echo "Group Title: SRG-OS-000004-GPOS-00004" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep /etc/group /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return a line, or the line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-73163" >> RHE7findings.txt
echo "Group Title: SRG-OS-000342-GPOS-00133" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the audit system takes appropriate action when there is an error sending audit records to a remote system." >> RHE7findings.txt
echo "Discussion: Taking appropriate action when there is an error sending audit records to a remote system will minimize the possibility of losing audit records." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i network_failure_action /etc/audisp/audisp-remote.conf &>> RHE7findings.txt
echo "Finding: If the value of the 'network_failure_action' option is not 'syslog', 'single', or 'halt', or the line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-73161" >> RHE7findings.txt
echo "Group Title:SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must prevent binary files from being executed on file systems that are being imported via Network File System (NFS)." >> RHE7findings.txt
echo "Discussion: The 'noexec' mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
more /etc/fstab | grep nfs &>> RHE7findings.txt
echo "Finding: If a file system found in '/etc/fstab' refers to NFS and it does not have the 'noexec' option set, and use of NFS imported binaries is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding." >> RHE7findings.txt 
mount | grep nfs | grep noexec &>> RHE7findings.txt
echo "Finding: If no results are returned and use of NFS imported binaries is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-73159" >> RHE7findings.txt
echo "Group Title: SRG-OS-000069-GPOS-00037" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, pwquality must be used." >> RHE7findings.txt
echo "Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 'pwquality' enforces complex password construction configuration and has the ability to limit brute-force attacks on the system." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
cat /etc/pam.d/system-auth | grep pam_pwquality &>> RHE7findings.txt
echo "Finding: If the command does not return an uncommented line containing the value 'pam_pwquality.so', this is a finding.
If the value of 'retry' is set to '0' or greater than '3', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-73157" >> RHE7findings.txt
echo "Group Title: SRG-OS-000029-GPOS-00010" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must prevent a user from overriding the session idle-delay setting for the graphical user interface." >> RHE7findings.txt
echo "Discussion: A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep system-db /etc/dconf/profile/user &>> RHE7findings.txt
echo "Finding: Note: The example below is using the database 'local' for the system, so the path is '/etc/dconf/db/local.d'. This path must be modified if a database other than 'local' is being used." >> RHE7findings.txt 
grep -i idle-delay /etc/dconf/db/local.d/locks/* &>> RHE7findings.txt
echo "Finding: If the command does not return a result, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-73155" >> RHE7findings.txt
echo "Group Title:SRG-OS-000029-GPOS-00010" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver lock-delay setting for the graphical user interface." >> RHE7findings.txt
echo "Discussion: A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep system-db /etc/dconf/profile/user &>> RHE7findings.txt
echo "Finding: " >> RHE7findings.txt 
grep -i lock-delay /etc/dconf/db/local.d/locks/ *&>> RHE7findings.txt
echo "Finding: If the command does not return a result, this is a finding. " >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72433" >> RHE7findings.txt
echo "Group Title: SRG-OS-000375-GPOS-00160" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must implement certificate status checking for PKI authentication." >> RHE7findings.txt
echo "Discussion: Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.
Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.
A privileged account is defined as an information system account with authorizations of a privileged user.
Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep -v "^#" &>> RHE7findings.txt
echo "Finding: If 'ocsp_on' is not present in all uncommented 'cert_policy' lines in '/etc/pam_pkcs11/pam_pkcs11.conf', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72427" >> RHE7findings.txt
echo "Group Title: SRG-OS-000375-GPOS-00160" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must implement multifactor authentication for access to privileged accounts via pluggable authentication modules (PAM)." >> RHE7findings.txt
echo "Discussion: Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.
Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.
A privileged account is defined as an information system account with authorizations of a privileged user.
Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep services /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf &>> RHE7findings.txt
echo "Finding: If the 'pam' service is not present on all 'services' lines, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72417" >> RHE7findings.txt
echo "Group Title: SRG-OS-000375-GPOS-00160" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must have the required packages for multifactor authentication installed." >> RHE7findings.txt
echo "Discussion: 
Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.
Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.
A privileged account is defined as an information system account with authorizations of a privileged user.
Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed pam_pkcs11 &>> RHE7findings.txt
echo "Finding: If the 'pam_pkcs11' package is not installed, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72319" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not forward IPv6 source-routed packets." >> RHE7findings.txt
echo "Discussion: Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the system is functioning as a router." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep net.ipv6.conf.all.accept_source_route /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
echo "Finding: If 'net.ipv6.conf.all.accept_source_route' is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of '0', this is a finding." >> RHE7findings.txt 
/sbin/sysctl -a | grep net.ipv6.conf.all.accept_source_route >> RHE7findings.txt
echo "Finding: If the returned lines do not have a value of "0", this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72317" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not have unauthorized IP tunnels configured." >> RHE7findings.txt
echo "Discussion: IP tunneling mechanisms can be used to bypass network filtering. If tunneling is required, it must be documented with the Information System Security Officer (ISSO)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed libreswan &>> RHE7findings.txt
systemctl status ipsec &>> RHE7findings.txt
grep -iw conn /etc/ipsec.conf /etc/ipsec.d/*.conf &>> RHE7findings.txt
echo "Finding: If 'libreswan' is installed, 'IPsec' is active, and an undocumented tunnel is active, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72315" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system access control program must be configured to grant or deny system access to specific hosts and services." >> RHE7findings.txt
echo "Discussion: If the systems access control program is not configured with appropriate rules for allowing and denying access to system network resources, services may be accessible to unauthorized hosts." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
systemctl status firewalld &>> RHE7findings.txt
firewall-cmd --get-default-zone &>> RHE7findings.txt
firewall-cmd --list-all --zone=public &>> RHE7findings.txt
ls -al /etc/hosts.allow &>> RHE7findings.txt
ls -al /etc/hosts.deny &>> RHE7findings.txt
echo "Finding: If 'firewalld' is active and is not configured to grant access to specific hosts or 'tcpwrappers' is not configured to grant or deny access to specific hosts, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72313" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: SNMP community strings on the Red Hat Enterprise Linux operating system must be changed from the default." >> RHE7findings.txt
echo "Discussion: Whether active or not, default Simple Network Management Protocol (SNMP) community strings must be changed to maintain security. If the service is running with the default authenticators, anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s). It is highly recommended that SNMP version 3 user authentication and message encryption be used in place of the version 2 community strings." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
ls -al /etc/snmp/snmpd.conf &>> RHE7findings.txt
grep public /etc/snmp/snmpd.conf &>> RHE7findings.txt
grep private /etc/snmp/snmpd.conf &>> RHE7findings.txt
echo "Finding: If either of these commands returns any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72311" >> RHE7findings.txt
echo "Group Title:  SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the Network File System (NFS) is configured to use RPCSEC_GSS." >> RHE7findings.txt
echo "Discussion: When an NFS server is configured to use RPCSEC_SYS, a selected userid and groupid are used to handle requests from the remote user. The userid and groupid could mistakenly or maliciously be set incorrectly. The RPCSEC_GSS method of authentication uses certificates on the server and client systems to more securely authenticate the remote mount request." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
cat /etc/fstab | grep nfs &>> RHE7findings.txt
echo "Finding: If the system is mounting file systems via NFS and has the sec option without the 'krb5:krb5i:krb5p' settings, the 'sec' option has the 'sys' setting, or the 'sec' option is missing, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72309" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not be performing packet forwarding unless the system is a router." >> RHE7findings.txt
echo "Discussion: Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep net.ipv4.ip_forward /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
/sbin/sysctl -a | grep net.ipv4.ip_forward &>> RHE7findings.txt
echo "Finding: If IP forwarding value is '1' and the system is hosting any application, database, or web servers, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72307" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title:  The Red Hat Enterprise Linux operating system must not have an X Windows display manager installed unless approved." >> RHE7findings.txt
echo "Discussion: Internet services that are not required for system or application processes must not be active to decrease the attack surface of the system. X Windows has a long history of security vulnerabilities and will not be used unless approved and documented." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
rpm -qa | grep xorg | grep server &>> RHE7findings.txt
echo "Finding: If the use of X Windows on the system is not documented with the Information System Security Officer (ISSO), this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72305" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that if the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon is configured to operate in secure mode." >> RHE7findings.txt
echo "Discussion:Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed tftp-server &>> RHE7findings.txt
grep server_args /etc/xinetd.d/tftp &>> RHE7findings.txt
echo "Finding: If the 'server_args' line does not have a '-s' option and a subdirectory is not assigned, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72303" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that remote X connections for interactive users are encrypted." >> RHE7findings.txt
echo "Discussion: Open X displays allow an attacker to capture keystrokes and execute commands remotely." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i x11forwarding /etc/ssh/sshd_config | grep -v "^#" &>> RHE7findings.txt
echo "Finding: If the 'X11Forwarding' keyword is set to 'no' or is missing, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt




echo "V-72301" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not have the Trivial File Transfer Protocol (TFTP) server package installed if not required for operational support." >> RHE7findings.txt
echo "Discussion: If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Officer (ISSO), restricted to only authorized personnel, and have access control rules established." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed tftp-server &>> RHE7findings.txt
echo "Finding:If TFTP is installed and the requirement for TFTP is not documented with the ISSO, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72299" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not have a File Transfer Protocol (FTP) server package installed unless needed." >> RHE7findings.txt
echo "Discussion: The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
 yum list installed vsftpd &>> RHE7findings.txt
echo "Finding: If 'vsftpd' is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72297" >> RHE7findings.txt
echo "Group Title:SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured to prevent unrestricted mail relaying." >> RHE7findings.txt
echo "Discussion: If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending spam or other unauthorized activity." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed postfix &>> RHE7findings.txt
postconf -n smtpd_client_restrictions &>> RHE7findings.txt
echo "Finding: If the 'smtpd_client_restrictions' parameter contains any entries other than 'permit_mynetworks' and 'reject', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72295" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: Network interfaces configured on the Red Hat Enterprise Linux operating system must not be in promiscuous mode." >> RHE7findings.txt
echo "Discussion: Network interfaces in promiscuous mode allow for the capture of all network traffic visible to the system. If unauthorized individuals can access these applications, it may allow then to collect information such as logon IDs, passwords, and key exchanges between systems.
If the system is being used to perform a network troubleshooting function, the use of these tools must be documented with the Information System Security Officer (ISSO) and restricted to only authorized personnel." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
ip link | grep -i promisc &>> RHE7findings.txt
echo "Finding: If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72293" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects." >> RHE7findings.txt
echo "Discussion: ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep 'net.ipv4.conf.all.send_redirects' /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
echo "Finding: If 'net.ipv4.conf.all.send_redirects' is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of '0', this is a finding." >> RHE7findings.txt 
/sbin/sysctl -a | grep 'net.ipv4.conf.all.send_redirects' &>> RHE7findings.txt
echo "Finding: If the returned line does not have a value of '0', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72291" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not allow interfaces to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects by default." >> RHE7findings.txt
echo "Discussion: ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep 'net.ipv4.conf.default.send_redirects' /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
echo "Finding: If 'net.ipv4.conf.default.send_redirects' is not configured in the '/etc/sysctl.conf' file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of '0', this is a finding." >> RHE7findings.txt 
/sbin/sysctl -a | grep 'net.ipv4.conf.default.send_redirects' &>> RHE7findings.txt
echo "Finding: If the returned line does not have a value of "0", this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72289" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must prevent Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages from being accepted." >> RHE7findings.txt
echo "Discussion: ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep 'net.ipv4.conf.default.accept_redirects' /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
echo "Finding: If ' net.ipv4.conf.default.accept_redirects ' is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of '0', this is a finding." >> RHE7findings.txt 
/sbin/sysctl -a | grep 'net.ipv4.conf.default.accept_redirects' &>> RHE7findings.txt
echo "Finding: If the returned line does not have a value of "0", this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72287" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address." >> RHE7findings.txt
echo "Discussion: Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
echo "Finding: If ' net.ipv4.icmp_echo_ignore_broadcasts' is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of '1', this is a finding." >> RHE7findings.txt 
/sbin/sysctl -a | grep net.ipv4.icmp_echo_ignore_broadcasts &>> RHE7findings.txt
echo "Finding: If the returned line does not have a value of '1', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72285" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets by default." >> RHE7findings.txt
echo "Discussion: Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep net.ipv4.conf.default.accept_source_route /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
echo "Finding: If ' net.ipv4.conf.default.accept_source_route ' is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of '0', this is a finding." >> RHE7findings.txt 
/sbin/sysctl -a | grep net.ipv4.conf.default.accept_source_route &>> RHE7findings.txt
echo "Finding: If the returned line does not have a value of '0', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72283" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets." >> RHE7findings.txt
echo "Discussion: Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep net.ipv4.conf.all.accept_source_route /etc/sysctl.conf /etc/sysctl.d/* &>> RHE7findings.txt
echo "Finding: If ' net.ipv4.conf.all.accept_source_route ' is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of '0', this is a finding." >> RHE7findings.txt 
/sbin/sysctl -a | grep net.ipv4.conf.all.accept_source_route &>> RHE7findings.txt
echo "Finding: If the returned line does not have a value of '0', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72281" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: For Red Hat Enterprise Linux operating systems using DNS resolution, at least two name servers must be configured." >> RHE7findings.txt
echo "Discussion: To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep hosts /etc/nsswitch.conf &>> RHE7findings.txt
ls -al /etc/resolv.conf &>> RHE7findings.txt
echo "Finding: If local host authentication is being used and the '/etc/resolv.conf' file is not empty, this is a finding." >> RHE7findings.txt 
grep nameserver /etc/resolv.conf &>> RHE7findings.txt
echo "Finding: If less than two lines are returned that are not commented out, this is a finding." >> RHE7findings.txt 
sudo lsattr /etc/resolv.conf &>> RHE7findings.txt
echo "Finding: If the file is mutable and has not been documented with the Information System Security Officer (ISSO), this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72279" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not contain shosts.equiv files." >> RHE7findings.txt
echo "Discussion: The shosts.equiv files are used to configure host-based authentication for the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
find / -name shosts.equiv &>> RHE7findings.txt
echo "Finding: If any 'shosts.equiv' files are found on the system, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72277" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not contain .shosts files." >> RHE7findings.txt
echo "Discussion: The .shosts files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
find / -name '*.shosts' &>> RHE7findings.txt
echo "Finding: If any '.shosts' files are found on the system, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72275" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must display the date and time of the last successful account logon upon logon." >> RHE7findings.txt
echo "Discussion: Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep pam_lastlog /etc/pam.d/postlogin &>> RHE7findings.txt
echo "Finding: If 'pam_lastlog' is missing from '/etc/pam.d/postlogin' file, or the silent option is present, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72273" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must enable an application firewall, if available." >> RHE7findings.txt
echo "Discussion: Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed firewalld &>> RHE7findings.txt
echo "Finding: If an application firewall is not installed, this is a finding. " >> RHE7findings.txt 
systemctl status firewalld &>> RHE7findings.txt
echo "Finding: If 'firewalld' does not show a status of 'loaded' and 'active', this is a finding. " >> RHE7findings.txt 
firewall-cmd --state  &>> RHE7findings.txt
echo "Finding: If 'firewalld' does not show a state of 'running', this is a finding." >> RHE7findings.txt 

echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72269" >> RHE7findings.txt
echo "Group Title: SRG-OS-000355-GPOS-00143" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)." >> RHE7findings.txt
echo "Discussion: Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.
Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.
Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
ps -ef | grep ntp &>> RHE7findings.txt
ps -ef | grep chronyd &>> RHE7findings.txt
echo "Finding: If NTP or 'chronyd' is not running, this is a finding." >> RHE7findings.txt 
grep maxpoll /etc/ntp.conf &>> RHE7findings.txt
echo "Finding: If the option is set to '17' or is not set, this is a finding." >> RHE7findings.txt 
grep -i "ntpd -q" /etc/cron.daily/* &>> RHE7findings.txt
ls -al /etc/cron.* | grep ntp &>> RHE7findings.txt
grep maxpoll /etc/chrony.conf &>> RHE7findings.txt
echo "Finding: If the option is not set or the line is commented out, this is a finding. " >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72267" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow compression or only allows compression after successful authentication." >> RHE7findings.txt
echo "Discussion: If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i compression /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the 'Compression' keyword is set to 'yes', is missing, or the returned line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72265" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon uses privilege separation." >> RHE7findings.txt
echo "Discussion: SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i usepriv /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the 'UsePrivilegeSeparation' keyword is set to 'no', is missing, or the returned line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72263" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon performs strict mode checking of home directory configuration files." >> RHE7findings.txt
echo "Discussion: If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i strictmodes /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If 'StrictModes' is set to 'no', is missing, or the returned line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72261" >> RHE7findings.txt
echo "Group Title: SRG-OS-000364-GPOS-00151" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Kerberos authentication unless needed." >> RHE7findings.txt
echo "Discussion: Kerberos authentication for SSH is often implemented using Generic Security Service Application Program Interface (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation. Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation. To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems not using this capability." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i kerberosauth /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the 'KerberosAuthentication' keyword is missing, or is set to 'yes' and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72259" >> RHE7findings.txt
echo "Group Title: SRG-OS-000364-GPOS-00151" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed." >> RHE7findings.txt
echo "Discussion: GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system. GSSAPI authentication must be disabled unless needed." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i gssapiauth /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the 'GSSAPIAuthentication' keyword is missing, is set to 'yes' and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72257" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH private host key files have mode 0640 or less permissive." >> RHE7findings.txt
echo "Discussion: If an unauthorized user obtains the private SSH host key file, the host could be impersonated." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
find / -name '*ssh_host*key' | xargs ls -lL &>> RHE7findings.txt
echo "Finding: If any file has a mode more permissive than '0640', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt



echo "V-72255" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH public host key files have mode 0644 or less permissive." >> RHE7findings.txt
echo "Discussion: If a public host key file is modified by an unauthorized user, the SSH service may be compromised." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
find /etc/ssh -name '*.pub' -exec ls -lL {} \; &>> RHE7findings.txt
echo "Finding: If any file has a mode more permissive than '0644', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72253" >> RHE7findings.txt
echo "Group Title: SRG-OS-000250-GPOS-00093" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon is configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms." >> RHE7findings.txt
echo "Discussion: DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions. The only SSHv2 hash algorithm meeting this requirement is SHA." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i macs /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If any ciphers other than 'hmac-sha2-256' or 'hmac-sha2-512' are listed or the returned line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72251" >> RHE7findings.txt
echo "Group Title: SRG-OS-000074-GPOS-00042" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon is configured to only use the SSHv2 protocol." >> RHE7findings.txt
echo "Discussion: SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
cat /etc/redhat-release &>> RHE7findings.txt
grep -i protocol /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If any protocol line other than 'Protocol 2' is uncommented, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72249" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using known hosts authentication." >> RHE7findings.txt
echo "Discussion: Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i IgnoreUserKnownHosts /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the value is returned as 'no', the returned line is commented out, or no output is returned, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72247" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not permit direct logons to the root account using remote access via SSH." >> RHE7findings.txt
echo "Discussion: Even though the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging on directly as root. In addition, logging on with a user-specific account provides individual accountability of actions performed on the system." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i permitrootlogin /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the 'PermitRootLogin' keyword is set to 'yes', is missing, or is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72245" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must display the date and time of the last successful account logon upon an SSH logon." >> RHE7findings.txt
echo "Discussion: Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i printlastlog /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the 'PrintLastLog' keyword is set to 'no', is missing, or is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72243" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using rhosts authentication." >> RHE7findings.txt
echo "Discussion: Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i IgnoreRhosts /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the value is returned as 'no', the returned line is commented out, or no output is returned, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72241" >> RHE7findings.txt
echo "Group Title: SRG-OS-000163-GPOS-00072" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with SSH traffic terminate after a period of inactivity." >> RHE7findings.txt
echo "Discussion: Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.
Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i clientalivecount /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If 'ClientAliveCountMax' is not set to '0', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72239" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using RSA rhosts authentication." >> RHE7findings.txt
echo "Discussion:  Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
cat /etc/redhat-release &>> RHE7findings.txt
grep RhostsRSAAuthentication /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the value is returned as yes, the returned line is commented out, or no output is returned, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72237" >> RHE7findings.txt
echo "Group Title: SRG-OS-000163-GPOS-00072" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with SSH traffic are terminated at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements." >> RHE7findings.txt
echo "Discussion: Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.
Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw clientaliveinterval /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If 'ClientAliveInterval' is not configured, commented out, or has a value of '0', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72235" >> RHE7findings.txt
echo "Group Title: SRG-OS-000423-GPOS-00187" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all networked systems use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission." >> RHE7findings.txt
echo "Discussion: Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 
This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 
Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
systemctl status sshd &>> RHE7findings.txt
echo "Finding: If 'sshd' does not show a status of 'active' and 'running', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72233" >> RHE7findings.txt
echo "Group Title: SRG-OS-000423-GPOS-00187" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all networked systems have SSH installed." >> RHE7findings.txt
echo "Discussion: Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 
This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 
Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed \*ssh\* &>> RHE7findings.txt
echo "Finding: If the 'SSH server' package is not installed, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72231" >> RHE7findings.txt
echo "Group Title: SRG-OS-000250-GPOS-00093" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications." >> RHE7findings.txt
echo "Discussion: Without cryptographic integrity protections, information can be altered by unauthorized users without detection.Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
systemctl status sssd.service &>> RHE7findings.txt
grep -i "id_provider" /etc/sssd/sssd.conf &>> RHE7findings.txt
grep -i tls_cacert /etc/sssd/sssd.conf &>> RHE7findings.txt
echo "Finding: If this file does not exist, or the option is commented out or missing, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72229" >> RHE7findings.txt
echo "Group Title: SRG-OS-000250-GPOS-00093" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications." >> RHE7findings.txt
echo "Discussion: Without cryptographic integrity protections, information can be altered by unauthorized users without detection.
Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
systemctl status sssd.service &>> RHE7findings.txt
grep -i "id_provider" /etc/sssd/sssd.conf &>> RHE7findings.txt
grep -i tls_reqcert /etc/sssd/sssd.conf &>> RHE7findings.txt
echo "Finding: If the 'ldap_tls_reqcert' setting is missing, commented out, or does not exist, this is a finding." >> RHE7findings.txt 
echo "Finding: If the 'ldap_tls_reqcert' setting is not set to 'demand' or 'hard', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72227" >> RHE7findings.txt
echo "Group Title: SRG-OS-000250-GPOS-00093" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications." >> RHE7findings.txt
echo "Discussion: Without cryptographic integrity protections, information can be altered by unauthorized users without detection. Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
systemctl status sssd.service &>> RHE7findings.txt
grep -i "id_provider" /etc/sssd/sssd.conf &>> RHE7findings.txt
grep -i "start_tls" /etc/sssd/sssd.conf &>> RHE7findings.txt
echo "Finding: If the 'ldap_id_use_start_tls' option is not 'true', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72225" >> RHE7findings.txt
echo "Group Title: SRG-OS-000023-GPOS-00006" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner immediately prior to, or as part of, remote access logon prompts." >> RHE7findings.txt
echo "Discussion: Display of a standardized and approved use notification before granting access to the publicly accessible operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i banner /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: This command will return the banner keyword and the name of the file that contains the ssh banner (in this case '/etc/issue').If the line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72223" >> RHE7findings.txt
echo "Group Title: SRG-OS-000163-GPOS-00072" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with a communication session are terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements." >> RHE7findings.txt
echo "Discussion: Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 
Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i tmout /etc/profile.d/* &>> RHE7findings.txt
echo "Finding: If 'TMOUT' is not set to '600' or less in a script located in the /etc/profile.d/ directory to enforce session termination after inactivity, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72221" >> RHE7findings.txt
echo "Group Title: SRG-OS-000033-GPOS-00014" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must use a FIPS 140-2 approved cryptographic algorithm for SSH communications." >> RHE7findings.txt
echo "Discussion: Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.
Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.
FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i ciphers /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding:If any ciphers other than 'aes128-ctr', 'aes192-ctr', or 'aes256-ctr' are listed, the 'Ciphers' keyword is missing, or the returned line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72219" >> RHE7findings.txt
echo "Group Title: SRG-OS-000096-GPOS-00050" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA) and vulnerability assessments." >> RHE7findings.txt
echo "Discussion: In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
firewall-cmd --list-all &>> RHE7findings.txt
echo "Finding: If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72217" >> RHE7findings.txt
echo "Group Title: SRG-OS-000027-GPOS-00008" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types." >> RHE7findings.txt
echo "Discussion: Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.
This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep "maxlogins" /etc/security/limits.conf /etc/security/limits.d/*.conf &>> RHE7findings.txt
echo "Finding: If the 'maxlogins' item is missing, commented out, or the value is not set to '10' or less for all domains that have the 'maxlogins' item assigned, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72211" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation." >> RHE7findings.txt
echo "Discussion: Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a Denial of Service." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep imtcp /etc/rsyslog.conf &>> RHE7findings.txt
grep imudp /etc/rsyslog.conf &>> RHE7findings.txt
grep imrelp /etc/rsyslog.conf &>> RHE7findings.txt
echo "Finding: If the documentation does not exist, or does not specify the server as a log aggregation system, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72209" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must send rsyslog output to a log aggregation server." >> RHE7findings.txt
echo "Discussion: Sending rsyslog output to another system ensures that the logs cannot be removed or modified in the event that the system is compromised or has a hardware failure." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep @ /etc/rsyslog.conf /etc/rsyslog.d/*.conf &>> RHE7findings.txt
echo "Finding: If the lines are commented out or there is no evidence that the audit logs are being sent to another system, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72207" >> RHE7findings.txt
echo "Group Title: SRG-OS-000466-GPOS-00210" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the unlinkat syscall." >> RHE7findings.txt
echo "Discussion: If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw unlinkat /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'unlinkat' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72205" >> RHE7findings.txt
echo "Group Title: SRG-OS-000466-GPOS-00210" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the unlink syscall." >> RHE7findings.txt
echo "Discussion: If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw unlink /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'unlink' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72203" >> RHE7findings.txt
echo "Group Title: SRG-OS-000466-GPOS-00210" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the rmdir syscall." >> RHE7findings.txt
echo "Discussion: If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw rmdir /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'rmdir' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72201" >> RHE7findings.txt
echo "Group Title: SRG-OS-000466-GPOS-00210" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the renameat syscall." >> RHE7findings.txt
echo "Discussion: If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw renameat /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'renameat' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72199" >> RHE7findings.txt
echo "Group Title: SRG-OS-000466-GPOS-00210" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the rename syscall." >> RHE7findings.txt
echo "Discussion: If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw rename /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'rename' syscall, this is a finding.." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72197" >> RHE7findings.txt
echo "Group Title: SRG-OS-000004-GPOS-00004" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep /etc/passwd /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return a line, or the line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72191" >> RHE7findings.txt
echo "Group Title: SRG-OS-000471-GPOS-00216" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the kmod command." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. " >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw kmod /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72189" >> RHE7findings.txt
echo "Group Title: SRG-OS-000471-GPOS-00216" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the delete_module syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw delete_module /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'delete_module' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72187" >> RHE7findings.txt
echo "Group Title: SRG-OS-000471-GPOS-00216" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the init_module syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw init_module /etc/audit/audit.rules  &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'init_module' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72185" >> RHE7findings.txt
echo "Group Title: SRG-OS-000471-GPOS-00215" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the pam_timestamp_check command." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw "/usr/sbin/pam_timestamp_check" /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72183" >> RHE7findings.txt
echo "Group Title: SRG-OS-000042-GPOS-00020" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the crontab command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw /usr/bin/crontab /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72179" >> RHE7findings.txt
echo "Group Title: SRG-OS-000042-GPOS-00020" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the ssh-keysign command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
At a minimum, the organization must audit the full-text recording of privileged ssh commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw /usr/libexec/openssh/ssh-keysign /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt



echo "V-72177" >> RHE7findings.txt
echo "Group Title: SRG-OS-000042-GPOS-00020" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the postqueue command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
At a minimum, the organization must audit the full-text recording of privileged postfix commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw /usr/sbin/postqueue /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72175" >> RHE7findings.txt
echo "Group Title: SRG-OS-000042-GPOS-00020" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the postdrop command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.At a minimum, the organization must audit the full-text recording of privileged postfix commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw /usr/sbin/postdrop /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72173" >> RHE7findings.txt
echo "Group Title: SRG-OS-000042-GPOS-00020" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the umount command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
At a minimum, the organization must audit the full-text recording of privileged mount commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw "/usr/bin/umount" /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72171" >> RHE7findings.txt
echo "Group Title: SRG-OS-000042-GPOS-00020" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the mount command and syscall." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
At a minimum, the organization must audit the full-text recording of privileged mount commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw "mount" /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'mount' syscall, this is a finding.
If all uses of the 'mount' command are not being audited, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt



echo "V-72167" >> RHE7findings.txt
echo "Group Title: SRG-OS-000037-GPOS-00015" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the chsh command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i /usr/bin/chsh /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72165" >> RHE7findings.txt
echo "Group Title: SRG-OS-000037-GPOS-00015" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the newgrp command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i /usr/bin/newgrp /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72163" >> RHE7findings.txt
echo "Group Title: SRG-OS-000037-GPOS-00015" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the sudoers file and all files in the /etc/sudoers.d/ directory." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i "/etc/sudoers" /etc/audit/audit.rules &>> RHE7findings.txt
grep -i "/etc/sudoers.d/" /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the commands do not return output that match the examples, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72161" >> RHE7findings.txt
echo "Group Title: SRG-OS-000037-GPOS-00015" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the sudo command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw /usr/bin/sudo /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72159" >> RHE7findings.txt
echo "Group Title: SRG-OS-000037-GPOS-00015" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the su command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw /usr/bin/su /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72157" >> RHE7findings.txt
echo "Group Title: SRG-OS-000042-GPOS-00020" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the userhelper command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.]
At a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i /usr/sbin/userhelper /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72155" >> RHE7findings.txt
echo "Group Title: SRG-OS-000042-GPOS-00020" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the chage command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
At a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i /usr/bin/chage /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72153" >> RHE7findings.txt
echo "Group Title: SRG-OS-000042-GPOS-00020" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the gpasswd command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.At a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i /usr/bin/gpasswd /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72151" >> RHE7findings.txt
echo "Group Title: SRG-OS-000042-GPOS-00020" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the unix_chkpwd command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
At a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw /usr/sbin/unix_chkpwd /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72149" >> RHE7findings.txt
echo "Group Title: SRG-OS-000042-GPOS-00020" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the passwd command." >> RHE7findings.txt
echo "Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
At a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i /usr/bin/passwd /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72147" >> RHE7findings.txt
echo "Group Title: SRG-OS-000392-GPOS-00172" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must generate audit records for all successful account access events." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i /var/log/lastlog /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72145" >> RHE7findings.txt
echo "Group Title: SRG-OS-000392-GPOS-00172" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must generate audit records for all unsuccessful account access events." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i /var/run/faillock /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72141" >> RHE7findings.txt
echo "Group Title: SRG-OS-000392-GPOS-00172 " >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the setfiles command." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw /usr/sbin/setfiles /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72139" >> RHE7findings.txt
echo "Group Title: SRG-OS-000392-GPOS-00172" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the chcon command." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i /usr/bin/chcon /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding:If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt



echo "V-72137" >> RHE7findings.txt
echo "Group Title: SRG-OS-000392-GPOS-00172" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the setsebool command." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i /usr/sbin/setsebool /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72135" >> RHE7findings.txt
echo "Group Title: SRG-OS-000392-GPOS-00172" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the semanage command." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i /usr/sbin/semanage /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If the command does not return any output, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72133" >> RHE7findings.txt
echo "Group Title: SRG-OS-000064-GPOS-00033" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the ftruncate syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw ftruncate /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'ftruncate' syscall, this is a finding." >> RHE7findings.txt 
echo "Finding: If the output does not produce rules containing '-F exit=-EPERM', this is a finding." >> RHE7findings.txt 
echo "Finding:If the output does not produce rules containing '-F exit=-EACCES', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72131" >> RHE7findings.txt
echo "Group Title: SRG-OS-000064-GPOS-00033" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the truncate syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw truncate /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'truncate' syscall, this is a finding." >> RHE7findings.txt 
echo "Finding: If the output does not produce rules containing '-F exit=-EPERM', this is a finding." >> RHE7findings.txt 
echo "Finding: If the output does not produce rules containing '-F exit=-EACCES', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72129" >> RHE7findings.txt
echo "Group Title: SRG-OS-000064-GPOS-00033" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the open_by_handle_at syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw open_by_handle_at /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'open_by_handle_at' syscall, this is a finding." >> RHE7findings.txt 
echo "Finding: If the output does not produce rules containing '-F exit=-EPERM', this is a finding." >> RHE7findings.txt 
echo "Finding: If the output does not produce rules containing '-F exit=-EACCES', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72127" >> RHE7findings.txt
echo "Group Title: SRG-OS-000064-GPOS-00033" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the openat syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw openat /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'openat' syscall, this is a finding." >> RHE7findings.txt 
echo "Finding: If the output does not produce rules containing '-F exit=-EPERM', this is a finding." >> RHE7findings.txt 
echo "Finding: If the output does not produce rules containing '-F exit=-EACCES', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72125" >> RHE7findings.txt
echo "Group Title: SRG-OS-000064-GPOS-00033" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the open syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw open /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'open' syscall, this is a finding." >> RHE7findings.txt 
echo "Finding: If the output does not produce rules containing '-F exit=-EPERM', this is a finding." >> RHE7findings.txt 
echo "Finding: If the output does not produce rules containing '-F exit=-EACCES', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72123" >> RHE7findings.txt
echo "Group Title: SRG-OS-000064-GPOS-00033" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the creat syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw creat /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'creat' syscall, this is a finding." >> RHE7findings.txt 
echo "Finding: If the output does not produce rules containing '-F exit=-EPERM', this is a finding." >> RHE7findings.txt 
echo "Finding: If the output does not produce rules containing '-F exit=-EACCES', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72121" >> RHE7findings.txt
echo "Group Title: SRG-OS-000458-GPOS-00203" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the lremovexattr syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw lremovexattr /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'lremovexattr' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72119" >> RHE7findings.txt
echo "Group Title: SRG-OS-000458-GPOS-00203" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the fremovexattr syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw fremovexattr /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'fremovexattr' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72117" >> RHE7findings.txt
echo "Group Title: SRG-OS-000458-GPOS-00203" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the removexattr syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw removexattr /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'removexattr' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72115" >> RHE7findings.txt
echo "Group Title: SRG-OS-000458-GPOS-00203" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the lsetxattr syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw lsetxattr /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'lsetxattr' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72113" >> RHE7findings.txt
echo "Group Title: SRG-OS-000458-GPOS-00203" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the fsetxattr syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw fsetxattr /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'fsetxattr' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72111" >> RHE7findings.txt
echo "Group Title: SRG-OS-000458-GPOS-00203" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the setxattr syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw setxattr /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'setxattr' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72109" >> RHE7findings.txt
echo "Group Title: SRG-OS-000458-GPOS-00203" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the fchmodat syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw fchmodat /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'fchmodat' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72107" >> RHE7findings.txt
echo "Group Title:  SRG-OS-000458-GPOS-00203" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the fchmod syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw fchmod /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'fchmod' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72105" >> RHE7findings.txt
echo "Group Title: SRG-OS-000458-GPOS-00203" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the chmod syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw chmod /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'chmod' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72103" >> RHE7findings.txt
echo "Group Title:SRG-OS-000064-GPOS-00033" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the fchownat syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw fchownat /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'fchownat' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72101" >> RHE7findings.txt
echo "Group Title: SRG-OS-000064-GPOS-00033" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the lchown syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw lchown /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'lchown' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72099" >> RHE7findings.txt
echo "Group Title: SRG-OS-000064-GPOS-00033" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the fchown syscall." >> RHE7findings.txt
echo "Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw fchown /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'fchown' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72097" >> RHE7findings.txt
echo "Group Title: SRG-OS-000064-GPOS-00033" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all uses of the chown syscall." >> RHE7findings.txt
echo "Discussion:Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
Audit records can be generated from various components within the information system (e.g., module or policy filter)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw chown /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules are not defined for the 'chown' syscall, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72095" >> RHE7findings.txt
echo "Group Title: SRG-OS-000327-GPOS-00127" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must audit all executions of privileged functions." >> RHE7findings.txt
echo "Discussion: Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw execve /etc/audit/audit.rules &>> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules for 'SUID' files are not defined, this is a finding." >> RHE7findings.txt
echo "Finding: If both the 'b32' and 'b64' audit rules for 'SGID' files are not defined, this is a finding." >> RHE7findings.txt  
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72093" >> RHE7findings.txt
echo "Group Title: SRG-OS-000343-GPOS-00134" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached." >> RHE7findings.txt
echo "Discussion: If security personnel are not notified immediately when the threshold for the repository maximum audit record storage capacity is reached, they are unable to expand the audit record storage capacity before records are lost." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i action_mail_acct /etc/audit/auditd.conf &>> RHE7findings.txt
echo "Finding: If the value of the 'action_mail_acct' keyword is not set to 'root' and other accounts for security personnel, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72091" >> RHE7findings.txt
echo "Group Title: SRG-OS-000343-GPOS-00134" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached." >> RHE7findings.txt
echo "Discussion: If security personnel are not notified immediately when the threshold for the repository maximum audit record storage capacity is reached, they are unable to expand the audit record storage capacity before records are lost." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i space_left_action /etc/audit/auditd.conf &>> RHE7findings.txt
echo "Finding: If the value of the 'space_left_action' keyword is not set to 'email', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72089" >> RHE7findings.txt
echo "Group Title: SRG-OS-000343-GPOS-00134" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must initiate an action to notify the System Administrator (SA) and Information System Security Officer ISSO, at a minimum, when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity." >> RHE7findings.txt
echo "Discussion: If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -iw log_file /etc/audit/auditd.conf &>> RHE7findings.txt
df -h /var/log/audit/ &>> RHE7findings.txt
du -sh <partition>  &>> RHE7findings.txt
grep -iw space_left /etc/audit/auditd.conf &>> RHE7findings.txt
echo "Finding: If the value of the 'space_left' keyword is not set to 25 percent of the total partition size, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72087" >> RHE7findings.txt
echo "Group Title: SRG-OS-000342-GPOS-00133" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the audit system takes appropriate action when the audit storage volume is full." >> RHE7findings.txt
echo "Discussion: Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i disk_full_action /etc/audisp/audisp-remote.conf &>> RHE7findings.txt
echo "Finding: If the value of the 'disk_full_action' option is not 'syslog', 'single', or 'halt', or the line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72085" >> RHE7findings.txt
echo "Group Title: SRG-OS-000342-GPOS-00133" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited." >> RHE7findings.txt
echo "Discussion: Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
Off-loading is a common process in information systems with limited audit storage capacity." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i enable_krb5 /etc/audisp/audisp-remote.conf &>> RHE7findings.txt
echo "Finding: If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72083" >> RHE7findings.txt
echo "Group Title: SRG-OS-000342-GPOS-00133" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must off-load audit records onto a different system or media from the system being audited." >> RHE7findings.txt
echo "Discussion: Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
Off-loading is a common process in information systems with limited audit storage capacity." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i remote_server /etc/audisp/audisp-remote.conf &>> RHE7findings.txt
echo "Finding: If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72081" >> RHE7findings.txt
echo "Group Title:  SRG-OS-000046-GPOS-00022" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure." >> RHE7findings.txt
echo "Discussion: It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.
Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.
This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
auditctl -s | grep -i "fail" &>> RHE7findings.txt
echo "Finding: If the 'failure' setting is set to any value other than '1' or '2', this is a finding." >> RHE7findings.txt 
echo "Finding: If the 'failure' setting is not set, this should be upgraded to a CAT I finding." >> RHE7findings.txt 
echo "Finding: If the 'failure' setting is set to '1' but the availability concern is not documented or there is no monitoring of the kernel log, this should be downgraded to a CAT III finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72079" >> RHE7findings.txt
echo "Group Title: SRG-OS-000038-GPOS-00016" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that auditing is configured to produce records containing information to establish what type of events occurred, where the events occurred, the source of the events, and the outcome of the events. These audit records must also identify individual identities of group account users." >> RHE7findings.txt
echo "Discussion: Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.
Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.
Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
systemctl is-active auditd.service &>> RHE7findings.txt
echo "Finding: If the 'auditd' status is not active, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72077" >> RHE7findings.txt
echo "Group Title: SRG-OS-000095-GPOS-00049" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not have the telnet-server package installed." >> RHE7findings.txt
echo "Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.
Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed telnet-server &>> RHE7findings.txt
echo "Finding: If the telnet-server package is installed, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72075" >> RHE7findings.txt
echo "Group Title: SRG-OS-000364-GPOS-00151" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not allow removable media to be used as the boot loader unless approved." >> RHE7findings.txt
echo "Discussion: Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader. If removable media is designed to be used as the boot loader, the requirement must be documented with the Information System Security Officer (ISSO)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
find / -name grub.cfg &>> RHE7findings.txt
grep -c menuentry /boot/grub2/grub.cfg &>> RHE7findings.txt
grep 'set root' /boot/grub2/grub.cfg &>> RHE7findings.txt 
echo "Finding: If the system is using an alternate boot loader on removable media, and documentation does not exist approving the alternate configuration, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72073" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must use a file integrity tool that is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories." >> RHE7findings.txt
echo "Discussion: File integrity tools use cryptographic hashes for verifying file contents and directories have not been altered. These hashes must be FIPS 140-2 approved cryptographic hashes." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed aide &>> RHE7findings.txt
echo "Finding: If there is no application installed to perform file integrity checks, this is a finding." >> RHE7findings.txt 
find / -name aide.conf &>> RHE7findings.txt
echo "Finding: If the 'sha512' rule is not being used on all uncommented selection lines in the '/etc/aide.conf' file, or another file integrity tool is not using FIPS 140-2 approved cryptographic hashes for validating file contents and directories, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72071" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the file integrity tool is configured to verify extended attributes." >> RHE7findings.txt
echo "Discussion: Extended attributes in file systems are used to contain arbitrary data and file metadata with security implications." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed aide &>> RHE7findings.txt
find / -name aide.conf &>> RHE7findings.txt
echo "Finding: If the 'xattrs' rule is not being used on all uncommented selection lines in the '/etc/aide.conf' file, or extended attributes are not being checked by another file integrity tool, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72069" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the file integrity tool is configured to verify Access Control Lists (ACLs)." >> RHE7findings.txt
echo "Discussion: ACLs can provide permissions beyond those permitted through the file mode and must be verified by file integrity tools." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed aide &>> RHE7findings.txt
echo "Finding: If there is no application installed to perform file integrity checks, this is a finding." >> RHE7findings.txt 
find / -name aide.conf &>> RHE7findings.txt
echo "Finding: If the 'acl' rule is not being used on all uncommented selection lines in the '/etc/aide.conf' file, or ACLs are not being checked by another file integrity tool, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72067" >> RHE7findings.txt
echo "Group Title: SRG-OS-000033-GPOS-00014" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards." >> RHE7findings.txt
echo "Discussion: Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed dracut-fips &>> RHE7findings.txt
grep fips /boot/grub2/grub.cfg &>> RHE7findings.txt
cat /proc/sys/crypto/fips_enabled &>> RHE7findings.txt

echo "Finding: If a 'dracut-fips' package is not installed, the kernel command line does not have a fips entry, or the system has a value of '0' for 'fips_enabled' in '/proc/sys/crypto', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72065" >> RHE7findings.txt
echo "Group Title:SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must use a separate file system for /tmp (or equivalent)." >> RHE7findings.txt
echo "Discussion: The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
systemctl is-enabled tmp.mount &>> RHE7findings.txt
 grep -i /tmp /etc/fstab &>> RHE7findings.txt
echo "Finding: If 'tmp.mount' service is not enabled and the '/tmp' directory is not defined in the fstab with a device and mount point, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72063" >> RHE7findings.txt
echo "Group Title:SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must use a separate file system for the system audit data path." >> RHE7findings.txt
echo "Discussion: The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
 grep /var/log/audit /etc/fstab &>> RHE7findings.txt
echo "Finding: If no result is returned, or the operating system is not configured to have '/var/log/audit' on a separate file system, this is a finding." >> RHE7findings.txt 
mount | grep "/var/log/audit" &>> RHE7findings.txt
echo "Finding: If no result is returned, or '/var/log/audit' is not on a separate file system, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72061" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must use a separate file system for /var." >> RHE7findings.txt
echo "Discussion: The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep /var /etc/fstab &>> RHE7findings.txt
echo "Finding: If a separate entry for '/var' is not in use, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72059" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that a separate file system is used for user home directories (such as /home or an equivalent)." >> RHE7findings.txt
echo "Discussion: The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
cut -d: -f 1,3,6,7 /etc/passwd | egrep ":[1-4][0-9]{3}" | tr ":" "\t" &>> RHE7findings.txt
grep /home /etc/fstab &>> RHE7findings.txt
echo "Finding:If a separate entry for the file system/partition that contains the non-privileged interactive users' home directories does not exist, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt



echo "V-72055" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the cron.allow file, if it exists, is group-owned by root." >> RHE7findings.txt
echo "Discussion: If the group owner of the 'cron.allow' file is not set to root, sensitive information could be viewed or edited by unauthorized users." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
ls -al /etc/cron.allow &>> RHE7findings.txt
echo "Finding: If the 'cron.allow' file exists and has a group owner other than root, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72057" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must disable Kernel core dumps unless needed." >> RHE7findings.txt
echo "Discussion: Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
systemctl status kdump.service &>> RHE7findings.txt
echo "Finding: If the service is active and is not documented, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72053" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the cron.allow file, if it exists, is owned by root." >> RHE7findings.txt
echo "Discussion: If the owner of the 'cron.allow' file is not set to root, the possibility exists for an unauthorized user to view or to edit sensitive information" >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
ls -al /etc/cron.allow &>> RHE7findings.txt
echo "Finding: If the 'cron.allow' file exists and has an owner other than root, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72051" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must have cron logging implemented." >> RHE7findings.txt
echo "Discussion: Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf &>> RHE7findings.txt
echo "Finding: If 'rsyslog' is not logging messages for the cron facility or all facilities, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72049" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must set the umask value to 077 for all local interactive user accounts." >> RHE7findings.txt
echo "Discussion: The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 700 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be '0'. This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i umask /home/*/.* &>> RHE7findings.txt
echo "Finding: If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than '077', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72047" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all world-writable directories are group-owned by root, sys, bin, or an application group." >> RHE7findings.txt
echo "Discussion: If a world-writable directory has the sticky bit set and is not group-owned by a privileged Group Identifier (GID), unauthorized users may be able to modify files created by others.
The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access" >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
find / -xdev -perm -002 -type d -fstype xfs -exec ls -lLd {} \; &>> RHE7findings.txt
echo "Finding: If any world-writable directories are not owned by root, sys, bin, or an application group associated with the directory, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72045" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must prevent files with the setuid and setgid bit set from being executed on file systems that are being imported via Network File System (NFS)." >> RHE7findings.txt
echo "Discussion: The 'nosuid' mount option causes the system to not execute 'setuid' and 'setgid' files with owner privileges. This option must be used for mounting any file system not containing approved 'setuid' and 'setguid' files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
more /etc/fstab | grep nfs &>> RHE7findings.txt
echo "Finding: If a file system found in '/etc/fstab' refers to NFS and it does not have the 'nosuid' option set, this is a finding." >> RHE7findings.txt 
mount | grep nfs | grep nosuid &>> RHE7findings.txt
echo "Finding: If no results are returned, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72043" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media." >> RHE7findings.txt
echo "Discussion: The 'nosuid' mount option causes the system to not execute 'setuid' and 'setgid' files with owner privileges. This option must be used for mounting any file system not containing approved 'setuid' and 'setguid' files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
more /etc/fstab &>> RHE7findings.txt
echo "Finding: If a file system found in '/etc/fstab' refers to removable media and it does not have the 'nosuid' option set, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72041" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that file systems containing user home directories are mounted to prevent files with the setuid and setgid bit set from being executed." >> RHE7findings.txt
echo "Discussion: The 'nosuid' mount option causes the system to not execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
cut -d: -f 1,3,6 /etc/passwd | egrep ":[1-4][0-9]{3}" &>> RHE7findings.txt
more /etc/fstab &>> RHE7findings.txt
echo "Finding: If a file system found in '/etc/fstab' refers to the user home directory file system and it does not have the 'nosuid' option set, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72039" >> RHE7findings.txt
echo "Group Title:SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all system device files are correctly labeled to prevent unauthorized modification." >> RHE7findings.txt
echo "Discussion: If an unauthorized or modified device is allowed to exist on the system, there is the possibility the system may perform unintended or unauthorized operations." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n" &>> RHE7findings.txt
find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n" &>> RHE7findings.txt
echo "Finding: If there is output from either of these commands, other than already noted, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72037" >> RHE7findings.txt
echo "Group Title:SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that local initialization files do not execute world-writable programs." >> RHE7findings.txt
echo "Discussion: If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
find / -xdev -perm -002 -type f -exec ls -ld {} \; | more &>> RHE7findings.txt
grep <file> /home/*/.* &>> RHE7findings.txt
echo "Finding: If any local initialization files are found to reference world-writable files, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72035" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all local interactive user initialization files executable search paths contain only paths that resolve to the users home directory." >> RHE7findings.txt
echo "Discussion: The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory (other than the user's home directory), executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. If deviations from the default system search path for the local interactive user are required, they must be documented with the Information System Security Officer (ISSO)." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i path /home/smithj/.* &>> RHE7findings.txt
echo "Finding: If any local interactive user initialization files have executable search path statements that include directories outside of their home directory, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72033" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all local initialization files have mode 0740 or less permissive." >> RHE7findings.txt
echo "Discussion: Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
ls -al /home/smithj/.[^.]* | more &>> RHE7findings.txt
echo "Finding: If any local initialization files have a mode more permissive than '0740', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72031" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all local initialization files for local interactive users are be group-owned by the users primary group or root." >> RHE7findings.txt
echo "Discussion: Local initialization files for interactive users are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
cut -d: -f 1,4,6 /etc/passwd | egrep ":[1-4][0-9]{3}" &>> RHE7findings.txt
grep 1000 /etc/group &>> RHE7findings.txt
ls -al /home/smithj/.[^.]* | more &>> RHE7findings.txt
echo "Finding: If all local interactive user's initialization files are not group-owned by that user's primary GID, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72029" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all local initialization files for interactive users are owned by the home directory user or root." >> RHE7findings.txt
echo "Discussion: Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
cut -d: -f 1,3,6 /etc/passwd | egrep ":[1-4][0-9]{3}" &>> RHE7findings.txt
ls -al /home/smithj/.[^.]* | more  &>> RHE7findings.txt
echo "Finding: If all local interactive user's initialization files are not owned by that user or root, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72027" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories have a mode of 0750 or less permissive." >> RHE7findings.txt
echo "Discussion: If a local interactive user files have excessive permissions, unintended users may be able to access or modify them." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
ls -lLR /home/smithj &>> RHE7findings.txt
echo "Finding: If any files are found with a mode more permissive than 0750, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72025" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member." >> RHE7findings.txt
echo "Discussion: If a local interactive user's files are group-owned by a group of which the user is not a member, unintended users may be able to access them." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
ls -lLR /<home directory>/<users home directory>/ &>> RHE7findings.txt
grep smithj /etc/group &>> RHE7findings.txt
echo "Finding: If the user is not a member of a group that group owns file(s) in a local interactive user's home directory, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72023" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories are owned by the owner of the home directory." >> RHE7findings.txt
echo "Discussion: If local interactive users do not own the files in their directories, unauthorized users may be able to access them. Additionally, if files are not owned by the user, this could be an indication of system compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
ls -lLR /home/smithj &>> RHE7findings.txt
echo "Finding: If any files are found with an owner different than the home directory user, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72021" >> RHE7findings.txt
echo "Group Title:SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories are group-owned by the home directory owners primary group." >> RHE7findings.txt
echo "Discussion: If the Group Identifier (GID) of a local interactive user's home directory is not the same as the primary GID of the user, this would allow unauthorized access to the user's files, and users that share the same group may not be able to access files that they legitimately should." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
ls -ld $(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6) &>> RHE7findings.txt
grep users /etc/group &>> RHE7findings.txt
echo "Finding: If the user home directory referenced in '/etc/passwd' is not group-owned by that user's primary GID, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72019" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories are owned by their respective users." >> RHE7findings.txt
echo "Discussion: If a local interactive user does not own their home directory, unauthorized users could access or modify the user's files, and the users may not be able to access their own files." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
ls -ld $(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6) &>> RHE7findings.txt
echo "Finding: If any home directories referenced in '/etc/passwd' are not owned by the interactive user, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt



echo "V-72017" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories have mode 0750 or less permissive." >> RHE7findings.txt
echo "Discussion: Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
 ls -ld $(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6) &>> RHE7findings.txt
echo "Finding: If home directories referenced in '/etc/passwd' do not have a mode of '0750' or less permissive, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72015" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories are defined in the /etc/passwd file." >> RHE7findings.txt
echo "Discussion: If a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon logon. This could create a Denial of Service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
cut -d: -f 1,3,6 /etc/passwd | egrep ":[1-4][0-9]{3}" &>> RHE7findings.txt
pwck -r  &>> RHE7findings.txt
echo "Finding: If any home directories referenced in '/etc/passwd' are returned as not defined, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72013" >> RHE7findings.txt
echo "Group Title:SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all local interactive user accounts, upon creation, are assigned a home directory." >> RHE7findings.txt
echo "Discussion:  If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i create_home /etc/login.defs &>> RHE7findings.txt
echo "Finding: If the value for 'CREATE_HOME' parameter is not set to 'yes', the line is missing, or the line is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72011" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all local interactive users have a home directory assigned in the /etc/passwd file." >> RHE7findings.txt
echo "Discussion: If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
pwck -r &>> RHE7findings.txt
cut -d: -f 1,3 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$" &>> RHE7findings.txt
echo "Finding: If any interactive users do not have a home directory assigned, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72009" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all files and directories have a valid group owner." >> RHE7findings.txt
echo "Discussion: Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
find / -fstype xfs -nogroup &>> RHE7findings.txt
echo "Finding: If any files on the system do not have an assigned group, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72007" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all files and directories have a valid owner." >> RHE7findings.txt
echo "Discussion: Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier 'UID' as the UID of the un-owned files." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
find / -fstype xfs -nouser &>> RHE7findings.txt
echo "Finding: If any files on the system do not have an assigned owner, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72005" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the root account must be the only account having unrestricted access to the system." >> RHE7findings.txt
echo "Discussion: If an account other than root also has a User Identifier (UID) of '0', it has root authority, giving that account unrestricted access to the entire operating system. Multiple accounts with a UID of '0' afford an opportunity for potential intruders to guess a password for a privileged account." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
awk -F: '$3 == 0 {print $1}' /etc/passwd &>> RHE7findings.txt
echo "Finding: If any accounts other than root have a UID of '0', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72003" >> RHE7findings.txt
echo "Group Title: SRG-OS-000104-GPOS-00051" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that all Group Identifiers (GIDs) referenced in the /etc/passwd file are defined in the /etc/group file." >> RHE7findings.txt
echo "Discussion: If a user is assigned the GID of a group not existing on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
pwck -r &>> RHE7findings.txt
echo "Finding: If GIDs referenced in '/etc/passwd' file are returned as not defined in '/etc/group' file, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-72001" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not have unnecessary accounts." >> RHE7findings.txt
echo "Discussion: Accounts providing no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
more /etc/passwd &>> RHE7findings.txt
echo "Finding: If the accounts on the system do not match the provided documentation, or accounts that do not support an authorized system function are present, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71999" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system security patches and updates must be installed and up to date." >> RHE7findings.txt
echo "Discussion: Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced System Administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum history list | more &>> RHE7findings.txt
echo "Finding: If package updates have not been performed on the system within the timeframe that the site/program documentation requires, this is a finding." >> RHE7findings.txt
echo "Finding: If the operating system is in non-compliance with the Information Assurance Vulnerability Management (IAVM) process, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71997" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be a vendor supported release." >> RHE7findings.txt
echo "Discussion: An operating system release is considered 'supported' if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
cat /etc/redhat-release &>> RHE7findings.txt
echo "Finding: If the release is not supported by the vendor, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71995" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00228" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files." >> RHE7findings.txt
echo "Discussion: Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i umask /etc/login.defs &>> RHE7findings.txt
echo "Finding: If the value for the 'UMASK' parameter is not '077', or the 'UMASK' parameter is missing or is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71993" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled on the command line." >> RHE7findings.txt
echo "Discussion: A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
systemctl status ctrl-alt-del.target &>> RHE7findings.txt
echo "Finding: If the ctrl-alt-del.target is not masked, this is a finding." >> RHE7findings.txt 
echo "Finding: If the ctrl-alt-del.target is active, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71991" >> RHE7findings.txt
echo "Group Title: SRG-OS-000445-GPOS-00199" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must enable the SELinux targeted policy." >> RHE7findings.txt
echo "Discussion: Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
sestatus &>> RHE7findings.txt
echo "Finding: If the 'Loaded policy name' is not set to 'targeted', this is a finding." >> RHE7findings.txt 
grep -i "selinuxtype" /etc/selinux/config | grep -v '^#' &>> RHE7findings.txt
echo "Finding: If no results are returned or 'SELINUXTYPE' is not set to 'targeted', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71989" >> RHE7findings.txt
echo "Group Title: SRG-OS-000445-GPOS-00199" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must enable SELinux." >> RHE7findings.txt
echo "Discussion: Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
getenforce &>> RHE7findings.txt
echo "Finding: If 'SELinux' is not active and not in 'Enforcing' mode, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71987" >> RHE7findings.txt
echo "Group Title: SRG-OS-000437-GPOS-00194" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must remove all software components after updated versions have been installed." >> RHE7findings.txt
echo "Discussion: Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i clean_requirements_on_remove /etc/yum.conf &>> RHE7findings.txt
echo "Finding: If 'clean_requirements_on_remove' is not set to '1', 'True', or 'yes', or is not set in '/etc/yum.conf', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71985" >> RHE7findings.txt
echo "Group Title: SRG-OS-000114-GPOS-00059" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must disable the file system automounter unless required." >> RHE7findings.txt
echo "Discussion: Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
systemctl status autofs &>> RHE7findings.txt
echo "Finding: If the 'autofs' status is set to 'active' and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71983" >> RHE7findings.txt
echo "Group Title: SRG-OS-000114-GPOS-00059" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured to disable USB mass storage." >> RHE7findings.txt
echo "Discussion: USB mass storage permits easy introduction of unknown devices, thereby facilitating malicious activity." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -r usb-storage /etc/modprobe.d/* | grep -i "/bin/true" | grep -v "^#" &>> RHE7findings.txt
echo "Finding: If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding." >> RHE7findings.txt 
grep usb-storage /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#" &>> RHE7findings.txt
echo "Finding: If the command does not return any output or the output is not 'blacklist usb-storage', and use of USB storage devices is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71979" >> RHE7findings.txt
echo "Group Title: SRG-OS-000366-GPOS-00153" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization." >> RHE7findings.txt
echo "Discussion: Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.
Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.
Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep localpkg_gpgcheck /etc/yum.conf &>> RHE7findings.txt
echo "Finding: If there is no process to validate the signatures of local packages that is approved by the organization, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt




echo "V-71977" >> RHE7findings.txt
echo "Group Title: SRG-OS-000366-GPOS-00153" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization." >> RHE7findings.txt
echo "Discussion: Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.
Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.
Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep gpgcheck /etc/yum.conf &>> RHE7findings.txt
echo "Finding: If there is no process to validate certificates that is approved by the organization, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71975" >> RHE7findings.txt
echo "Group Title: SRG-OS-000363-GPOS-00150" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that designated personnel are notified if baseline configurations are changed in an unauthorized manner." >> RHE7findings.txt
echo "Discussion: Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.
Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed aide &>> RHE7findings.txt
ls -al /etc/cron.* | grep aide &>> RHE7findings.txt
grep aide /etc/crontab /var/spool/cron/root &>> RHE7findings.txt
more /etc/cron.daily/aide &>> RHE7findings.txt

echo "Finding: If the file integrity application does not notify designated personnel of changes, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71973" >> RHE7findings.txt
echo "Group Title: SRG-OS-000363-GPOS-00150" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that a file integrity tool verifies the baseline operating system configuration at least weekly." >> RHE7findings.txt
echo "Discussion: Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.
Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed aide &>> RHE7findings.txt
ls -al /etc/cron.* | grep aide &>> RHE7findings.txt
grep aide /etc/crontab /var/spool/cron/root &>> RHE7findings.txt
echo "Finding: If the file integrity application does not exist, or a script file controlling the execution of the file integrity application does not exist, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71971" >> RHE7findings.txt
echo "Group Title: SRG-OS-000324-GPOS-00125" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures." >> RHE7findings.txt
echo "Discussion: Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.
Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
semanage login -l | more &>> RHE7findings.txt
echo "Finding: If they are not mapped in this way, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71969" >> RHE7findings.txt
echo "Group Title: SRG-OS-000095-GPOS-00049" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not have the ypserv package installed." >> RHE7findings.txt
echo "Discussion: Removing the 'ypserv' package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed ypserv &>> RHE7findings.txt
echo "Finding: If the 'ypserv' package is installed, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71967" >> RHE7findings.txt
echo "Group Title: SRG-OS-000095-GPOS-00049" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not have the rsh-server package installed." >> RHE7findings.txt
echo "Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.
Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
The rsh-server service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session and has very weak authentication.
If a privileged user were to log on using this service, the privileged user password could be compromised." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed rsh-server &>> RHE7findings.txt
echo "Finding: If the rsh-server package is installed, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71965" >> RHE7findings.txt
echo "Group Title: SRG-OS-000104-GPOS-00051" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication." >> RHE7findings.txt
echo "Discussion: To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.
Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following:
1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; 
and
2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
authconfig --test | grep "pam_pkcs11 is enabled" &>> RHE7findings.txt
echo "Finding: If no results are returned, this is a finding." >> RHE7findings.txt 
authconfig --test | grep "smartcard removal action" &>> RHE7findings.txt
echo "Finding: If 'smartcard removal action' is blank, this is a finding." >> RHE7findings.txt 
authconfig --test | grep "smartcard module" &>> RHE7findings.txt
echo "Finding: If 'smartcard module' is blank, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71963" >> RHE7findings.txt
echo "Group Title: SRG-OS-000080-GPOS-00048" >> RHE7findings.txt
echo "Rule Title: Red Hat Enterprise Linux operating systems prior to version 7.2 using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes." >> RHE7findings.txt
echo "Discussion: If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i password /boot/efi/EFI/redhat/grub.cfg &>> RHE7findings.txt
echo "Finding: If the root password entry does not begin with 'password_pbkdf2', this is a finding.
If the 'superusers-account' is not set to 'root', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71961" >> RHE7findings.txt
echo "Group Title: SRG-OS-000080-GPOS-00048" >> RHE7findings.txt
echo "Rule Title: Red Hat Enterprise Linux operating systems prior to version 7.2 with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes." >> RHE7findings.txt
echo "Discussion: If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i password_pbkdf2 /boot/grub2/grub.cfg &>> RHE7findings.txt
echo "Finding: If the root password entry does not begin with 'password_pbkdf2', this is a finding.
If the 'superusers-account' is not set to 'root', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71959" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00229" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not allow a non-certificate trusted host SSH logon to the system." >> RHE7findings.txt
echo "Discussion: Failure to restrict system access to authenticated users negatively impacts operating system security." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i hostbasedauthentication /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the 'HostbasedAuthentication' keyword is not set to 'no', is missing, or is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71957" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00229" >> RHE7findings.txt
echo "Rule Title:  The Red Hat Enterprise Linux operating system must not allow users to override SSH environment variables." >> RHE7findings.txt
echo "Discussion: Failure to restrict system access to authenticated users negatively impacts operating system security." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
 grep -i permituserenvironment /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the 'PermitUserEnvironment' keyword is not set to 'no', is missing, or is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71955" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00229" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not allow an unrestricted logon to the system." >> RHE7findings.txt
echo "Discussion: Failure to restrict system access to authenticated users negatively impacts operating system security." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i timedloginenable /etc/gdm/custom.conf &>> RHE7findings.txt
echo "Finding: If the value of 'TimedLoginEnable' is not set to 'false', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71953" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00229" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not allow an unattended or automatic logon to the system via a graphical user interface." >> RHE7findings.txt
echo "Discussion: Failure to restrict system access to authenticated users negatively impacts operating system security." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i automaticloginenable /etc/gdm/custom.conf &>> RHE7findings.txt
echo "Finding: If the value of 'AutomaticLoginEnable' is not set to 'false', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71951" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00226" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the delay between logon prompts following a failed console logon attempt is at least four seconds." >> RHE7findings.txt
echo "Discussion: Configuring the operating system to implement organization-wide security implementation guides and security checklists verifies compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.
Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i fail_delay /etc/login.defs &>> RHE7findings.txt
echo "Finding: If the value of 'FAIL_DELAY' is not set to '4' or greater, or the line is commented out, this is a finding" >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71949" >> RHE7findings.txt
echo "Group Title: SRG-OS-000373-GPOS-00156" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that users must re-authenticate for privilege escalation." >> RHE7findings.txt
echo "Discussion: Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 
When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i authenticate /etc/sudoers /etc/sudoers.d/* &>> RHE7findings.txt
echo "Finding: If any uncommented line is found with a '!authenticate' tag, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71947" >> RHE7findings.txt
echo "Group Title: SRG-OS-000373-GPOS-00156" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that users must provide a password for privilege escalation." >> RHE7findings.txt
echo "Discussion: Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 
When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i nopasswd /etc/sudoers /etc/sudoers.d/* &>> RHE7findings.txt
echo "Finding: If any uncommented line is found with a 'NOPASSWD' tag, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71945" >> RHE7findings.txt
echo "Group Title: SRG-OS-000329-GPOS-00128" >> RHE7findings.txt
echo "Rule Title:  The Red Hat Enterprise Linux operating system must lock the associated account after three unsuccessful root logon attempts are made within a 15-minute period." >> RHE7findings.txt
echo "Discussion: By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep pam_faillock.so /etc/pam.d/password-auth &>> RHE7findings.txt
echo "Finding: If the 'even_deny_root' setting is not defined on both lines with the 'pam_faillock.so' module, is commented out, or is missing from a line, this is a finding." >> RHE7findings.txt 
grep pam_faillock.so /etc/pam.d/system-auth &>> RHE7findings.txt
echo "Finding: If the 'even_deny_root' setting is not defined on both lines with the 'pam_faillock.so' module, is commented out, or is missing from a line, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71943" >> RHE7findings.txt
echo "Group Title: SRG-OS-000329-GPOS-00128" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured to lock accounts for a minimum of 15 minutes after three unsuccessful logon attempts within a 15-minute timeframe." >> RHE7findings.txt
echo "Discussion: By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt

grep pam_faillock.so /etc/pam.d/password-auth &>> RHE7findings.txt
echo " Finding: If the 'deny' parameter is set to '0' or a value less than '3' on both 'auth' lines with the 'pam_faillock.so' module, or is missing from these lines, this is a finding.
If the 'even_deny_root' parameter is not set on both 'auth' lines with the 'pam_faillock.so' module, or is missing from these lines, this is a finding.
If the 'fail_interval' parameter is set to '0' or is set to a value less than '900' on both 'auth' lines with the 'pam_faillock.so' module, or is missing from these lines, this is a finding.
If the 'unlock_time' parameter is not set to '0', 'never', or is set to a value less than '900' on both 'auth' lines with the 'pam_faillock.so' module, or is missing from these lines, this is a finding.
Note: The maximum configurable value for 'unlock_time' is '604800'. 
If any line referencing the 'pam_faillock.so' module is commented out, this is a finding." >> RHE7findings.txt 

grep pam_faillock.so /etc/pam.d/system-auth &>> RHE7findings.txt
echo "Finding: If the 'deny' parameter is set to '0' or a value less than '3' on both 'auth' lines with the 'pam_faillock.so' module, or is missing from these lines, this is a finding.
If the 'even_deny_root' parameter is not set on both 'auth' lines with the 'pam_faillock.so' module, or is missing from these lines, this is a finding.
If the 'fail_interval' parameter is set to '0' or is set to a value less than '900' on both 'auth' lines with the 'pam_faillock.so' module, or is missing from these lines, this is a finding.
If the 'unlock_time' parameter is not set to '0', 'never', or is set to a value less than '900' on both 'auth' lines with the 'pam_faillock.so' module or is missing from these lines, this is a finding.
Note: The maximum configurable value for 'unlock_time' is '604800'. 
If any line referencing the 'pam_faillock.so' module is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71941" >> RHE7findings.txt
echo "Group Title: SRG-OS-000118-GPOS-00060" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires." >> RHE7findings.txt
echo "Discussion: Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.
Operating systems need to track periods of inactivity and disable application identifiers after zero days of inactivity." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i inactive /etc/default/useradd &>> RHE7findings.txt
echo "Finding: If the value is not set to '0', is commented out, or is not defined, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71939" >> RHE7findings.txt
echo "Group Title: SRG-OS-000106-GPOS-00053" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using an empty password." >> RHE7findings.txt
echo "Discussion: Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i PermitEmptyPasswords /etc/ssh/sshd_config &>> RHE7findings.txt
echo "Finding: If the required value is not set, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71937" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must not have accounts configured with blank or null passwords." >> RHE7findings.txt
echo "Discussion: If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth &>> RHE7findings.txt
echo "Finding: If null passwords can be used, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71935" >> RHE7findings.txt
echo "Group Title: SRG-OS-000078-GPOS-00046" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that passwords are a minimum of 15 characters in length." >> RHE7findings.txt
echo "Discussion: The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.
Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep minlen /etc/security/pwquality.conf &>> RHE7findings.txt
echo "Finding: If the command does not return a 'minlen' value of 15 or greater, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71933" >> RHE7findings.txt
echo "Group Title: SRG-OS-000077-GPOS-00045" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that passwords are prohibited from reuse for a minimum of five generations." >> RHE7findings.txt
echo "Discussion: Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth &>> RHE7findings.txt
echo "Finding: If the line containing the 'pam_pwhistory.so' line does not have the 'remember' module argument set, is commented out, or the value of the 'remember' module argument is set to less than '5', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71931" >> RHE7findings.txt
echo "Group Title: SRG-OS-000076-GPOS-00044" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that existing passwords are restricted to a 60-day maximum lifetime." >> RHE7findings.txt
echo "Discussion: Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow &>> RHE7findings.txt
echo "Finding: If any results are returned that are not associated with a system account, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71929" >> RHE7findings.txt
echo "Group Title: SRG-OS-000076-GPOS-00044" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that passwords for new users are restricted to a 60-day maximum lifetime." >> RHE7findings.txt
echo "Discussion:  Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i pass_max_days /etc/login.defs &>> RHE7findings.txt
echo "Finding: If the 'PASS_MAX_DAYS' parameter value is not 60 or less, or is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71927" >> RHE7findings.txt
echo "Group Title: SRG-OS-000075-GPOS-00043" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that passwords are restricted to a 24 hours/1 day minimum lifetime." >> RHE7findings.txt
echo "Discussion: Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow &>> RHE7findings.txt
echo "Finding: If any results are returned that are not associated with a system account, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71925" >> RHE7findings.txt
echo "Group Title: SRG-OS-000075-GPOS-00043" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that passwords for new users are restricted to a 24 hours/1 day minimum lifetime." >> RHE7findings.txt
echo "Discussion: Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i pass_min_days /etc/login.defs &>> RHE7findings.txt
echo "Finding: If the 'PASS_MIN_DAYS' parameter value is not '1' or greater, or is commented out, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71923" >> RHE7findings.txt
echo "Group Title:  SRG-OS-000073-GPOS-00041" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that user and group account administration utilities are configured to store only encrypted representations of password" >> RHE7findings.txt
echo "Discussion:  Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i sha512 /etc/libuser.conf &>> RHE7findings.txt
echo "Finding: If the 'crypt_style' variable is not set to 'sha512', is not in the defaults section, is commented out, or does not exist, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71921" >> RHE7findings.txt
echo "Group Title: SRG-OS-000073-GPOS-00041" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured to use the shadow file to store only encrypted representations of passwords" >> RHE7findings.txt
echo "Discussion: Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i encrypt /etc/login.defs &>> RHE7findings.txt
echo "Finding: If the '/etc/login.defs' configuration file does not exist or allows for password hashes other than SHA512 to be used, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71919" >> RHE7findings.txt
echo "Group Title:  SRG-OS-000073-GPOS-00041" >> RHE7findings.txt
echo "Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that the PAM system service is configured to store only encrypted representations of passwords." >> RHE7findings.txt
echo "Discussion: Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep password /etc/pam.d/system-auth /etc/pam.d/password-auth &>> RHE7findings.txt
echo "Finding: If the '/etc/pam.d/system-auth' and '/etc/pam.d/password-auth' configuration files allow for password hashes other than SHA512 to be used, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71917" >> RHE7findings.txt
echo "Group Title:SRG-OS-000072-GPOS-00040" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed the number of repeating characters of the same character class must not be more than four characters." >> RHE7findings.txt
echo "Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep maxclassrepeat /etc/security/pwquality.conf  &>> RHE7findings.txt
echo "Finding: If the value of 'maxclassrepeat' is set to more than '4', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71915" >> RHE7findings.txt
echo "Group Title: SRG-OS-000072-GPOS-00040" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed the number of repeating consecutive characters must not be more than three characters." >> RHE7findings.txt
echo "Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep maxrepeat /etc/security/pwquality.conf  &>> RHE7findings.txt
echo "Finding: If the value of 'maxrepeat' is set to more than '3', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71913" >> RHE7findings.txt
echo "Group Title: SRG-OS-000072-GPOS-00040" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed a minimum of four character classes must be changed." >> RHE7findings.txt
echo "Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised" >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep minclass /etc/security/pwquality.conf  &>> RHE7findings.txt
echo "Finding: If the value of 'minclass' is set to less than '4', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71911" >> RHE7findings.txt
echo "Group Title: SRG-OS-000072-GPOS-00040" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed a minimum of eight of the total number of characters must be changed." >> RHE7findings.txt
echo "Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep difok /etc/security/pwquality.conf &>> RHE7findings.txt
echo "Finding: If the value of 'difok' is set to less than '8', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71909" >> RHE7findings.txt
echo "Group Title: SRG-OS-000266-GPOS-00101" >> RHE7findings.txt
echo "Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one special character." >> RHE7findings.txt
echo "Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep ocredit /etc/security/pwquality.conf  &>> RHE7findings.txt
echo "Finding: If the value of 'ocredit' is not set to a negative value, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71907" >> RHE7findings.txt
echo "Group Title: SRG-OS-000071-GPOS-00039" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are assigned, the new password must contain at least one numeric character." >> RHE7findings.txt
echo "Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep dcredit /etc/security/pwquality.conf  &>> RHE7findings.txt
echo "Finding: If the value of 'dcredit' is not set to a negative value, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71905" >> RHE7findings.txt
echo "Group Title: SRG-OS-000070-GPOS-00038" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one lower-case character." >> RHE7findings.txt
echo "Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep lcredit /etc/security/pwquality.conf  &>> RHE7findings.txt
echo "Finding: If the value of 'lcredit' is not set to a negative value, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71903" >> RHE7findings.txt
echo "Group Title: SRG-OS-000069-GPOS-00037" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one upper-case character." >> RHE7findings.txt
echo "Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep ucredit /etc/security/pwquality.conf  &>> RHE7findings.txt
echo "Finding: If the value of 'ucredit' is not set to a negative value, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71901" >> RHE7findings.txt
echo "Group Title: SRG-OS-000029-GPOS-00010" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must initiate a session lock for graphical user interfaces when the screensaver is activated." >> RHE7findings.txt
echo "Discussion: A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
The session lock is implemented at the point where session activity can be determined and/or controlled." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i lock-delay /etc/dconf/db/local.d/* &>> RHE7findings.txt
echo "Finding: If the 'lock-delay' setting is missing, or is not set to '5' or less, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71899" >> RHE7findings.txt
echo "Group Title: SRG-OS-000029-GPOS-00010" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces." >> RHE7findings.txt
echo "Discussion: A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
The session lock is implemented at the point where session activity can be determined and/or controlled." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i idle-activation-enabled /etc/dconf/db/local.d/* &>> RHE7findings.txt
echo "Finding: If 'idle-activation-enabled' is not set to 'true', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71897" >> RHE7findings.txt
echo "Group Title: SRG-OS-000029-GPOS-00010" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must have the screen package installed." >> RHE7findings.txt
echo "Discussion: A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
The screen and tmux packages allow for a session lock to be implemented and configured." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
yum list installed screen &>> RHE7findings.txt
yum list installed tmux &>> RHE7findings.txt
echo "Finding: If either the screen package or the tmux package is not installed, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71893" >> RHE7findings.txt
echo "Group Title: SRG-OS-000029-GPOS-00010" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces." >> RHE7findings.txt
echo "Discussion: A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
The session lock is implemented at the point where session activity can be determined and/or controlled" >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i idle-delay /etc/dconf/db/local.d/* &>> RHE7findings.txt
echo "Finding: If the 'idle-delay' setting is missing or is not set to '900' or less, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71891" >> RHE7findings.txt
echo "Group Title: SRG-OS-000028-GPOS-00009" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures." >> RHE7findings.txt
echo "Discussion:  A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.
The session lock is implemented at the point where session activity can be determined.
Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep -i lock-enabled /etc/dconf/db/local.d/* &>> RHE7findings.txt
echo "Finding: If the 'lock-enabled' setting is missing or is not set to 'true', this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71863" >> RHE7findings.txt
echo "Group Title: SRG-OS-000023-GPOS-00006" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon." >> RHE7findings.txt
echo "Discussion: Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
more /etc/issue &>> RHE7findings.txt
echo "Finding: If the operating system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.
If the text in the '/etc/issue' file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71861" >> RHE7findings.txt
echo "Group Title: SRG-OS-000023-GPOS-00006" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must display the approved Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon." >> RHE7findings.txt
echo "Discussion:  Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep banner-message-text /etc/dconf/db/local.d/* &>> RHE7findings.txt
echo "Finding: If the banner does not match the approved Standard Mandatory DoD Notice and Consent Banner, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71859" >> RHE7findings.txt
echo "Group Title: SRG-OS-000023-GPOS-00006" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon." >> RHE7findings.txt
echo "Discussion: Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
grep banner-message-enable /etc/dconf/db/local.d/* &>> RHE7findings.txt
echo "Finding: If 'banner-message-enable' is set to 'false' or is missing, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71855" >> RHE7findings.txt
echo "Group Title: SRG-OS-000480-GPOS-00227" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the cryptographic hash of system files and commands matches vendor values." >> RHE7findings.txt
echo "Discussion: Without cryptographic integrity protections, system command and files can be altered by unauthorized users without detection.
Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
rpm -Va --noconfig | grep '^..5' &>> RHE7findings.txt
echo "Finding: If there is any output from the command for system files or binaries, this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt


echo "V-71849" >> RHE7findings.txt
echo "Group Title: SRG-OS-000257-GPOS-00098" >> RHE7findings.txt
echo "Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the file permissions, ownership, and group membership of system files and commands match the vendor values." >> RHE7findings.txt
echo "Discussion: Discretionary access control is weakened if a user or group has access permissions to system files and directories greater than the default." >> RHE7findings.txt
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt
for i in `rpm -Va | egrep -i '^\.[M|U|G|.]{8}' | cut -d " " -f4,5`;do for j in `rpm -qf $i`;do rpm -ql $j --dump | cut -d " " -f1,5,6,7 | grep $i;done;done &>> RHE7findings.txt

echo "Finding: If the file is more permissive than the default permissions, this is a finding.
If the file is not owned by the default owner and is not documented with the Information System Security Officer (ISSO), this is a finding.
If the file is not a member of the default group and is not documented with the Information System Security Officer (ISSO), this is a finding." >> RHE7findings.txt 
echo "|---------------------------------------------------------------------|"  >> RHE7findings.txt