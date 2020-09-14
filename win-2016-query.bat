@echo off
 
	echo "V-78125" > query.txt 
	reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mrxsmb10 " /v "Start" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Smart Card removal option must be configured to Force Logoff or Lock Workstation. " >> Win2016.txt
 	echo "Discussion: Unattended systems are susceptible to unauthorized use and must be locked. Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended."  >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-78123" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ " /v "SMB1" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Server Message Block (SMB) v1 protocol must be disabled on the SMB server. " >> Win2016.txt
 	echo "Discussion: SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73807" >> Win2016.txt
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ " /v "REG_SZ" >> Win2016.txt 
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Smart Card removal option must be configured to Force Logoff or Lock Workstation. " >> Win2016.txt
 	echo "Discussion: Unattended systems are susceptible to unauthorized use and must be locked. Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73727" >> Win2016.txt
	reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\ " /v "SaveZoneInformation" >> Win2016.txt 
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Zone information must be preserved when saving attachments. " >> Win2016.txt
 	echo "Discussion: Attachments from outside sources may contain malicious code. Preserving zone of origin (Internet, intranet, local, restricted) information on file attachments allows Windows to determine risk." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73721" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "EnableLUA" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: User Account Control must virtualize file and registry write failures to per-user locations." >> Win2016.txt
 	echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures non-UAC-compliant applications to run in virtualized file and registry entries in per-user locations, allowing them to run." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73719" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "EnableSecureUIAPaths" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title:User Account Control must run all administrators in Admin Approval Mode, enabling UAC. ">> Win2016.txt
 	echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting enables UAC." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73717" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "EnableSecureUIAPaths" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: User Account Control must only elevate UIAccess applications that are installed in secure locations." >> Win2016.txt
 	echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures Windows to only allow applications installed in a secure location on the file system, such as the Program Files or the Windows\System32 folders, to run with elevated privileges." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73715" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "EnableInstallerDetection" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: User Account Control must be configured to detect application installations and prompt for elevation." >> Win2016.txt
 	echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting requires Windows to respond to application installation requests by prompting for credentials." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73713" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\  " /v "ConsentPromptBehaviorUser" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: User Account Control must automatically deny standard user requests for elevation." >> Win2016.txt
 	echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting controls the behavior of elevation when requested by a standard user account." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73711" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\  " /v "ConsentPromptBehaviorAdmin" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: User Account Control must, at a minimum, prompt administrators for consent on the secure desktop." >> Win2016.txt
 	echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the elevation requirements for logged-on administrators to complete a task that requires raised privileges." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73709" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "EnableUIADesktopToggle" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: " >> Win2016.txt
 	echo "Discussion: " >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73707" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "FilterAdministratorToken" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: UIAccess applications must not be allowed to prompt for elevation without using the secure desktop." >> Win2016.txt
 	echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting prevents User Interface Accessibility programs from disabling the secure desktop for elevation prompts." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73705" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\ " /v "ProtectionMode" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The default permissions of global system objects must be strengthened." >> Win2016.txt
 	echo "Discussion: Windows systems maintain a global list of shared system resources such as DOS device names, mutexes, and semaphores. Each type of object is created with a default Discretionary Access Control List (DACL) that specifies who can access the objects with what permissions. When this policy is enabled, the default DACL is stronger, allowing non-administrative users to read shared objects but not to modify shared objects they did not create." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73701" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\ " /v "Enabled" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Windows Server 2016 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing." >> Win2016.txt
 	echo "Discussion: This setting ensures the system uses algorithms that are FIPS-compliant for encryption, hashing, and signing. FIPS-compliant algorithms meet specific standards established by the U.S. Government and must be the algorithms used for all OS encryption functions." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73699" >> Win2016.txt
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\ " /v "ForceKeyProtection" >> Win2016.txt 
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Users must be required to enter a password to access private keys stored on the computer." >> Win2016.txt
 	echo "Discussion: If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure...." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73697" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\ " /v "NTLMMinServerSec" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption." >> Win2016.txt
 	echo "Discussion: Microsoft has implemented a variety of security support providers for use with Remote Procedure Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73695" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\ " /v "NTLMMinClientSec" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption." >> Win2016.txt
 	echo "Discussion: Microsoft has implemented a variety of security support providers for use with Remote Procedure Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73693" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\ " /v "LDAPClientIntegrity" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Windows Server 2016 must be configured to at least negotiate signing for LDAP client signing." >> Win2016.txt
 	echo "Discussion: This setting controls the signing requirements for LDAP clients. This must be set to 'Negotiate signing' or 'Require signing', depending on the environment and type of LDAP server in use." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73691" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ " /v "LmCompatibilityLevel" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The LAN Manager authentication level must be set to send NTLMv2 response only and to refuse LM and NTLM." >> Win2016.txt
 	echo "Discussion: The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts. NTLM, which is less secure, is retained in later Windows versions for compatibility with clients and servers that are running earlier versions of Windows or applications that still use it. It is also used to authenticate logons to standalone computers that are running later versions." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73687" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ " /v "NoLMHash" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Windows Server 2016 must be configured to prevent the storage of the LAN Manager hash of passwords." >> Win2016.txt
 	echo "Discussion: The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords. This setting controls whether a LAN Manager hash of the password is stored in the SAM the next time the password is changed." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73685" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\ " /v "SupportedEncryptionTypes" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites." >> Win2016.txt
 	echo "Discussion: Certain encryption types are no longer considered secure. The DES and RC4 encryption suites must not be used for Kerberos encryption. Note: Organizations with domain controllers running earlier versions of Windows where RC4 encryption is enabled, selecting 'The other domain supports Kerberos AES Encryption' on domain trusts, may be required to allow client communication across the trust relationship." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73683" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\pku2u\ " /v "AllowOnlineID" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: PKU2U authentication using online identities must be prevented." >> Win2016.txt
 	echo "Discussion: PKU2U is a peer-to-peer authentication protocol. This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts. " >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73681" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\ " /v "allownullsessionfallback" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: NTLM must be prevented from falling back to a Null session. " >> Win2016.txt
 	echo "Discussion: NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73679"  >> Win2016.txt
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\ " /v "UseMachineId" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously." >> Win2016.txt
 	echo "Discussion: Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously versus using the computer identity." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	

	echo "V-73677" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ " /v "RestrictRemoteSAM" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Remote calls to the Security Account Manager (SAM) must be restricted to Administrators." >> Win2016.txt
 	echo "Discussion: The Windows Security Account Manager (SAM) stores users' passwords. Restricting Remote Procedure Call (RPC) connections to the SAM to Administrators helps protect those credentials." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73675" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\ " /v "RestrictNullSessAccess" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Anonymous access to Named Pipes and Shares must be restricted." >> Win2016.txt
 	echo "Discussion: Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access. This setting restricts access to those defined in 'Network access: Named Pipes that can be accessed anonymously' and 'Network access: Shares that can be accessed anonymously', both of which must be blank under other requirements." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73673" >> Win2016.txt
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ " /v "EveryoneIncludesAnonymous" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Windows Server 2016 must be configured to prevent anonymous users from having the same permissions as the Everyone group." >> Win2016.txt
 	echo "Discussion: Access by anonymous users must be restricted. If this setting is enabled, anonymous users have the same rights and permissions as the built-in Everyone group. Anonymous users must not have these permissions or rights." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	

	echo "V-73669" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ " /v "RestrictAnonymous" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Anonymous enumeration of shares must not be allowed. " >> Win2016.txt
 	echo "Discussion: Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73667" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ " /v "RestrictAnonymousSAM" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Anonymous enumeration of Security Account Manager (SAM) accounts must not be allowed." >> Win2016.txt
 	echo "Discussion: Anonymous enumeration of SAM accounts allows anonymous logon users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73663" >> Win2016.txt
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ " /v "EnableSecuritySignature" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled." >> Win2016.txt
 	echo "Discussion: The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will negotiate SMB packet signing as requested by the client." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	

	echo "V-73661" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ " /v "RequireSecuritySignature" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title:  The setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled. " >> Win2016.txt
 	echo "Discussion: The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will only communicate with an SMB client that performs SMB packet signing." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73657" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\ " /v "EnablePlainTextPassword" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers." >> Win2016.txt
 	echo "Discussion: Some non-Microsoft SMB servers only support unencrypted (plain-text) password authentication. Sending plain-text passwords across the network when authenticating to an SMB server reduces the overall security of the environment. Check with the vendor of the SMB server to determine if there is a way to support encrypted password authentication." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73655" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\ " /v "EnableSecuritySignature" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled." >> Win2016.txt
 	echo "Discussion: The server message block (SMB) protocol provides the basis for many network operations. If this policy is enabled, the SMB client will request packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73653" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\ " /v "RequireSecuritySignature" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled." >> Win2016.txt
 	echo "Discussion: The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB client will only communicate with an SMB server that performs SMB packet signing." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73651" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ " /v "CachedLogonsCount" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Caching of logon credentials must be limited." >> Win2016.txt
 	echo "Discussion: The default Windows configuration caches the last logon credentials for users who log on interactively to a system. This feature is provided for system availability reasons, such as the user's machine being disconnected from the network or domain controllers being unavailable. Even though the credential cache is well protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73649" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "LegalNoticeCaption" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Windows dialog box title for the legal banner must be configured with the appropriate text." >> Win2016.txt
 	echo "Discussion: Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources. Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000228-GPOS-00088" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

    echo "V-73647" >> Win2016.txt 
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "LegalNoticeText" >> Win2016.txt
    IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
    echo "Rule Title: The required legal notice must be configured to display before console logon." >> Win2016.txt
 	echo "Discussion: Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources. Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007, SRG-OS-000228-GPOS-00088" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73645" >> Win2016.txt
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "InactivityTimeoutSecs" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The machine inactivity limit must be set to 15 minutes, locking the system with the screen saver. " >> Win2016.txt
 	echo "Discussion: Unattended systems are susceptible to unauthorized use and should be locked when unattended. The screen saver should be set at a maximum of 15 minutes and be password protected. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73643" >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ " /v "RequireStrongKey" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Windows Server 2016 must be configured to require a strong session key." >> Win2016.txt
 	echo "Discussion: A computer connecting to a domain controller will establish a secure channel. The secure channel connection may be subject to compromise, such as hijacking or eavesdropping, if strong session keys are not used to establish the connection. Requiring strong session keys enforces 128-bit encryption between systems. Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
    
    echo "V-73641" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ " /v "MaximumPasswordAge" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The maximum age for machine account passwords must be configured to 30 days or less." >> Win2016.txt
 	echo "Discussion: Computer account passwords are changed automatically on a regular basis. This setting controls the maximum password age that a machine account may have. This must be set to no more than 30 days, ensuring the machine changes its password monthly." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73639" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ " /v "DisablePasswordChange" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The computer account password must not be prevented from being reset. " >> Win2016.txt
 	echo "Discussion: Computer account passwords are changed automatically on a regular basis. Disabling automatic password changes can make the system more vulnerable to malicious access. Frequent password changes can be a significant safeguard for the system. A new password for the computer account will be generated every 30 days." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73637" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ " /v "SignSecureChannel" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled." >> Win2016.txt
 	echo "Discussion: Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but the channel is not integrity checked. If this policy is enabled, outgoing secure channel traffic will be signed. Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
    
    echo "V-73635" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ " /v "SealSecureChannel" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to enabled." >> Win2016.txt
 	echo "Discussion: Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted. Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73633" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ " /v "RequireSignOrSeal" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled." >> Win2016.txt
 	echo "Discussion: Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted and signed. Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73631" >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ " /v "RefusePasswordChange" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Domain controllers must be configured to allow reset of machine account passwords." >> Win2016.txt
 	echo "Discussion: Enabling this setting on all domain controllers in a domain prevents domain members from changing their computer account passwords. If these passwords are weak or compromised, the inability to change them may leave these computers vulnerable." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
    
    echo "V-73629" >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\ " /v "LDAPServerIntegrity" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Domain controllers must require LDAP access signing." >> Win2016.txt
 	echo "Discussion: Unsigned network traffic is susceptible to man-in-the-middle attacks, where an intruder captures packets between the server and the client and modifies them before forwarding them to the client. In the case of an LDAP server, this means that an attacker could cause a client to make decisions based on false records from the LDAP directory. The risk of an attacker pulling this off can be decreased by implementing strong physical security measures to protect the network infrastructure. Furthermore, implementing Internet Protocol security (IPsec) authentication header mode (AH), which performs mutual authentication and packet integrity for Internet Protocol (IP) traffic, can make all types of man-in-the-middle attacks extremely difficult. Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73627" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ " /v "SCENoApplyLegacyAuditPolicy" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Audit policy using subcategories must be enabled." >> Win2016.txt
 	echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. This setting allows administrators to enable more precise auditing capabilities." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73621" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ " /v "LimitBlankPasswordUse" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Local accounts with blank passwords must be restricted to prevent access from the network." >> Win2016.txt
 	echo "Discussion: An account without a password can allow unauthorized access to a system as only the username would be required. Password policies should prevent accounts with blank passwords from existing on a system. However, if a local account with a blank password does exist, enabling this setting will prevent network access, limiting the account to local console logon only." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
    
    echo "V-73603" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\ " /v "DisableRunAs" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Windows Remote Management (WinRM) service must not store RunAs credentials." >> Win2016.txt
 	echo "Discussion:  Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73601" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\ " /v "AllowUnencryptedTraffic" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: " >> Win2016.txt
 	echo "Discussion: " >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73599" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\ " /v "AllowBasic" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Windows Remote Management (WinRM) service must not allow unencrypted traffic." >> Win2016.txt
 	echo "Discussion: Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this. Satisfies: SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
    
    echo "V-73597" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\ " /v "AllowDigest" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Windows Remote Management (WinRM) client must not use Digest authentication." >> Win2016.txt
 	echo "Discussion: Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks. Disallowing Digest authentication will reduce this potential." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73595"  >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\ " /v "AllowUnencryptedTraffic" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Windows Remote Management (WinRM) client must not allow unencrypted traffic." >> Win2016.txt
 	echo "Discussion: Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this. Satisfies: SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73593" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\ " /v "AllowBasic" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Windows Remote Management (WinRM) client must not use Basic authentication." >> Win2016.txt
 	echo "Discussion: Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73591" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\ Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\ " /v "EnableScriptBlockLogging" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: PowerShell script block logging must be enabled." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73589" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "DisableAutomaticRestartSignOn" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Automatically signing in the last interactive user after a system-initiated restart must be disabled." >> Win2016.txt
 	echo "Discussion: Windows can be configured to automatically sign the user back in after a Windows Update restart. Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73587" >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\ " /v "SafeForScripting" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Users must be notified if a web-based program attempts to install software." >> Win2016.txt
 	echo "Discussion: Web-based programs may attempt to install malicious software on a system. Ensuring users are notified if a web-based program attempts to install software allows them to refuse the installation. " >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73585" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\ " /v "AlwaysInstallElevated" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Windows Installer Always install with elevated privileges option must be disabled. " >> Win2016.txt
 	echo "Discussion: Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73583" >> Win2016.txt    
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\ " /v "EnableUserControl" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Users must be prevented from changing installation options. " >> Win2016.txt
 	echo "Discussion: Installation options for applications are typically controlled by administrators. This setting prevents users from changing installation options that may bypass security features." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73581" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\ " /v "AllowIndexingEncryptedStoresOrItems" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Indexing of encrypted files must be turned off." >> Win2016.txt
 	echo "Discussion: Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files from being indexed." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73579" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\  " /v "AllowBasicAuthInClear" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Basic authentication for RSS feeds over HTTP must not be used." >> Win2016.txt
 	echo "Discussion: Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73577" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\ " /v "DisableEnclosureDownload" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Attachments must be prevented from being downloaded from RSS feeds." >> Win2016.txt
 	echo "Discussion: Attachments from RSS feeds may not be secure. This setting will prevent attachments from being downloaded from RSS feeds." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73575" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\ " /v "MinEncryptionLevel" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Remote Desktop Services must be configured with the client connection encryption set to High Level." >> Win2016.txt
 	echo "Discussion: Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73573" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\ " /v "fEncryptRPCTraffic" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Remote Desktop Session Host must require secure Remote Procedure Call (RPC) communications." >> Win2016.txt
 	echo "Discussion: Allowing unsecure RPC communication exposes the system to man-in-the-middle attacks and data disclosure attacks. A man-in-the-middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73571" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\ " /v "fPromptForPassword" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Remote Desktop Services must always prompt a client for passwords upon connection." >> Win2016.txt
 	echo "Discussion: This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73569" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\ " /v "fDisableCdm" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Local drives must be prevented from sharing with Remote Desktop Session Hosts." >> Win2016.txt
 	echo "Discussion: Preventing users from sharing the local drives on their client computers with Remote Session Hosts that they access helps reduce possible exposure of sensitive data." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73567" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\ " /v "DisablePasswordSaving" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Passwords must not be saved in the Remote Desktop Client." >> Win2016.txt
 	echo "Discussion: Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system. The system must be configured to prevent users from saving passwords in the Remote Desktop Client.Satisfies: SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00156" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73565" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ " /v "PreXPSP2ShellProtocolBehavior" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: File Explorer shell protocol must run in protected mode." >> Win2016.txt
 	echo "Discussion: The shell protocol will limit the set of folders that applications can open when run in protected mode. Restricting files an application can open to a limited set of folders increases the security of Windows." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73563" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer\ " /v "NoHeapTerminationOnCorruption" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Turning off File Explorer heap termination on corruption must be disabled" >> Win2016.txt
 	echo "Discussion: Legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Disabling this feature will prevent thiS." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73561" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer\ " /v "NoDataExecutionPrevention" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Explorer Data Execution Prevention must be enabled." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73559" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\ " /v "EnableSmartScreen" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Windows Server 2016 Windows SmartScreen must be enabled." >> Win2016.txt
 	echo "Discussion: Windows SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling SmartScreen will warn users of potentially malicious programs." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73557"  >> Win2016.txt  
	reg query " HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\ " /v "MaxSize" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The System event log size must be configured to 32768 KB or greater." >> Win2016.txt
 	echo "Discussion: Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73555"  >> Win2016.txt  
	reg query " HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\ " /v "MaxSize" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Security event log size must be configured to 196608 KB or greater." >> Win2016.txt
 	echo "Discussion: Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73553" >> Win2016.txt   
	reg query " HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\ " /v "MaxSize" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Application event log size must be configured to 32768 KB or greater. " >> Win2016.txt
 	echo "Discussion: Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73551"  >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection\ " /v "AllowTelemetry" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Windows Telemetry must be configured to Security or Basic." >> Win2016.txt
 	echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The 'Security' option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender, and telemetry client settings. 'Basic' sends basic diagnostic and usage data and may be required to support some Microsoft services." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73549" >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\ " /v "NoDriveTypeAutoRun" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The 'Security' option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender, and telemetry client settings. 'Basic' sends basic diagnostic and usage data and may be required to support some Microsoft services." >> Win2016.txt
 	echo "Discussion: Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading from a drive as soon media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. By default, AutoPlay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives. Enabling this policy disables AutoPlay on all drives." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73547" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ " /v "NoAutorun" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The default AutoRun behavior must be configured to prevent AutoRun commands." >> Win2016.txt
 	echo "Discussion: Allowing AutoRun commands to execute may introduce malicious code to a system. Configuring this setting prevents AutoRun commands from executing." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73545" >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer\ " /v "NoAutoplayfornonVolume" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: AutoPlay must be turned off for non-volume devices." >> Win2016.txt
 	echo "Discussion: Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading from a drive as soon as media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. This setting will disable AutoPlay for non-volume devices, such as Media Transfer Protocol (MTP) devices." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73543" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat\ " /v "DisableInventory" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft." >> Win2016.txt
 	echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system.This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73541" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\ " /v "RestrictRemoteClients" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Unauthenticated Remote Procedure Call (RPC) clients must be restricted from connecting to the RPC server." >> Win2016.txt
 	echo "Discussion: Unauthenticated RPC clients may allow anonymous access to sensitive information. Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73539" >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\  " /v "ACSettingIndex" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Users must be prompted to authenticate when the system wakes from sleep (plugged in)." >> Win2016.txt
 	echo "Discussion: A system that does not require authentication when resuming from sleep may provide access to unauthorized users. Authentication must always be required when accessing a system. This setting ensures users are prompted for a password when the system wakes from sleep (plugged in)." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73537" >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ " /v "DCSettingIndex" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Users must be prompted to authenticate when the system wakes from sleep (on battery)." >> Win2016.txt
 	echo "Discussion: A system that does not require authentication when resuming from sleep may provide access to unauthorized users. Authentication must always be required when accessing a system. This setting ensures users are prompted for a password when the system wakes from sleep (on battery)." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73533" >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\ " /v "EnumerateLocalUsers" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Local users on domain-joined computers must not be enumerated." >> Win2016.txt
 	echo "Discussion: The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73531" >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\ " /v "DontDisplayNetworkSelectionUI" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The network selection user interface (UI) must not be displayed on the logon screen." >> Win2016.txt
 	echo "Discussion: Enabling interaction with the network selection UI allows users to change connections to available networks without signing in to Windows." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73529" >> Win2016.txt   
	reg query " HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\ " /v "DisableHTTPPrinting" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Printing over HTTP must be prevented." >> Win2016.txt
 	echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system. This setting prevents the client computer from printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73527" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\ " /v "DisableWebPnPDownload" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Downloading print driver packages over HTTP must be prevented." >> Win2016.txt
 	echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system. This setting prevents the computer from downloading print driver packages over HTTP." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73525" >> Win2016.txt
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\ " /v "" >> Win2016.txt   
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Group Policy objects must be reprocessed even if they have not changed." >> Win2016.txt
 	echo "Discussion: Registry entries for group policy settings can potentially be changed from the required configuration. This could occur as part of troubleshooting or by a malicious process on a compromised system. Enabling this setting and then selecting the 'Process even if the Group Policy objects have not changed' option ensures the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again." >> Win2016.txt	
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73521" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\ " /v "DriverLoadPolicy" >> Win2016.txt 
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad." >> Win2016.txt
 	echo "Discussion: Compromised boot drivers can introduce malware prior to protection mechanisms that load after initialization. The Early Launch Antimalware driver can limit allowed drivers based on classifications determined by the malware protection application. At a minimum, drivers determined to be bad must not be allowed." >> Win2016.txt 
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73515" >> Win2016.txt
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ " /v "LsaCfgFlags" >> Win2016.txt   
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Windows Server 2016 must be running Credential Guard on domain-joined member servers." >> Win2016.txt
 	echo "Discussion: Credential Guard uses virtualization-based security to protect data that could be used in credential theft attacks if compromised. This authentication information, which was stored in the Local Security Authority (LSA) in previous versions of Windows, is isolated from the rest of operating system and can only be accessed by privileged system software." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73513" >> Win2016.txt
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ " /v "EnableVirtualizationBasedSecurity" >> Win2016.txt 
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Windows Server 2016 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ " /v "RequirePlatformSecurityFeatures" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: " >> Win2016.txt
 	echo "Discussion: " >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73511" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ " /v "ProcessCreationIncludeCmdLine_Enabled" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: " >> Win2016.txt
 	echo "Discussion: " >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73509" >> Win2016.txt
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ " /v "\\*\NETLOGON" >> Win2016.txt  
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Command line data must be included in process creation events. " >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\ " /v "\\*\SYSVOL" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares." >> Win2016.txt
 	echo "Discussion: Additional security requirements are applied to Universal Naming Convention (UNC) paths specified in hardened UNC paths before allowing access to them. This aids in preventing tampering with or spoofing of connections to these paths." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73507" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\ " /v "AllowInsecureGuestAuth" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Insecure logons to an SMB server must be disabled." >> Win2016.txt
 	echo "Discussion: Insecure guest logons allow unauthenticated access to shared folders. Shared resources on a system must require authentication to establish proper access" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73505" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\ " /v "NoNameReleaseOnDemand" >> Win2016.txt 
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Windows Server 2016 must be configured to ignore NetBIOS name release requests except from WINS servers." >> Win2016.txt
 	echo "Discussion: Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service (DoS) attack. The DoS consists of sending a NetBIOS name release request to the server for each entry in the server's cache, causing a response delay in the normal operation of the server's WINS resolution capability." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73503" >> Win2016.txt   
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\ " /v "EnableICMPRedirect" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Windows Server 2016 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes." >> Win2016.txt
 	echo "Discussion: Allowing ICMP redirect of routes can lead to traffic not being routed properly. When disabled, this forces ICMP to be routed via the shortest path first." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt

	echo "V-73501" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\ " /v "DisableIPSourceRouting" >> Win2016.txt 
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing. " >> Win2016.txt
 	echo "Discussion: Configuring the system to disable IP source routing protects against spoofing. " >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73499" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ " /v "DisableIPSourceRouting" >> Win2016.txt 
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title:  Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing." >> Win2016.txt
 	echo "Discussion:  Configuring the system to disable IPv6 source routing protects against spoofing." >> Win2016.txt 
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73497" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\ " /v "UseLogonCredential" >> Win2016.txt 
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: WDigest Authentication must be disabled on Windows Server 2016." >> Win2016.txt
 	echo "Discussion: When the WDigest Authentication protocol is enabled, plain-text passwords are stored in the Local Security Authority Subsystem Service (LSASS), exposing them to theft. WDigest is disabled by default in Windows Server 2016. This setting ensures this is enforced." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73495" >> Win2016.txt  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "LocalAccountTokenFilterPolicy" >> Win2016.txt
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems." >> Win2016.txt
 	echo "Discussion: A compromised local administrator account can provide means for an attacker to move laterally between domain systems. With User Account Control enabled, filtering the privileged token for local administrator accounts will prevent the elevated privileges of these accounts from being used over the network" >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73493" >> Win2016.txt
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization\ " /v "NoLockScreenSlideshow" >> Win2016.txt 
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: The display of slide shows on the lock screen must be disabled." >> Win2016.txt
 	echo "Discussion: Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged-on user." >> Win2016.txt 
	echo "---------------------------------------------------------------------"  >> Win2016.txt
	
	echo "V-73487" >> Win2016.txt 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\ " /v "EnumerateAdministrators" >> Win2016.txt 
	IF %errorlevel% == 0 (echo "SUCCESS" >> Win2016.txt) else (echo "FAILURE" >> Win2016.txt)
	echo "Rule Title: Administrator accounts must not be enumerated during elevation." >> Win2016.txt
 	echo "Discussion: Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to type in a username and password to elevate a running application." >> Win2016.txt
	echo "---------------------------------------------------------------------"  >> Win2016.txt


gpresult /r > gpresult2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73311" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must have the number of allowed bad logon attempts configured to three or less." >> Win2016.txt
echo "Discussion:  The account lockout feature, when enabled, prevents brute-force password attacks on the system. The higher this value is, the less effective the account lockout feature will be in protecting the local system. The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack while allowing for honest errors made during normal user logon." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "Account Lockout Policy"
echo "FINDING: If 'LockoutBadCount' equals '0' or is greater than '3' in the file, this is a finding."  >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73313" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater." >> Win2016.txt
echo "Discussion:  The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to "0". The smaller this value is, the less effective the account lockout feature will be in protecting the local system.

Satisfies: SRG-OS-000021-GPOS-00005, SRG-OS-000329-GPOS-00128" >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "Account Lockout Policy"
echo "FINDING: If 'ResetLockoutCount' is less than '15' in the file, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73315" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 password history must be configured to 24 passwords remembered." >> Win2016.txt
echo "Discussion:  A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change to a unique password on a regularly scheduled basis. This enables users to effectively negate the purpose of mandating periodic password changes. The default value is "24" for Windows domain systems. DoD has decided this is the appropriate value for all Windows systems." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "Password Policy"
echo "FINDING: If 'PasswordHistorySize' is less than '24' in the file, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73317" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 maximum password age must be configured to 60 days or less." >> Win2016.txt
echo "Discussion:  The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords. Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "Password Policy"
echo "FINDING: If 'MaximumPasswordAge' is greater than '60' or equal to '0' in the file, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73319" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 minimum password age must be configured to at least one day." >> Win2016.txt
echo "Discussion:  Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database. This enables users to effectively negate the purpose of mandating periodic password changes." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "Password Policy"
echo "FINDING:If 'MinimumPasswordAge' equals '0' in the file, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt




echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73321" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 minimum password length must be configured to 14 characters." >> Win2016.txt
echo "Discussion:  Information systems not protected with strong password schemes (including passwords of minimum length) provide the opportunity for anyone to crack the password, thus gaining access to the system and compromising the device, information, or the local network." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "Password Policy"
echo "FINDING: If 'MinimumPasswordLength' is less than '14' in the file, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73323" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must have the built-in Windows password complexity policy enabled." >> Win2016.txt
echo "Discussion:  The use of complex passwords increases their strength against attack. The built-in Windows password complexity policy requires passwords to contain at least three of the four types of characters (numbers, upper- and lower-case letters, and special characters) and prevents the inclusion of user names or parts of user names.

Satisfies: SRG-OS-000069-GPOS-00037, SRG-OS-000070-GPOS-00038, SRG-OS-000071-GPOS-00039, SRG-OS-000266-GPOS-00101" >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "Password Policy"
echo "FINDING: If 'PasswordComplexity' equals '0' in the file, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73325" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: high" >> Win2016.txt
echo "Rule Title: Windows Server 2016 reversible password encryption must be disabled." >> Win2016.txt
echo "Discussion:  Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the passwords, which are easily compromised. For this reason, this policy must never be enabled." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "Password Policy"
echo "FINDING: If 'ClearTextPassword' equals '1' in the file, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73665" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: high" >> Win2016.txt
echo "Rule Title: Anonymous SID/Name translation must not be allowed." >> Win2016.txt
echo "Discussion:  Allowing anonymous SID/Name translation can provide sensitive information for accessing a system. Only authorized users must be able to perform such translations." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "Security Options"
echo "FINDING: If 'LSAAnonymousNameLookup' equals '1' in the file, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73729" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Access Credential Manager as a trusted caller' user right may be able to retrieve the credentials of other accounts from Credential Manager." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If 'LSAAnonymousNameLookup' equals '1' in the file, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73731" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and 
Enterprise Domain Controllers groups on domain controllers." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Access this computer from the network' right may access resources on the system, and this right must be limited to those requiring it." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups other than the following are granted the 'Access this computer from the network' right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73733" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on member servers." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Access this computer from the network' user right may access resources on the system, and this right must be limited to those requiring it." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups other than the following are granted the 'Access this computer from the network' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73735" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: high" >> Win2016.txt
echo "Rule Title: The Act as part of the operating system user right must not be assigned to any groups or accounts." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Act as part of the operating syste' user right can assume the identity of any user and gain access to resources that the user is authorized to access. Any accounts with this right can take complete control of a system." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73737" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Add workstations to domain user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Add workstations to domain' right may add computers to a domain. This could result in unapproved or incorrectly configured systems being added to a domain." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups (to include administrators), are granted the 'Act as part of the operating system' user right, this is a finding.
"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73739" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Allow log on locally user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the'Allow log on locally' user right can log on interactively to a system." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups other than the following are granted the 'Allow log on locally' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73741" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Allow log on through Remote Desktop Services' user right can access a system through Remote Desktop." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups other than the following are granted the 'Allow log on through Remote Desktop Services' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73743" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Back up files and directories user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Back up files and directories' user right can circumvent file and directory permissions and could allow access to sensitive data." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups other than the following are granted the 'Back up files and directories' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73745" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Create a pagefile user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Create a pagefile' user right can change the size of a pagefile, which could affect system performance." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups other than the following are granted the 'Create a pagefile' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73747" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: high" >> Win2016.txt
echo "Rule Title: The Create a token object user right must not be assigned to any groups or accounts." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Create a token object' user right allows a process to create an access token. This could be used to provide elevated rights and compromise a system." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups are granted the 'Create a token object' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73749" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Create global objects' user right can create objects that are available to all sessions, which could affect processes in other users sessions. " >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups other than the following are granted the 'Create global objects' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73751" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Create permanent shared objects user right must not be assigned to any groups or accounts." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the Create permanent shared objects user right could expose sensitive data by creating shared objects." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups are granted the 'Create permanent shared objects' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73753" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Create symbolic links user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Create symbolic links' user right can create pointers to other objects, which could expose the system to attack." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups other than the following are granted the 'Create symbolic links' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73755" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: high" >> Win2016.txt
echo "Rule Title: The Debug programs user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Debug programs' user right can attach a debugger to any process or to the kernel, providing complete access to sensitive and critical operating system components. This right is given to Administrators in the default configuration." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups other than the following are granted the 'Debug programs' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73757" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny access to this computer from the network' user right defines the accounts that are prevented from logging on from the network.

The Guests group must be assigned this right to prevent unauthenticated access." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If the following accounts or groups are not defined for the 'Deny access to this computer from the network' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73759" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny access to this computer from the network' user right defines the accounts that are prevented from logging on from the network.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.

Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If the following accounts or groups are not defined for the 'Deny access to this computer from the network' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73761" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The'Deny log on as a batch job' user right defines accounts that are prevented from logging on to the system as a batch job, such as Task Scheduler.

The Guests group must be assigned to prevent unauthenticated access." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If the following accounts or groups are not defined for the 'Deny log on as a batch job' user right, this is a finding.
- Guests Group "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt




echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73763" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny log on as a batch job' user right defines accounts that are prevented from logging on to the system as a batch job, such as Task Scheduler.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.

The Guests group must be assigned to prevent unauthenticated access." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If the following accounts or groups are not defined for the 'Deny log on as a batch job' user right, this is a finding.

Domain Systems Only:
- Enterprise Admins Group
- Domain Admins Group

All Systems:
- Guests Group"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73765" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny log on as a service' user right defines accounts that are denied logon as a service.

Incorrect configurations could prevent services from starting and result in a denial of service." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups are defined for the 'Deny log on as a service' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73767" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems. No other groups or accounts must be assigned this right." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny log on as a service' user right defines accounts that are denied logon as a service.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.

Incorrect configurations could prevent services from starting and result in a DoS." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If the following accounts or groups are not defined for the 'Deny log on as a service' user right on domain-joined systems, this is a finding. "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73769" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny log on locally' user right defines accounts that are prevented from logging on interactively.

The Guests group must be assigned this right to prevent unauthenticated access." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If the following accounts or groups are not defined for the 'Deny log on locally' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73771" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Deny log on locally user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny log on locally' user right defines accounts that are prevented from logging on interactively.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.

The Guests group must be assigned this right to prevent unauthenticated access." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If the following accounts or groups are not defined for the 'Deny log on locally' user right, this is a finding.

Domain Systems Only:
- Enterprise Admins Group
- Domain Admins Group

All Systems:
- Guests Group"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73773" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny log on through Remote Desktop Services' user right defines the accounts that are prevented from logging on using Remote Desktop Services.

The Guests group must be assigned this right to prevent unauthenticated access." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: 
If the following accounts or groups are not defined for the 'Deny log on through Remote Desktop Services' user right, this is a finding.
- Guests Group"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73775" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems and from unauthenticated access on all systems." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny log on through Remote Desktop Services' user right defines the accounts that are prevented from logging on using Remote Desktop Services.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.

Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If the following accounts or groups are not defined for the 'Deny log on through Remote Desktop Services' user right, this is a finding.

Domain Systems Only:
- Enterprise Admins group
- Domain Admins group
- Local account (see Note below)

All Systems:
- Guests group"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73277" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The roles and features required by the system must be documented." >> Win2016.txt
echo "Discussion:  Unnecessary roles and features increase the attack surface of a system. Limiting roles and features of a system to only those necessary reduces this potential. The standard installation option (previously called Server Core) further reduces this when selected at installation." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups other than the following are granted the 'Enable computer and user accounts to be trusted for delegation' user right, this is a finding.

- Administrators"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73779" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on member servers." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Enable computer and user accounts to be trusted for delegation' user right allows the 'Trusted for Delegation' setting to be changed. This could allow unauthorized users to impersonate other users." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any SIDs are granted the 'SeEnableDelegationPrivilege' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73781" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Force shutdown from a remote system user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Force shutdown from a remote system' user right can remotely shut down a system, which could result in a denial of service." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any SIDs other than the following are granted the 'SeRemoteShutdownPrivilege' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73783" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Generate security audits user right must only be assigned to Local Service and Network Service." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Generate security audits' user right specifies users and processes that can generate Security Log audit records, which must only be the system service accounts defined." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any SIDs other than the following are granted the 'SeAuditPrivilege' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73785" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Impersonate a client after authentication' user right allows a program to impersonate another user or account to run on their behalf. An attacker could use this to elevate privileges." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any SIDs other than the following are granted the 'SeImpersonatePrivilege' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73787" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Increase scheduling priority user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Increase scheduling priority' user right can change a scheduling priority, causing performance issues or a denial of service." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any SIDs other than the following are granted the 'SeIncreaseBasePriorityPrivilege' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73789" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Load and unload device drivers user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Load and unload device drivers' user right allows a user to load device drivers dynamically on a system. This could be used by an attacker to install malicious code." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any SIDs other than the following are granted the 'SeLoadDriverPrivilege' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73791" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Lock pages in memory user right must not be assigned to any groups or accounts." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Lock pages in memory' user right allows physical memory to be assigned to processes, which could cause performance issues or a denial of service." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any accounts or groups are granted the 'Lock pages in memory' user right, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73793" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Manage auditing and security log user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Manage auditing and security log' user right can manage the security log and change auditing configurations. This could be used to clear evidence of tampering.

Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029, SRG-OS-000063-GPOS-00032, SRG-OS-000337-GPOS-00129" >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any SIDs other than the following are granted the 'SeSecurityPrivilege' user right, this is a finding.

S-1-5-32-544 (Administrators) "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73795" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Modify firmware environment values user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Modify firmware environment values' user right can change hardware configuration environment variables. This could result in hardware failures or a denial of service." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any SIDs other than the following are granted the 'SeSystemEnvironmentPrivilege' user right, this is a finding.

S-1-5-32-544 (Administrators)"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73797" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Perform volume maintenance tasks user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Perform volume maintenance tasks' user right can manage volume and disk configurations. This could be used to delete volumes, resulting in data loss or a denial of service." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any SIDs other than the following are granted the 'SeManageVolumePrivilege' user right, this is a finding.

S-1-5-32-544 (Administrators)"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73799" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Profile single process user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Profile single process' user right can monitor non-system processes performance. An attacker could use this to identify processes to attack." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any SIDs other than the following are granted the 'SeProfileSingleProcessPrivilege' user right, this is a finding.

S-1-5-32-544 (Administrators)"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73801" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Restore files and directories user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Restore files and directories' user right can circumvent file and directory permissions and could allow access to sensitive data. It could also be used to overwrite more current data." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: 
If any SIDs other than the following are granted the 'SeRestorePrivilege' user right, this is a finding.

S-1-5-32-544 (Administrators)"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73803" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: The Take ownership of files or other objects user right must only be assigned to the Administrators group." >> Win2016.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Take ownership of files or other objects' user right can take ownership of objects and make changes." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any SIDs other than the following are granted the 'SeTakeOwnershipPrivilege' user right, this is a finding.

S-1-5-32-544 (Administrators)"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73809" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 built-in guest account must be disabled." >> Win2016.txt
echo "Discussion:  A system faces an increased vulnerability threat if the built-in guest account is not disabled. This is a known account that exists on all Windows systems and cannot be deleted. This account is initialized during the installation of the operating system with no password assigned." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If 'EnableGuestAccount' equals '1' in the file, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-78127" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Orphaned security identifiers (SIDs) must be removed from user rights on Windows 2016." >> Win2016.txt
echo "Discussion:  Accounts or groups given rights on a system may show up as unresolved SIDs for various reasons including deletion of the accounts or groups.  If the account or group objects are reanimated, there is a potential they may still have rights no longer intended.  Valid domain accounts or groups may also show up as unresolved SIDs if a connection to the domain cannot be established for some reason." >> Win2016.txt
TYPE gpresult2016.txt | findstr /i "User Rights Assignment"
echo "FINDING: If any unresolved SIDs exist and are not for currently valid accounts or groups, this is a finding."  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



AuditPol /get /category:* > AUDITPOL2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73413" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Account Logon - Credential Validation successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Credential Validation records events related to validation tests on credentials for a user account logon." >> Win2016.txt

TYPE AUDITPOL2016.txt | findstr /i "Credential Validation" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.

Account Logon >> Credential Validation - Success"  >> Win2016.txt 

echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73415" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Account Logon - Credential Validation failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Credential Validation records events related to validation tests on credentials for a user account logon." >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Credential Validation" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.

Account Logon >> Credential Validation - Failure"  >> Win2016.txt 
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73417" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Account Management - Computer Account Management successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Computer Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling computer accounts.

Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000476-GPOS-00221" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Computer Account Management" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.   Account Management >> Computer Account Management - Success  "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73419" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Account Management - Other Account Management Events successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Other Account Management Events records events such as the access of a password hash or the Password Policy Checking API being called.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466-GPOS-00210" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Other Account Management Events" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Account Management >> Other Account Management Events - Success    "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73423" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Account Management - Security Group Management successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Security Group Management records events such as creating, deleting, or changing security groups, including changes in group members.

Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000476-GPOS-00221" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Security Group Management" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Account Management >> Security Group Management - Success    "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73427" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Account Management - User Account Management successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

User Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling user accounts.

Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000476-GPOS-00221" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "User Account Management " >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Account Management >> User Account Management - Success    "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73429" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Account Management - User Account Management failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

User Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling user accounts.

Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000476-GPOS-00221" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "User Account Management " >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Account Management >> User Account Management - Failure    "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73431" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Detailed Tracking - Plug and Play Events successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Plug and Play activity records events related to the successful connection of external devices." >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Plug and Play Events" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.  Detailed Tracking >> Plug and Play Events - Success  "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73433" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Detailed Tracking - Process Creation successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Process Creation records events related to the creation of a process and the source.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000471-GPOS-00215" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Process Creation" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Detailed Tracking >> Process Creation - Success    "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73435" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit DS Access - Directory Service Access successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Directory Service Access records events related to users accessing an Active Directory object.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Directory Service Access " >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. DS Access >> Directory Service Access - Success      "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73437" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit DS Access - Directory Service Access failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Directory Service Access records events related to users accessing an Active Directory object.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Directory Service Access " >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.  DS Access >> Directory Service Access - Failure   "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73439" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit DS Access - Directory Service Changes successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Directory Service Changes records events related to changes made to objects in Active Directory Domain Services.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Directory Service Changes" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.  DS Access >> Directory Service Changes - Success   "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73441" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit DS Access - Directory Service Changes failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Directory Service Changes records events related to changes made to objects in Active Directory Domain Services.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Directory Service Changes" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. DS Access >> Directory Service Changes - Failure "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73443" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Logon/Logoff - Account Lockout successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Account Lockout events can be used to identify potentially malicious logon attempts.

Satisfies: SRG-OS-000240-GPOS-00090, SRG-OS-000470-GPOS-00214" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Account Lockout" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.  Logon/Logoff >> Account Lockout - Success   "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73445" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Logon/Logoff - Account Lockout failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Account Lockout events can be used to identify potentially malicious logon attempts.

Satisfies: SRG-OS-000240-GPOS-00090, SRG-OS-000470-GPOS-00214" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Account Lockout" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.   Logon/Logoff >> Account Lockout - Failure "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73447" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Logon/Logoff - Group Membership successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Group Membership records information related to the group membership of a user's logon token." >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Group Membership" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.  Logon/Logoff >> Group Membership - Success   "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73449" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Logon/Logoff - Logoff successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Logoff records user logoffs. If this is an interactive logoff, it is recorded on the local system. If it is to a network share, it is recorded on the system accessed.

Satisfies: SRG-OS-000032-GPOS-00013, SRG-OS-000470-GPOS-00214, SRG-OS-000472-GPOS-00217, SRG-OS-000473-GPOS-00218, SRG-OS-000475-GPOS-00220" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Logoff" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.  Logon/Logoff >> Logoff - Success   "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73451" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Logon/Logoff - Logon successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Logon records user logons. If this is an interactive logon, it is recorded on the local system. If it is to a network share, it is recorded on the system accessed.

Satisfies: SRG-OS-000032-GPOS-00013, SRG-OS-000470-GPOS-00214, SRG-OS-000472-GPOS-00217, SRG-OS-000473-GPOS-00218, SRG-OS-000475-GPOS-00220" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Logon" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.   Logon/Logoff >> Logon - Success  "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73453" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Logon/Logoff - Logon failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Logon records user logons. If this is an interactive logon, it is recorded on the local system. If it is to a network share, it is recorded on the system accessed.

Satisfies: SRG-OS-000032-GPOS-00013, SRG-OS-000470-GPOS-00214, SRG-OS-000472-GPOS-00217, SRG-OS-000473-GPOS-00218, SRG-OS-000475-GPOS-00220" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Logon" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.  Logon/Logoff >> Logon - Failure   "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73455" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Logon/Logoff - Special Logon successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Special Logon records special logons that have administrative privileges and can be used to elevate processes.

Satisfies: SRG-OS-000470-GPOS-00214, SRG-OS-000472-GPOS-00217, SRG-OS-000473-GPOS-00218, SRG-OS-000475-GPOS-00220" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Special Logon" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Logon/Logoff >> Special Logon - Success   "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73457" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Object Access - Removable Storage successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Removable Storage auditing under Object Access records events related to access attempts on file system objects on removable storage devices." >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Removable Storage" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Object Access >> Removable Storage - Success    "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73459" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Object Access - Removable Storage failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Removable Storage auditing under Object Access records events related to access attempts on file system objects on removable storage devices." >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Removable Storage" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.    Object Access >> Removable Storage - Failure "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73461" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Policy Change - Audit Policy Change successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Policy Change records events related to changes in audit policy.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Audit Policy Change" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Policy Change >> Audit Policy Change - Success"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73463" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Policy Change - Audit Policy Change failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Policy Change records events related to changes in audit policy.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Audit Policy Change" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.   Policy Change >> Audit Policy Change - Failure  "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73465" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Policy Change - Authentication Policy Change successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Authentication Policy Change records events related to changes in authentication policy, including Kerberos policy and Trust changes.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466-GPOS-00210" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Authentication Policy Change" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding.  Policy Change >> Authentication Policy Change - Success   "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73467" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Policy Change - Authorization Policy Change successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Authorization Policy Change records events related to changes in user rights, such as "Create a token object".

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466-GPOS-00210" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Authentication Policy Change" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Policy Change >> Authorization Policy Change - Success"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt




echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73469" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Privilege Use - Sensitive Privilege Use successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Sensitive Privilege Use records events related to use of sensitive privileges, such as "Act as part of the operating system" or "Debug programs".

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466-GPOS-00210" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Sensitive Privilege Use" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Privilege Use >> Sensitive Privilege Use - Success"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73471" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit Privilege Use - Sensitive Privilege Use failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Sensitive Privilege Use records events related to use of sensitive privileges, such as "Act as part of the operating system" or "Debug programs".

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466-GPOS-00210" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Sensitive Privilege Use" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Privilege Use >> Sensitive Privilege Use - Failure "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt





echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73473" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit System - IPsec Driver successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

IPsec Driver records events related to the IPsec Driver, such as dropped packets.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "IPsec Driver" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. System >> IPsec Driver - Success "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73475" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit System - IPsec Driver failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

IPsec Driver records events related to the IPsec Driver, such as dropped packets.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "IPsec Driver" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. System >> IPsec Driver - Failure"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73477" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit System - Other System Events successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Other System Events records information related to cryptographic key operations and the Windows Firewall service.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Other System Events" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. System >> Other System Events - Success"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73479" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit System - Other System Events failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Other System Events records information related to cryptographic key operations and the Windows Firewall service.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Other System Events" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. System >> Other System Events - Failure"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73481" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit System - Security State Change successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Security State Change records events related to changes in the security state, such as startup and shutdown of the system.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Security State Change" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. System >> Security State Change - Success"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73483" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit System - Security System Extension successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Security System Extension records events related to extension code being loaded by the security subsystem.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000458-GPOS-00203, SRG-OS-000463-GPOS-00207, SRG-OS-000468-GPOS-00212" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Security System Extension" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. System >> Security System Extension - Success"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt

echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73489" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit System - System Integrity successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

System Integrity records events related to violations of integrity to the security subsystem.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000471-GPOS-00215, SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "System Integrity" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. System >> System Integrity - Success"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt


echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-73491" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows Server 2016 must be configured to audit System - System Integrity failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

System Integrity records events related to violations of integrity to the security subsystem.

Satisfies: SRG-OS-000327-GPOS-00127, SRG-OS-000471-GPOS-00215, SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222" >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "System Integrity" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. System >> System Integrity - Failure"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt





echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-90359" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows 2016 must be configured to audit Object Access - Other Object Access Events successes." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Auditing for other object access records events related to the management of task scheduler jobs and COM+ objects." >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Other Object Access Events" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Object Access >> Other Object Access Events - Success"  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt



echo "|---------------------------------------------------------------------|" >> Win2016.txt
echo "V-90361" >> Win2016.txt
echo "Group Title:  " >> Win2016.txt
echo "Severity: medium" >> Win2016.txt
echo "Rule Title: Windows 2016 must be configured to audit Object Access - Other Object Access Events failures." >> Win2016.txt
echo "Discussion:  Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Auditing for other object access records events related to the management of task scheduler jobs and COM+ objects." >> Win2016.txt
TYPE AUDITPOL2016.txt | findstr /i "Other Object Access Events" >> Win2016.txt
echo "FINDING: If the system does not audit the following, this is a finding. Object Access >> Other Object Access Events - Failure "  >> Win2016.txt
echo "|---------------------------------------------------------------------|" >> Win2016.txt




@echo on