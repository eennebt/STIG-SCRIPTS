@echo off

echo "V-72753" > Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\ " /v "UseLogonCredential" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: WDigest Authentication must be disabled." >> Win2012.txt
echo "Discussion: When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security Authority Subsystem Service (LSASS) exposing them to theft. This setting will prevent WDigest from storing credentials in memory."  >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-57639" >> Win2012.txt 
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\ " /v "ForceKeyProtection" >> Win2012.txt 
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must be required to enter a password to access private keys stored on the computer." >> Win2012.txt
echo "Discussion: If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.The cornerstone of the PKI is the private key used to encrypt or digitally sign information.If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-43245" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "DisableAutomaticRestartSignOn" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Automatically signing in the last interactive user after a system-initiated restart must be disabled (Windows 2012 R2)." >> Win2012.txt
echo "Discussion: Windows 2012 R2 can be configured to automatically sign the user back in after a Windows Update restart. Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-43241" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "MSAOptional" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The setting to allow Microsoft accounts to be optional for modern style apps must be enabled (Windows 2012 R2). " >> Win2012.txt
echo "Discussion: Control of credentials and the system must be maintained within the enterprise. Enabling this setting allows enterprise credentials to be used with modern style apps that support this, instead of Microsoft accounts." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-43240" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\ " /v "DontDisplayNetworkSelectionUI" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The network selection user interface (UI) must not be displayed on the logon screen (Windows 2012 R2)." >> Win2012.txt
echo "Discussion:  Enabling interaction with the network selection UI allows users to change connections to available networks without signing into Windows." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-43239" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ " /v "ProcessCreationIncludeCmdLine_Enabled" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Command line data must be prevented from inclusion in process creation events (Windows 2012 R2)." >> Win2012.txt
echo "Discussion: When enabled, the Windows policy setting, 'Include command line in process creation events', will save all command line entries details to the event log. This could potentially include passwords saved in clear text, which must be prevented." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-43238" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization\ " /v "NoLockScreenSlideshow" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The display of slide shows on the lock screen must be disabled (Windows 2012 R2)." >> Win2012.txt
echo "Discussion: Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged on user." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-40204" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "RedirectOnlyDefaultClientPrinter" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Only the default client printer must be redirected to the Remote Desktop Session Host. (Remote Desktop Services Role)." >> Win2012.txt
echo "Discussion: Allowing the redirection of only the default client printer to a Remote Desktop session helps reduce possible exposure of sensitive data." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-36773" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "InactivityTimeoutSecs" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver." >> Win2012.txt
echo "Discussion: Unattended systems are susceptible to unauthorized use and should be locked when unattended. The screen saver should be set at a maximum of 15 minutes and be password protected. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

timeout /t 5

echo "V-36720" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\ " /v "DisableRunAs" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows Remote Management (WinRM) service must not store RunAs credentials." >> Win2012.txt
echo "Discussion: Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-36719" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\ " /v "AllowUnencryptedTraffic" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows Remote Management (WinRM) service must not allow unencrypted traffic." >> Win2012.txt
echo "Discussion: Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-36718" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\ " /v "AllowBasic" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows Remote Management (WinRM) service must not use Basic authentication." >> Win2012.txt
echo "Discussion: Basic authentication uses plain text passwords that could be used to compromise a system." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-36714" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\ " /v "AllowDigest" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows Remote Management (WinRM) client must not use Digest authentication." >> Win2012.txt
echo "Discussion: Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-36713" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\ " /v "AllowUnencryptedTraffic" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows Remote Management (WinRM) client must not allow unencrypted traffic." >> Win2012.txt
echo "Discussion: Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-36712" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\ " /v "AllowBasic" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title:  The Windows Remote Management (WinRM) client must not use Basic authentication." >> Win2012.txt
echo "Discussion: Basic authentication uses plain text passwords that could be used to compromise a system." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36711" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore\ " /v "RemoveWindowsStore" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows Store application must be turned off." >> Win2012.txt
echo "Discussion: Uncontrolled installation of applications can introduce various issues, including system instability, and provide access to sensitive information. Installation of applications must be controlled by the enterprise. Turning off access to the Windows Store will limit access to publicly available applications." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-36710" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore\ " /v "AutoDownload" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Automatic download of updates from the Windows Store must be turned off." >> Win2012.txt
echo "Discussion: Uncontrolled system updates can introduce issues to a system. Obtaining update components from an outside source may also potentially allow sensitive information outside of the enterprise. Application updates must be obtained from an internal source. " >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore\WindowsUpdate\ " /v "AutoDownload" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title:" >> Win2012.txt
echo "Discussion:" >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36709" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Feeds\ " /v "AllowBasicAuthInClear" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Basic authentication for RSS feeds over HTTP must be turned off." >> Win2012.txt
echo "Discussion: Basic authentication uses plain text passwords that could be used to compromise a system." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36708" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors\ " /v "DisableLocation" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The location feature must be turned off." >> Win2012.txt
echo "Discussion: The location service on systems may allow sensitive data to be used by applications on the system. This should be turned off unless explicitly allowed for approved systems/applications." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

timeout /t 5

echo "V-36707" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\ " /v "EnableSmartScreen" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows SmartScreen must be turned off." >> Win2012.txt
echo "Discussion: Some features may send system information to the vendor. Turning off this feature will prevent potentially sensitive information from being sent outside the enterprise." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36700" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI\ " /v "DisablePasswordReveal" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The password reveal button must not be displayed." >> Win2012.txt
echo "Discussion: Visible passwords may be seen by nearby persons, compromising them. The password reveal button can be used to display an entered password and must not be allowed." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36698" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\ " /v "Enabled" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The use of biometrics must be disabled." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-36697" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Appx\ " /v "AllowAllTrustedApps" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Trusted app installation must be enabled to allow for signed enterprise line of business apps." >> Win2012.txt
echo "Discussion: Enabling trusted app installation allows for enterprise line of business Windows 8 type apps. A trusted app package is one that is signed with a certificate chain that can be successfully validated in the enterprise. Configuring this ensures enterprise line of business apps are accessible." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36696" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat\ " /v "DisablePcaUI" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The detection of compatibility issues for applications and drivers must be turned off." >> Win2012.txt
echo "Discussion:  Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this feature will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36687" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\ " /v "DisableLockScreenAppNotifications" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: App notifications on the lock screen must be turned off." >> Win2012.txt
echo "Discussion:  App notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged on user." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36684" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\ " /v "EnumerateLocalUsers" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title:  App notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged on user." >> Win2012.txt
echo "Discussion: The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36681" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Control Panel\International\ " /v "BlockUserInputMethodsForSignIn" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Copying of user input methods to the system account for sign-in must be prevented" >> Win2012.txt
echo "Discussion: Allowing different input methods for sign-in could open different avenues of attack. User input methods must be restricted to those enabled for the system account at sign-in." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36680" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer\ " /v "NoUseStoreOpenWith" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Access to the Windows Store must be turned off." >> Win2012.txt
echo "Discussion: Uncontrolled installation of applications can introduce various issues, including system instability, and allow access to sensitive information. Installation of applications must be controlled by the enterprise. Turning off access to the Windows Store will limit access to publicly available applications." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36679" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\EarlyLaunch\ " /v "DriverLoadPolicy" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Early Launch Antimalware, Boot-Start Driver Initialization Policy must be enabled and configured to only Good and Unknown." >> Win2012.txt
echo "Discussion: Compromised boot drivers can introduce malware prior to some protection mechanisms that load after initialization. The Early Launch Antimalware driver can limit allowed drivers based on classifications determined by the malware protection application. At a minimum, drivers determined to be bad must not be allowed." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-36678" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching\ " /v "DriverServerSelection" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Device driver updates must only search managed servers, not Windows Update." >> Win2012.txt
echo "Discussion: Uncontrolled system updates can introduce issues to a system. Obtaining update components from an outside source may also potentially provide sensitive information outside of the enterprise. Device driver updates must be obtained from an internal source." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36677" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\ " /v "UseWindowsUpdate" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Optional component installation and component repair must be prevented from using Windows Update." >> Win2012.txt
echo "Discussion: Uncontrolled system updates can introduce issues to a system. Obtaining update components from an outside source may also potentially provide sensitive information outside of the enterprise. Optional component installation or repair must be obtained from an internal source." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36673" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\ " /v "EnableIPAutoConfigurationLimits" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title:  IP stateless autoconfiguration limits state must be enabled." >> Win2012.txt
echo "Discussion: IP stateless autoconfiguration could configure routes that circumvent preferred routes if not limited." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt



echo "V-36439" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "LocalAccountTokenFilterPolicy" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems." >> Win2012.txt
echo "Discussion: A compromised local administrator account can provide means for an attacker to move laterally between domain systems. With User Account Control enabled, filtering the privileged token for local administrator accounts will prevent the elevated privileges of these accounts from being used over the network." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "LocalAccountTokenFilterPolicy" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "---------------------------------------------------------------------"  >> Win2012.txt



echo "V-34974" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\ " /v "AlwaysInstallElevated" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows Installer Always install with elevated privileges option must be disabled." >> Win2012.txt
echo "Discussion:  Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-28504" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\ " /v "DisableSendRequestAdditionalSoftwareToWER" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Windows must be prevented from sending an error report when a device driver requests additional software during installation. " >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting will prevent Windows from sending an error report to Microsoft when a device driver requests additional software during installation." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26582" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\ " /v "MaxSize" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The System event log size must be configured to 32768 KB or greater." >> Win2012.txt
echo "Discussion: Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26581" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\ " /v "MaxSize" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Setup event log size must be configured to 32768 KB or greater." >> Win2012.txt
echo "Discussion: Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26580" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\ " /v "MaxSize" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Security event log size must be configured to 196608 KB or greater." >> Win2012.txt
echo "Discussion: Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-26579" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\ " /v "MaxSize" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Application event log size must be configured to 32768 KB or greater." >> Win2012.txt
echo "Discussion: Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26578" >> Win2012.txt
reg query "Software\Policies\Microsoft\Windows\TCPIP\v6Transition\ " /v "Teredo_State" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Teredo IPv6 transition technology must be disabled." >> Win2012.txt
echo "Discussion: IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26577" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\ " /v "ISATAP_State" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The ISATAP IPv6 transition technology must be disabled." >> Win2012.txt
echo "Discussion: IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26576" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface\ " /v "IPHTTPS_ClientState" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The IP-HTTPS IPv6 transition technology must be disabled." >> Win2012.txt
echo "Discussion: IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-26575" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\ " /v "6to4_State" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The 6to4 IPv6 transition technology must be disabled. " >> Win2012.txt
echo "Discussion: IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26359" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "LegalNoticeCaption" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows dialog box title for the legal banner must be configured." >> Win2012.txt
echo "Discussion: Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26283" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ " /v "RestrictAnonymousSAM" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Anonymous enumeration of SAM accounts must not be allowed." >> Win2012.txt
echo "Discussion: Anonymous enumeration of SAM accounts allows anonymous log on users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-22692" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ " /v "NoAutorun" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The default Autorun behavior must be configured to prevent Autorun commands. " >> Win2012.txt
echo "Discussion: Allowing Autorun commands to execute may introduce malicious code to a system. Configuring this setting prevents Autorun commands from executing." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21980" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\ " /v "NoDataExecutionPrevention" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Explorer Data Execution Prevention must be enabled." >> Win2012.txt
echo "Discussion: Data Execution Prevention (DEP) provides additional protection by performing checks on memory to help prevent malicious code from running. This setting will prevent Data Execution Prevention from being turned off for File Explorer." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21973" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\ " /v "NoAutoplayfornonVolume" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Autoplay must be turned off for non-volume devices." >> Win2012.txt
echo "Discussion: Allowing Autoplay to execute may introduce malicious code to a system. Autoplay begins reading from a drive as soon as media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. This setting will disable Autoplay for non-volume devices (such as Media Transfer Protocol (MTP) devices)." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-21971" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat\ " /v "DisableInventory" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21970" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ " /v "ScenarioExecutionEnabled" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Responsiveness events must be prevented from being aggregated and sent to Microsoft." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting prevents responsiveness events from being aggregated and sent to Microsoft." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21969" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\ " /v "EnableQueryRemoteServer" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Access to Windows Online Troubleshooting Service (WOTS) must be prevented." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting prevents users from searching troubleshooting content on Microsoft servers. Only local content will be available." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21967" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\ " /v "DisableQueryRemoteServer" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Microsoft Support Diagnostic Tool (MSDT) interactive communication with Microsoft must be prevented." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting prevents the MSDT from communicating with and sending collected data to Microsoft, the default support provider." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt



echo "V-21965" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching\ " /v "SearchOrderConfig" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Device driver searches using Windows Update must be prevented." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting will prevent the system from searching Windows Update for device drivers." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21964" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata\ " /v "PreventDeviceMetadataFromNetwork" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Device metadata retrieval from the Internet must be prevented." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting will prevent Windows from retrieving device metadata from the Internet." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21963" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\ " /v "DoNotInstallCompatibleDriverFromWindowsUpdate" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Windows Update must be prevented from searching for point and print drivers." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting will prevent Windows from searching Windows Update for point and print drivers. Only the local driver store and server driver cache will be searched." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21961" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\ " /v "Force_Tunneling" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: All Direct Access traffic must be routed through the internal network." >> Win2012.txt
echo "Discussion: Routing all Direct Access traffic through the internal network allows monitoring and prevents split tunneling." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21960" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections\ " /v "NC_StdDomainUserSetLocation" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Domain users must be required to elevate when setting a networks location." >> Win2012.txt
echo "Discussion:Selecting an incorrect network location may allow greater exposure of a system. Elevation is required by default on nondomain systems to change network location. This setting configures elevation to also be required on domain-joined systems." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21956" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ " /v "TcpMaxDataRetransmissions" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: IPv6 TCP data retransmissions must be configured to prevent resources from becoming exhausted." >> Win2012.txt
echo "Discussion: Configuring Windows to limit the number of times that IPv6 TCP retransmits unacknowledged data segments before aborting the attempt helps prevent resources from becoming exhausted." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-21955" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ " /v "DisableIPSourceRouting" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: IPv6 source routing must be configured to the highest protection level." >> Win2012.txt
echo "Discussion: Configuring the system to disable IPv6 source routing protects against spoofing." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21954" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\ " /v "SupportedEncryptionTypes" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The use of DES encryption suites must not be allowed for Kerberos encryption." >> Win2012.txt
echo "Discussion: Certain encryption types are no longer considered secure. By default, Windows 2012/R2 does not use the DES encryption suites. If the configuration of allowed Kerberos encryption suites is needed, the DES encryption suites must not be included." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21953" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA\pku2u\ " /v "AllowOnlineID" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: PKU2U authentication using online identities must be prevented." >> Win2012.txt
echo "Discussion: PKU2U is a peer-to-peer authentication protocol. This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21952" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA\MSV1_0\ " /v "allownullsessionfallback" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: NTLM must be prevented from falling back to a Null session. " >> Win2012.txt
echo "Discussion: NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-21951" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA\ " /v "UseMachineId" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously." >> Win2012.txt
echo "Discussion: Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously vs. using the computer identity." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-21950" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\ " /v "SmbServerNameHardeningLevel" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The service principal name (SPN) target name validation level must be turned off." >> Win2012.txt
echo "Discussion: If a service principle name (SPN) is provided by the client, it is validated against the server's list of SPNs. Implementation may disrupt file and print sharing capabilities." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-16020" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SQMClient\Windows\ " /v "CEIPEnable" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows Customer Experience Improvement Program must be disabled." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting ensures the Windows Customer Experience Improvement Program is disabled so information is not passed to the vendor." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-16008" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "ValidateAdminCodeSignatures" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Windows must elevate all applications in User Account Control, not just signed ones." >> Win2012.txt
echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures whether Windows elevates all applications, or only signed ones." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-16000" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "fEnableSmartCard" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to ensure smart card devices can be redirected to the Remote Desktop session. (Remote Desktop Services Role)." >> Win2012.txt
echo "Discussion: Enabling the redirection of smart card devices allows their use within Remote Desktop sessions." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15999" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "fDisablePNPRedir" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must be prevented from redirecting Plug and Play devices to the Remote Desktop Session Host. (Remote Desktop Services Role)." >> Win2012.txt
echo "Discussion: Preventing the redirection of Plug and Play devices in Remote Desktop sessions helps reduce possible exposure of sensitive data." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15998" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "fDisableLPT" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must be prevented from mapping local LPT ports and redirecting data from the Remote Desktop Session Host to local LPT ports. (Remote Desktop Services Role)." >> Win2012.txt
echo "Discussion: Preventing the redirection of Remote Desktop session data to a client computer's LPT ports helps reduce possible exposure of sensitive data." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-15997" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "fDisableCcm" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must be prevented from mapping local COM ports and redirecting data from the Remote Desktop Session Host to local COM ports. (Remote Desktop Services Role)." >> Win2012.txt
echo "Discussion: Preventing the redirection of Remote Desktop session data to a client computer's COM ports helps reduce possible exposure of sensitive data." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15991" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "EnableUIADesktopToggle" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: UIAccess applications must not be allowed to prompt for elevation without using the secure desktop." >> Win2012.txt
echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting prevents User Interface Accessibility programs from disabling the secure desktop for elevation prompts." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15722" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WMDRM\ " /v "DisableOnline" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Windows Media Digital Rights Management (DRM) must be prevented from accessing the Internet." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This check verifies that Windows Media DRM will be prevented from accessing the Internet." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-15718" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\ " /v "NoHeapTerminationOnCorruption" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Turning off File Explorer heap termination on corruption must be disabled." >> Win2012.txt
echo "Discussion: Legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Disabling this feature will prevent this" >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-15713" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet\ " /v "SpyNetReporting" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Microsoft Active Protection Service membership must be disabled." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this feature will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. This setting disables Microsoft Active Protection Service membership and reporting." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15707" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "LoggingEnabled" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Remote Assistance log files must be generated." >> Win2012.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. This setting will turn on session logging for Remote Assistance connections." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15706" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ " /v "ACSettingIndex" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The user must be prompted to authenticate on resume from sleep (plugged in)." >> Win2012.txt
echo "Discussion: Authentication must always be required when accessing a system. This setting ensures the user is prompted for a password on resume from sleep (plugged in)." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15705" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ " /v "DCSettingIndex" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must be prompted to authenticate on resume from sleep (on battery)." >> Win2012.txt
echo "Discussion: Authentication must always be required when accessing a system. This setting ensures the user is prompted for a password on resume from sleep (on battery)." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15704" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HandwritingErrorReports\ " /v "PreventHandwritingErrorReports" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Errors in handwriting recognition on tablet PCs must not be reported to Microsoft." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting prevents errors in handwriting recognition on tablet PCs from being reported to Microsoft." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15703" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching\ " /v "DontPromptForWindowsUpdate" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must not be prompted to search Windows Update for device drivers." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting prevents users from being prompted to search Windows Update for device drivers." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-15702" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\ " /v "DisableSendGenericDriverNotFoundToWER" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: An Error Report must not be sent when a generic device driver is installed." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting prevents an error report from being sent when a generic device driver is installed." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15701" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\ " /v "DisableSystemRestore" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: A system restore point must be created when a new device driver is installed." >> Win2012.txt
echo "Discussion: A system restore point allows a rollback if an issue is encountered when a new device driver is installed." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15700" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\ " /v "AllowRemoteRPC" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Remote access to the Plug and Play interface must be disabled for device installation." >> Win2012.txt
echo "Discussion: Remote access to the Plug and Play interface could potentially allow connections by unauthorized devices. This setting configures remote access to the Plug and Play interface and must be disabled." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15699" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\UI\ " /v "DisableWcnUi" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows Connect Now wizards must be disabled." >> Win2012.txt
echo "Discussion: Windows Connect Now provides wizards for tasks such as 'Set up a wireless router or access point' and must not be available to users. Functions such as these may allow unauthorized connections to a system and the potential for sensitive information to be compromised." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-15698" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrars\ " /v "DisableFlashConfigRegistrar" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrars\ " /v "DisableInBand802DOT11Registrar" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrars\ " /v "DisableUPnPRegistrar" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrars\ " /v "DisableWPDRegistrar" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrars\ " /v "EnableRegistrars" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The configuration of wireless devices using Windows Connect Now must be disabled." >> Win2012.txt
echo "Discussion: Windows Connect Now allows the discovery and configuration of devices over wireless. Wireless devices must be managed. If a rogue device is connected to a system, there is potential for sensitive information to be compromised." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15697" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD\ " /v "AllowRspndrOndomain" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD\ " /v "AllowRspndrOnPublicNet" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD\ " /v "EnableRspndr" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD\ " /v "ProhibitRspndrOnPrivateNet" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Responder network protocol driver must be disabled." >> Win2012.txt
echo "Discussion: The Responder network protocol driver allows a computer to be discovered and located on a network. Disabling this helps protect the system from potentially being discovered and connected to by unauthorized devices." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

 
echo "V-15696" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD\ " /v "AllowLLTDIOOndomain" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD\ " /v "AllowLLTDIOOnPublicNet" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD\ " /v "EnableLLTDIO" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD\ " /v "ProhibitLLTDIOOnPrivateNet" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Mapper I/O network protocol (LLTDIO) driver must be disabled." >> Win2012.txt
echo "Discussion:  The Mapper I/O network protocol (LLTDIO) driver allows the discovery of the connected network and allows various options to be enabled. Disabling this helps protect the system from potentially discovering and connecting to unauthorized devices. " >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15687" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer\ " /v "GroupPrivacyAcceptance" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must not be presented with Privacy and Installation options on first use of Windows Media Player." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting prevents users from being presented with Privacy and Installation options on first use of Windows Media Player, which could enable some communication with the vendor." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15686" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\ " /v "DisableLUAPatching" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Nonadministrators must be prevented from applying vendor-signed updates." >> Win2012.txt
echo "Discussion: Uncontrolled system updates can introduce issues to a system. This setting will prevent users from applying vendor-signed updates (though they may be from a trusted source)." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15685" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\ " /v "EnableUserControl" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must be prevented from changing installation options" >> Win2012.txt
echo "Discussion: Installation options for applications are typically controlled by administrators. This setting prevents users from changing installation options that may bypass security features." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-15684" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\ " /v "SafeForScripting" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must be notified if a web-based program attempts to install software." >> Win2012.txt
echo "Discussion: Users must be aware of attempted program installations. This setting ensures users are notified if a web-based program attempts to install software." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15683" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ " /v "PreXPSP2ShellProtocolBehavior" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: File Explorer shell protocol must run in protected mode." >> Win2012.txt
echo "Discussion: The shell protocol will limit the set of folders applications can open when run in protected mode. Restricting files an application can open to a limited set of folders increases the security of Windows." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15682" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Feeds\ " /v "DisableEnclosureDownload" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Attachments must be prevented from being downloaded from RSS feeds." >> Win2012.txt
echo "Discussion: Attachments from RSS feeds may not be secure. This setting will prevent attachments from being downloaded from RSS feeds." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15680" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "LogonType" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The classic logon screen must be required for user logons." >> Win2012.txt
echo "Discussion: The classic logon screen requires users to enter a logon name and password to access a system. The simple logon screen or Welcome screen displays usernames for selection, providing part of the necessary logon information. " >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-15674" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ " /v "NoInternetOpenWith" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Internet File Association service must be turned off." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting prevents unhandled file associations from using the Microsoft Web service to find an application." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-15672" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EventViewer\ " /v "MicrosoftEventVwrDisableLinks" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Event Viewer Events.asp links must be turned off. " >> Win2012.txt
echo "Discussion: Viewing events is a function of administrators, who must not access the internet with privileged accounts. This setting will disable Events.asp hyperlinks in Event Viewer to prevent links to the internet from within events." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15667" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections\ " /v "NC_AllowNetBridge_NLA" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Network Bridges must be prohibited in Windows." >> Win2012.txt
echo "Discussion: A Network Bridge can connect two or more network segments, allowing unauthorized access or exposure of sensitive data. This setting prevents a Network Bridge from being installed and configured." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-15666" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Peernet\ " /v "Disabled" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Windows Peer-to-Peer networking services must be turned off." >> Win2012.txt
echo "Discussion: Peer-to-Peer applications can allow unauthorized access to a system and exposure of sensitive data. This setting will turn off the Microsoft Peer-to-Peer Networking Service." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14261" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching\ " /v "DontSearchWindowsUpdate" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Windows must be prevented from using Windows Update to search for drivers." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting prevents Windows from searching Windows Update for device drivers when no local drivers for a device are present." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-14260" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\ " /v "DisableWebPnPDownload" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Downloading print driver packages over HTTP must be prevented." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting prevents the computer from downloading print driver packages over HTTP." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14259" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\ " /v "DisableHTTPPrinting" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Printing over HTTP must be prevented." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting prevents the client computer from printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14253" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\ " /v "RestrictRemoteClients" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Unauthenticated RPC clients must be restricted from connecting to the RPC server." >> Win2012.txt
echo "Discussion: Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14249" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "fDisableCdm" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Local drives must be prevented from sharing with Remote Desktop Session Hosts. (Remote Desktop Services Role)." >> Win2012.txt
echo "Discussion: Preventing users from sharing the local drives on their client computers to Remote Session Hosts that they access helps reduce possible exposure of sensitive data." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-14247" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "DisablePasswordSaving" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Passwords must not be saved in the Remote Desktop Client." >> Win2012.txt
echo "Discussion: Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system. The system must be configured to prevent users from saving passwords in the Remote Desktop Client." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14243" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\ " /v "EnumerateAdministrators" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must require username and password to elevate a running application." >> Win2012.txt
echo "Discussion: Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to type in a username and password to elevate a running application." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14242" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "EnableVirtualization" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: User Account Control must virtualize file and registry write failures to per-user locations." >> Win2012.txt
echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures non-UAC-compliant applications to run in virtualized file and registry entries in per-user locations, allowing them to run." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14241" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "PromptOnSecureDesktop" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: User Account Control must switch to the secure desktop when prompting for elevation." >> Win2012.txt
echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting ensures that the elevation prompt is only used in secure desktop mode." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14240" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "EnableLUA" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: User Account Control must run all administrators in Admin Approval Mode, enabling UAC." >> Win2012.txt
echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting enables UAC." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14239" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "EnableSecureUIAPaths" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: User Account Control must only elevate UIAccess applications that are installed in secure locations." >> Win2012.txt
echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures Windows to only allow applications installed in a secure location on the file system, such as the Program Files or the Windows\System32 folders, to run with elevated privileges." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-14237" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "EnableInstallerDetection" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: User Account Control must be configured to detect application installations and prompt for elevation." >> Win2012.txt
echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting requires Windows to respond to application installation requests by prompting for credentials." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14236" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "ConsentPromptBehaviorUser" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: User Account Control must automatically deny standard user requests for elevation." >> Win2012.txt
echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting controls the behavior of elevation when requested by a standard user account." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14235" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "ConsentPromptBehaviorAdmin" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: User Account Control must, at minimum, prompt administrators for consent." >> Win2012.txt
echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the elevation requirements for logged on administrators to complete a task that requires raised privileges." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14234" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "FilterAdministratorToken" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: User Account Control approval mode for the built-in Administrator must be enabled." >> Win2012.txt
echo "Discussion: User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the built-in Administrator account so that it runs in Admin Approval Mode." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14232" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\IPSEC\ " /v "NoDefaultExempt" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: IPSec Exemptions must be limited." >> Win2012.txt
echo "Discussion: IPSec exemption filters allow specific traffic that may be needed by the system for such things as Kerberos authentication. This setting configures Windows for specific IPSec exemptions." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14230" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ " /v "SCENoApplyLegacyAuditPolicy" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Audit policy using subcategories must be enabled." >> Win2012.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. 
This setting allows administrators to enable more precise auditing capabilities." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14229" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ " /v "FullPrivilegeAuditing" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Auditing of Backup and Restore Privileges must be turned off." >> Win2012.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. 
This setting prevents the system from generating audit events for every file backed up or restored, which could fill the security log in Windows, making it difficult to identify actual issues." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14228" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ " /v "AuditBaseObjects" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Auditing the Access of Global System Objects must be turned off." >> Win2012.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
This setting prevents the system from setting up a default system access control list for certain system objects, which could create a very large number of security events, filling the security log in Windows and making it difficult to identify actual issues." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-11806" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "DontDisplayLastUserName" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to prevent the display of the last username on the logon screen." >> Win2012.txt
echo "Discussion: Displaying the username of the last logged on user provides half of the userid/password equation that an unauthorized person would need to gain access. The username of the last user to log on to a system must not be displayed." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-6834" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\ " /v "RestrictNullSessAccess" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Anonymous access to Named Pipes and Shares must be restricted." >> Win2012.txt
echo "Discussion: Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access. This setting restricts access to those defined in 'Network access: Named Pipes that can be accessed anonymously' and 'Network access: Shares that can be accessed anonymously', both of which must be blank under other requirements." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-6833" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\ " /v "RequireSecuritySignature" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows SMB server must be configured to always perform SMB packet signing." >> Win2012.txt
echo "Discussion: The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will only communicate with an SMB client that performs SMB packet signing." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-6832" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\ " /v "RequireSecuritySignature" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows SMB client must be configured to always perform SMB packet signing." >> Win2012.txt
echo "Discussion: The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB client will only communicate with an SMB server that performs SMB packet signing." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-6831" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\ " /v "RequireSignOrSeal" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Outgoing secure channel traffic must be encrypted or signed." >> Win2012.txt
echo "Discussion: Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted and signed." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-4448" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\ " /v "NoGPOListChanges" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Group Policy objects must be reprocessed even if they have not changed." >> Win2012.txt
echo "Discussion: Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures that the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-4447" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "fEncryptRPCTraffic" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Remote Desktop Session Host must require secure RPC communications." >> Win2012.txt
echo "Discussion: Allowing unsecure RPC communication exposes the system to man-in-the-middle attacks and data disclosure attacks. A man-in-the-middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-4445" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Subsystems\ " /v "Optional" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Optional Subsystems must not be permitted to operate on the system." >> Win2012.txt
echo "Discussion: The POSIX subsystem is an Institute of Electrical and Electronic Engineers (IEEE) standard that defines a set of operating system services. The POSIX Subsystem is required if the server supports applications that use that subsystem. The subsystem introduces a security risk relating to processes that can potentially persist across logins. That is, if a user starts a process and then logs out, there is a potential that the next user who logs in to the system could access the previous users process. This is dangerous because the process started by the first user may retain that users system privileges, and anything the second user does with that process will be performed with the privileges of the first user." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-4443" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\ " /v "Machine" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Unauthorized remotely accessible registry paths and sub-paths must not be configured." >> Win2012.txt
echo "Discussion:The registry is integral to the function, security, and stability of the Windows system. Some processes may require remote access to the registry. This setting controls which registry paths and sub-paths are accessible from a remote computer. These registry paths must be limited, as they could give unauthorized individuals access to the registry." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-4442" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ " /v "ScreenSaverGracePeriod" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to have password protection take effect within a limited time frame when the screen saver becomes active." >> Win2012.txt
echo "Discussion: Allowing more than several seconds makes the computer vulnerable to a potential attack from someone walking up to the console to attempt to log on to the system before the lock takes effect." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-4438" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\ " /v "TcpMaxDataRetransmissions" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must limit how many times unacknowledged TCP data is retransmitted." >> Win2012.txt
echo "Discussion: In a SYN flood attack, the attacker sends a continuous stream of SYN packets to a server, and the server leaves the half-open connections open until it is overwhelmed and is no longer able to respond to legitimate requests." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-4116" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\ " /v "NoNameReleaseOnDemand" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to ignore NetBIOS name release requests except from WINS servers." >> Win2012.txt
echo "Discussion: Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service (DoS) attack. The DoS consists of sending a NetBIOS name release request to the server for each entry in the server's cache, causing a response delay in the normal operation of the servers WINS resolution capability." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-4113" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\ " /v "KeepAliveTime" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to limit how often keep-alive packets are sent." >> Win2012.txt
echo "Discussion: This setting controls how often TCP sends a keep-alive packet in attempting to verify that an idle connection is still intact. A higher value could allow an attacker to cause a denial of service with numerous connections." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-4112" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\ " /v "PerformRouterDiscovery" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to disable the Internet Router Discovery Protocol (IRDP)." >> Win2012.txt
echo "Discussion: The Internet Router Discovery Protocol (IRDP) is used to detect and configure default gateway addresses on the computer. If a router is impersonated on a network, traffic could be routed through the compromised system." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-4111" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\ " /v "EnableICMPRedirect" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes." >> Win2012.txt
echo "Discussion: Allowing ICMP redirect of routes can lead to traffic not being routed properly. When disabled, this forces ICMP to be routed via shortest path first. " >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-4110" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\ " /v "DisableIPSourceRouting" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to prevent IP source routing." >> Win2012.txt
echo "Discussion: Configuring the system to disable IP source routing protects against spoofing." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-4108" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\Security\ " /v "WarningLevel" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must generate an audit event when the audit log reaches a percentage of full threshold." >> Win2012.txt
echo "Discussion: When the audit log reaches a given percent full, an audit event is written to the security log. It is recorded as a successful audit event under the category of System. This option may be especially useful if the audit logs are set to be cleared manually." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3666" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\ " /v "NTLMMinServerSec" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to meet the minimum session security requirement for NTLM SSP-based servers." >> Win2012.txt
echo "Discussion: Microsoft has implemented a variety of security support providers for use with RPC sessions. All of the options must be enabled to ensure the maximum security level." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3480" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer\ " /v "DisableAutoupdate" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Windows Media Player must be configured to prevent automatic checking for updates." >> Win2012.txt
echo "Discussion: Uncontrolled system updates can introduce issues to a system. The automatic check for updates performed by Windows Media Player must be disabled to ensure a constant platform and to prevent the introduction of unknown\untested software on the system." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3479" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\ " /v "SafeDllSearchMode" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to use Safe DLL Search Mode." >> Win2012.txt
echo "Discussion: The default search behavior, when an application calls a function in a Dynamic Link Library (DLL), is to search the current directory, followed by the directories contained in the system's path environment variable. An unauthorized DLL, inserted into an application's working directory, could allow malicious code to be run on the system. Setting this policy value forces the system to search the %Systemroot% for the DLL before searching the current directory or the rest of the path." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3472" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\W32time\Parameters\ " /v "Type" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\W32time\Parameters\ " /v "NTPServer" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: If the time service is configured, it must use an authorized time server." >> Win2012.txt
echo "Discussion: The Windows Time Service controls time synchronization settings. Time synchronization is essential for authentication and auditing purposes. If the Windows Time Service is used, it must synchronize with a secure, authorized time source. Domain-joined systems are automatically configured to synchronize with domain controllers. If an NTP server is configured, it must synchronize with a secure, authorized time source." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3470" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "fAllowUnsolicited" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title:  The system must be configured to prevent unsolicited remote assistance offers." >> Win2012.txt
echo "Discussion:  Remote assistance allows another user to view or take control of the local session of a user. Unsolicited remote assistance is help that is offered by the remote user. This may allow unauthorized parties access to the resources on the computer." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-3469" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\system\ " /v "DisableBkGndGroupPolicy" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Group Policies must be refreshed in the background if the user is logged on." >> Win2012.txt
echo "Discussion: If this setting is enabled, then Group Policy settings are not refreshed while a user is currently logged on. This could lead to instances when a user does not have the latest changes to a policy applied and is therefore operating in an insecure context." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3456" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "DeleteTempDirsOnExit" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Remote Desktop Services must delete temporary folders when a session is terminated." >> Win2012.txt
echo "Discussion: Remote desktop session temporary folders must always be deleted after a session is over to prevent hard disk clutter and potential leakage of information. This setting controls the deletion of the temporary folders when the session is terminated." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3455" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "PerSessionTempDir" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Remote Desktop Services must be configured to use session-specific temporary folders." >> Win2012.txt
echo "Discussion: If a communal temporary folder is used for remote desktop sessions, it might be possible for users to access other users' temporary folders. If this setting is enabled, only one temporary folder is used for all remote desktop sessions. Per session temporary folders must be established." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3454" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "MinEncryptionLevel" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Remote Desktop Services must be configured with the client connection encryption set to the required level." >> Win2012.txt
echo "Discussion: Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3453" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\ " /v "fPromptForPassword" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Remote Desktop Services must always prompt a client for passwords upon connection." >> Win2012.txt
echo "Discussion: This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3449" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\  " /v "fSingleSessionPerUser" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Remote Desktop Services must limit users to one remote session." >> Win2012.txt
echo "Discussion: Allowing multiple Remote Desktop Services sessions could consume resources. There is also potential to make a secondary connection to a system with compromised credentials." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3385" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ " /v "ObCaseInsensitive" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to require case insensitivity for non-Windows subsystems." >> Win2012.txt
echo "Discussion: This setting controls the behavior of non-Windows subsystems when dealing with the case of arguments or commands. Case sensitivity could lead to the access of files or commands that must be restricted. To prevent this from happening, case insensitivity restrictions must be required." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3383" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\ " /v "Enabled" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing." >> Win2012.txt
echo "Discussion: This setting ensures that the system uses algorithms that are FIPS-compliant for encryption, hashing, and signing. FIPS-compliant algorithms meet specific standards established by the U.S. Government and must be the algorithms used for all OS encryption functions." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3382" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\ " /v "NTLMMinClientSec" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to meet the minimum session security requirement for NTLM SSP-based clients." >> Win2012.txt
echo "Discussion: Microsoft has implemented a variety of security support providers for use with RPC sessions. All of the options must be enabled to ensure the maximum security level." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3381" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP\ " /v "LDAPClientIntegrity" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to the required LDAP client signing level." >> Win2012.txt
echo "Discussion: This setting controls the signing requirements for LDAP clients. This setting must be set to Negotiate signing or Require signing, depending on the environment and type of LDAP server in use." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

timeout /t 5

echo "V-3379" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ " /v "NoLMHash" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to prevent the storage of the LAN Manager hash of passwords." >> Win2012.txt
echo "Discussion: The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords. This setting controls whether or not a LAN Manager hash of the password is stored in the SAM the next time the password is changed." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3378" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ " /v "ForceGuest" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to use the Classic security model." >> Win2012.txt
echo "Discussion: Windows includes two network-sharing security models - Classic and Guest only. With the Classic model, local accounts must be password protected; otherwise, anyone can use guest user accounts to access shared system resources." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3377" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ " /v "ForceGuest" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to prevent anonymous users from having the same rights as the Everyone group." >> Win2012.txt
echo "Discussion: Access by anonymous users must be restricted. If this setting is enabled, then anonymous users have the same rights and permissions as the built-in Everyone group. Anonymous users must not have these permissions or rights." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3376" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ " /v "DisableDomainCreds" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to prevent the storage of passwords and credentials." >> Win2012.txt
echo "Discussion: This setting controls the storage of passwords and credentials for network authentication on the local system. Such credentials must not be stored on the local machine, as that may lead to account compromise." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3374" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\ " /v "RequireStrongKey" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must be configured to require a strong session key." >> Win2012.txt
echo "Discussion: A computer connecting to a domain controller will establish a secure channel. Requiring strong session keys enforces 128-bit encryption between systems." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3373" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\ " /v "MaximumPasswordAge" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The maximum age for machine account passwords must be set to requirements." >> Win2012.txt
echo "Discussion: Computer account passwords are changed automatically on a regular basis. This setting controls the maximum password age that a machine account may have. This setting must be set to no more than 30 days, ensuring the machine changes its password monthly." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3344" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ " /v "LimitBlankPasswordUse" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Local accounts with blank passwords must be restricted to prevent access from the network." >> Win2012.txt
echo "Discussion: An account without a password can allow unauthorized access to a system as only the username would be required. Password policies should prevent accounts with blank passwords from existing on a system. However, if a local account with a blank password did exist, enabling this setting will prevent network access, limiting the account to local console logon only." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3343" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\  " /v "fAllowToGetHelp" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Solicited Remote Assistance must not be allowed." >> Win2012.txt
echo "Discussion: Remote assistance allows another user to view or take control of the local session of a user. Solicited assistance is help that is specifically requested by the local user. This may allow unauthorized parties access to the resources on the computer." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3340" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\ " /v "NullSessionShares" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Network shares that can be accessed anonymously must not be allowed." >> Win2012.txt
echo "Discussion: Anonymous access to network shares provides the potential for gaining unauthorized system access by network users. This could lead to the exposure or corruption of sensitive data." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3339" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\ " /v "Machine" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)echo "Rule Title:" >> Win2012.txt
echo "Rule Title: Unauthorized remotely accessible registry paths must not be configured." >> Win2012.txt
echo "Discussion: The registry is integral to the function, security, and stability of the Windows system. Some processes may require remote access to the registry. This setting controls which registry paths are accessible from a remote computer. These registry paths must be limited, as they could give unauthorized individuals access to the registry." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-3338"
echo "V-3338" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\ " /v "NullSessionPipes" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Named pipes that can be accessed anonymously must be configured to contain no values on member servers." >> Win2012.txt
echo "Discussion: Named pipes that can be accessed anonymously provide the potential for gaining unauthorized system access. Pipes are internal system communications processes. They are identified internally by ID numbers that vary between systems. To make access to these processes easier, these pipes are given names that do not vary between systems. This setting controls which of these pipes anonymous users may access." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-2374" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\ " /v "NoDriveTypeAutoRun" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Autoplay must be disabled for all drives." >> Win2012.txt
echo "Discussion: Allowing Autoplay to execute may introduce malicious code to a system. Autoplay begins reading from a drive as soon media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. By default, Autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives. Enabling this policy disables Autoplay on all drives." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1174" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ " /v "" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The amount of idle time required before suspending a session must be properly set." >> Win2012.txt
echo "Discussion: Open sessions can increase the avenues of attack on a system. This setting is used to control when a computer disconnects an inactive SMB session. If client activity resumes, the session is automatically reestablished. This protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1173" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\ " /v "ProtectionMode" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The default permissions of global system objects must be increased." >> Win2012.txt
echo "Discussion: Windows systems maintain a global list of shared system resources such as DOS device names, mutexes, and semaphores. Each type of object is created with a default DACL that specifies who can access the objects with what permissions. If this policy is enabled, the default DACL is stronger, allowing nonadministrative users to read shared objects, but not modify shared objects that they did not create." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1172" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ " /v "PasswordExpiryWarning" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must be warned in advance of their passwords expiring." >> Win2012.txt
echo "Discussion: Creating strong passwords that can be remembered by users requires some thought. By giving the user advance warning, the user has time to construct a sufficiently strong password. This setting configures the system to display a warning to users telling them how many days are left before their password expires." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1171" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ " /v "AllocateDASD" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Ejection of removable NTFS media must be restricted to Administrators." >> Win2012.txt
echo "Discussion: Removable hard drives, if they are not properly configured, can be formatted and ejected by users who are not members of the Administrators Group. Formatting and ejecting removable NTFS media must only be done by administrators." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1166" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\ " /v "EnableSecuritySignature" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows SMB client must be enabled to perform SMB packet signing when possible." >> Win2012.txt
echo "Discussion: The server message block (SMB) protocol provides the basis for many network operations. If this policy is enabled, the SMB client will request packet signing when communicating with an SMB server that is enabled or required to perform SMB packet signing." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1165" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\ " /v "DisablePasswordChange" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The computer account password must not be prevented from being reset." >> Win2012.txt
echo "Discussion: Computer account passwords are changed automatically on a regular basis. Disabling automatic password changes can make the system more vulnerable to malicious access. Frequent password changes can be a significant safeguard for your system. A new password for the computer account will be generated every 30 days." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1164" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ " /v "SignSecureChannel" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Outgoing secure channel traffic must be signed when possible." >> Win2012.txt
echo "Discussion: Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but the channel is not integrity checked. If this policy is enabled, outgoing secure channel traffic will be signed." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1163" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ " /v "SealSecureChannel" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Outgoing secure channel traffic must be encrypted when possible." >> Win2012.txt
echo "Discussion: Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted. If this policy is enabled, outgoing secure channel traffic will be encrypted." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-1162" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\ " /v "EnableSecuritySignature" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows SMB server must perform SMB packet signing when possible." >> Win2012.txt
echo "Discussion: The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will negotiate SMB packet signing as requested by the client." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1157" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ " /v "SCRemoveOption" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Smart Card removal option must be configured to Force Logoff or Lock Workstation." >> Win2012.txt
echo "Discussion: Unattended systems are susceptible to unauthorized use and must be locked. Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1154" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "DisableCAD" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Ctrl+Alt+Del security attention sequence for logons must be enabled." >> Win2012.txt
echo "Discussion: Disabling the Ctrl+Alt+Del security attention sequence can compromise system security. Because only Windows responds to the Ctrl+Alt+Del security sequence, a user can be assured that any passwords entered following that sequence are sent only to Windows. If the sequence requirement is eliminated, malicious programs can request and receive a user's Windows password. Disabling this sequence also suppresses a custom logon banner." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1153" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ " /v "LmCompatibilityLevel" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM." >> Win2012.txt
echo "Discussion: The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts. NTLM, which is less secure, is retained in later Windows versions for compatibility with clients and servers that are running earlier versions of Windows or applications that still use it. It is also used to authenticate logons to stand-alone computers that are running later versions." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1151" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\ " /v "AddPrinterDrivers" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The print driver installation privilege must be restricted to administrators." >> Win2012.txt
echo "Discussion: Allowing users to install drivers can introduce malware or cause the instability of a system. Print driver installation should be restricted to administrators." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1145" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ " /v "AutoAdminLogon" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ " /v "DefaultPassword" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Automatic logons must be disabled." >> Win2012.txt
echo "Discussion: Allowing a system to automatically log on when the machine is booted could give access to any unauthorized individual who restarts the computer. Automatic logon with administrator privileges would give full access to an unauthorized individual." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1141" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\ " /v "EnablePlainTextPassword" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Unencrypted passwords must not be sent to third-party SMB Servers." >> Win2012.txt
echo "Discussion: Some non-Microsoft SMB servers only support unencrypted (plain text) password authentication. Sending plain text passwords across the network, when authenticating to an SMB server, reduces the overall security of the environment. Check with the vendor of the SMB server to see if there is a way to support encrypted password authentication." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1136" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\ " /v "EnableForcedLogoff" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must be forcibly disconnected when their logon hours expire." >> Win2012.txt
echo "Discussion: Users must not be permitted to remain logged on to the network after they have exceeded their permitted logon hours. In many cases, this indicates that a user forgot to log off before leaving for the day. However, it may also indicate that a user is attempting unauthorized access at a time when the system may be less closely monitored. Forcibly disconnecting users when logon hours expire protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1093" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ " /v "RestrictAnonymous" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Anonymous enumeration of shares must be restricted." >> Win2012.txt
echo "Discussion: Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1090" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ " /v "CachedLogonsCount" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Caching of logon credentials must be limited." >> Win2012.txt
echo "Discussion: The default Windows configuration caches the last logon credentials for users who log on interactively to a system. This feature is provided for system availability reasons, such as the user's machine being disconnected from the network or domain controllers being unavailable. Even though the credential cache is well-protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5


echo "V-1089" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "LegalNoticeText" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The required legal notice must be configured to display before console logon." >> Win2012.txt
echo "Discussion: Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-1075" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "LegalNoticeText" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The shutdown option must not be available from the logon dialog box." >> Win2012.txt
echo "Discussion: Displaying the shutdown button may allow individuals to shut down a system anonymously. Only authenticated users should be allowed to shut down the system. Preventing display of this button in the logon dialog box ensures that individuals who shut down the system are authorized and tracked in the system's Security event log." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "--------------------------HKEY_CURRENT_USER---------------------------" >> Win2012.txt

echo "V-36777" >> Win2012.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\ " /v "NoToastApplicationNotificationOnLockScreen" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Toast notifications to the lock screen must be turned off." >> Win2012.txt
echo "Discussion: Toast notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged on user." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36776" >> Win2012.txt
reg query "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\ " /v "NoCloudApplicationNotification" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Notifications from Windows Push Network Service must be turned off." >> Win2012.txt
echo "Discussion: The Windows Push Notification Service (WNS) allows third-party vendors to send updates for toasts, tiles, and badges." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36775" >> Win2012.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System\ " /v "NoDispScrSavPage" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Changing the screen saver must be prevented." >> Win2012.txt
echo "Discussion: Unattended systems are susceptible to unauthorized use and must be locked. Preventing users from changing the screen saver ensures an approved screen saver is used. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36774" >> Win2012.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ " /v "SCRNSAVE.EXE" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: A screen saver must be defined." >> Win2012.txt
echo "Discussion: Unattended systems are susceptible to unauthorized use and must be locked. Specifying a screen saver ensures the screen saver timeout lock is initiated properly. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36657" >> Win2012.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ " /v "ScreenSaverIsSecure" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The screen saver must be password protected." >> Win2012.txt
echo "Discussion: Unattended systems are susceptible to unauthorized use and must be locked when unattended. Enabling a password-protected screen saver to engage after a specified period of time helps protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-36656" >> Win2012.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ " /v "ScreenSaveActive" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: A screen saver must be enabled on the system." >> Win2012.txt
echo "Discussion: Unattended systems are susceptible to unauthorized use and must be locked when unattended. Enabling a password-protected screen saver to engage after a specified period of time helps protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-16048" >> Win2012.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Assistance\Client\1.0\ " /v "NoExplicitFeedback" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Windows Help Ratings feedback must be turned off." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting ensures users cannot provide ratings feedback to Microsoft for Help content." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-16021" >> Win2012.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Assistance\Client\1.0\ " /v "NoImplicitFeedback" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The Windows Help Experience Improvement Program must be disabled." >> Win2012.txt
echo "Discussion: Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. 
This setting ensures the Windows Help Experience Improvement Program is disabled to prevent information from being passed to the vendor." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


timeout /t 5

echo "V-15727" >> Win2012.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ " /v "NoInPlaceSharing" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Users must be prevented from sharing files in their profiles." >> Win2012.txt
echo "Discussion: Allowing users to share files in their profiles may provide unauthorized access or result in the exposure of sensitive data." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14270" >> Win2012.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ " /v "ScanWithAntiVirus" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: The system must notify antivirus when file attachments are opened." >> Win2012.txt
echo "Discussion: Attaching malicious files is a known avenue of attack. This setting configures the system to notify antivirus programs when a user opens a file attachment." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-14269" >> Win2012.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ " /v "HideZoneInfoOnProperties" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Mechanisms for removing zone information from file attachments must be hidden." >> Win2012.txt
echo "Discussion: Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows Windows to determine risk. This setting prevents users from manually removing zone information from saved file attachments." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-13268" >> Win2012.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ " /v "SaveZoneInformation" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: " >> Win2012.txt
echo "Discussion: Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows Windows to determine risk." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-3481" >> Win2012.txt
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\WindowsMediaPlayer\ " /v "PreventCodecDownload" >> Win2012.txt
IF %errorlevel% == 0 (echo "SUCCESS" >> Win20123.txt) else (echo "FAILURE" >> Win20123.txt)
echo "Rule Title: Media Player must be configured to prevent automatic Codec downloads." >> Win2012.txt
echo "Discussion: The Windows Media Player uses software components, referred to as Codecs, to play back media files. By default, when an unknown file type is opened with the Media Player, it will search the Internet for the appropriate Codec and automatically download it. To ensure platform consistency and to protect against new vulnerabilities associated with media types, all Codecs must be installed by the System Administrator." >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt


AuditPol /get /category:* > AUDITPOL.txt

echo "V-26529" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Credential validation records events related to validation tests on credentials for a user account logon." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Account Logon - Credential Validation successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "^Credential.*Validation$" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding. Account Logon -> Credential Validation - Success
"
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26530" >> query.txt
echo "Discussion:" >> Win2012.txt
echo "Rule Title:" >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "^Credential.*Validation$" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding. Account Logon -> Credential Validation - Failure
"
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26531" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Computer Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling computer accounts." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Account Management - Computer Account Management successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "^.*$" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.

Account Management -> Computer Account Management - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26532" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Computer Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling computer accounts." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Account Management - Computer Account Management failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "^Computer.*Account Managemen$" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding." >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26533" >> query.txt
echo "Discussion:Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Other Account Management Events records events such as the access of a password hash or the Password Policy Checking API being called." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Account Management - Other Account Management Events successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "^Other.*Account Management Events$" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding. Account Management -> Other Account Management Events - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26534" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Account Management - Other Account Management Events failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "^Other.*Account Management Events$" >> Win2012.txt
echo "FINDING:Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Account Management -> Other Account Management Events - Failur" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26535" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Account Management - Security Group Management successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "^Security.*Group Management$" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding." >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26536" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Account Management - Security Group Management failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "^Security.*Group Management$" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding." >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26537" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Account Management - User Account Management successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "^User.*Account Management$" >> Win2012.txt
echo "FINDING:" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26538" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Account Management - User Account Management failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "User Account Management" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Account Management -> User Account Management - Failur" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26539" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Detailed Tracking - Process Creation successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Process Creation" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding." >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26540" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Logon/Logoff - Logoff successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Logoff" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding." >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26541" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Logon/Logoff - Logon successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Logon" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Logon/Logoff -> Logoff - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26542" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title:The system must be configured to audit Logon/Logoff - Logon failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Logon" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.Logon/Logoff -> Logon - FAILURE" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26543" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Logon/Logoff - Special Logon successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Special Logon" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Logon/Logoff -> Special Logon - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-26546" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Policy Change - Audit Policy Change successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Audit Policy Change" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Policy Change -> Audit Policy Change - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26547" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Audit Policy Change records events related to changes in audit policy." >> Win2012.txt
echo "Rule Title:  The system must be configured to audit Policy Change - Audit Policy Change failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Audit Policy Change" >> Win2012.txt
echo "FINDING:Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Policy Change -> Audit Policy Change - Failure" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26548" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Authentication Policy Change records events related to changes in authentication policy, including Kerberos policy and Trust changes." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Policy Change - Authentication Policy Change successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Authentication Policy Change" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding. Policy Change -> Authentication Policy Change - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26549" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Privilege Use - Sensitive Privilege Use successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Sensitive Privilege Use" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Privilege Use -> Sensitive Privilege Use - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26550" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Privilege Use - Sensitive Privilege Use failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Sensitive Privilege Use" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding." >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26551" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit System - IPsec Driver successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "IPsec Driver" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding. System -> IPsec Driver - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26552" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit System - IPsec Driver failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "IPsec Driver" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
System -> IPsec Driver - Failure" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26553" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit System - Security State Change successes. " >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Security State Change" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
System -> Security State Change - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26554" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit System - Security State Change failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Security State Change" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding." >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26555" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit System - Security System Extension successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Security System Extension" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding. System -> Security System Extension - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26556" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit System - Security System Extension failures.The system must be configured to audit System - Security System Extension failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Security System Extension" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding. System -> Security System Extension - Failure" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-26557" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior." >> Win2012.txt
echo "Rule Title: The system must be configured to audit System - System Integrity successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "System Integrity" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
System -> System Integrity - Success" >> Win2012



echo "V-26558" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Removable Storage auditing under Object Access records events related to access attempts on file system objects on removable storage devices." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Object Access - Removable Storage failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "System Integrity" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
System ->  System Integrity - Failure" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-36667" >> query.txt
echo "Discussion:" >> Win2012.txt
echo "Rule Title:" >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Removable Storage" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Object Access >> Removable Storage - Failure" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt



echo "V-36668" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Removable Storage auditing under Object Access records events related to access attempts on file system objects on removable storage devices." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Object Access - Removable Storage successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Removable Storage" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding." >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt



echo "V-40200" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Central Access Policy Staging auditing under Object Access is used to enable the recording of events related to differences in permissions between central access policies and proposed policies." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Object Access - Central Access Policy Staging failures." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Central Policy Staging" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Object Access -> Central Policy Staging - Failure" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-40202" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Central Access Policy Staging auditing under Object Access is used to enable the recording of events related to differences in permissions between central access policies and proposed policies." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Object Access - Central Access Policy Staging successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Central Policy Staging" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Object Access -> Central Policy Staging - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt

echo "V-57633" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Authorization Policy Change records events related to changes in user rights, such as Create a token object." >> Win2012.txt
echo "Rule Title: The system must be configured to audit Policy Change - Authorization Policy Change successes." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Central Policy Staging" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Policy Change -> Authorization Policy Change - Success" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt


echo "V-57635" >> query.txt
echo "Discussion: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Authorization Policy Change records events related to changes in user rights, such as Create a token object." >> Win2012.txt
echo "Rule Title: Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
Authorization Policy Change records events related to changes in user rights, such as Create a token object." >> Win2012.txt
TYPE AUDITPOL.txt | findstr /i "Authorization Policy Change" >> Win2012.txt
echo "FINDING: Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.
Policy Change -> Authorization Policy Change - Failure" >> Win2012
echo "---------------------------------------------------------------------"  >> Win2012.txt





gpresult/h gpresult.html
gpresult /r > gpresult.txt



echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1097" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The number of allowed bad logon attempts must meet minimum requirements." >> Win2012.txt
echo "Discussion:  The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher this value is, the less effective the account lockout feature will be in protecting the local system.  The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Account Lockout Policy"
echo "Finding: If the 'Account lockout threshold' is '0' or more than '3' attempts, this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt

 
echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1098" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The period of time before the bad logon counter is reset must meet minimum requirements." >> Win2012.txt
echo "Discussion:  The account lockout feature, when enabled, prevents brute-force password attacks on the system.  This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to 0.  The smaller this value is, the less effective the account lockout feature will be in protecting the local system." >> Win2012.txt
TYPE gpresult.txt | findstr /i " Account Lockout Policy"
echo "Finding: If the 'Reset account lockout counter after' value is less than '60' minutes, this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt



echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1099" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The lockout duration must be configured to require an administrator to unlock an account." >> Win2012.txt
echo "Discussion:  The account lockout feature, when enabled, prevents brute-force password attacks on the system.  This parameter specifies the period of time that an account will remain locked after the specified number of failed logon attempts.  A value of 0 will require an administrator to unlock the account." >> Win2012.txt
TYPE gpresult.txt | findstr /i " Account Lockout Policy"
echo "Finding: If the 'Account lockout duration' is not set to '0', requiring an administrator to unlock the account, this is a finding. " >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt



echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1102" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: high" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Act as part of the operating system user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Act as part of the operating system" user right can assume the identity of any user and gain access to resources that user is authorized to access.  Any accounts with this right can take complete control of a system." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups (to include administrators), are granted the 'Act as part of the operating system' user right, this is a finding. " >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1104" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The maximum password age must meet requirements." >> Win2012.txt
echo "Discussion:  The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords.   Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Password Policy"
echo "Finding: If the value for the 'Maximum password age' is greater than '60' days, this is a finding. If the value is set to '0' (never expires), this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1105" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The minimum password age must meet requirements." >> Win2012.txt
echo "Discussion:  Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database.  This enables users to effectively negate the purpose of mandating periodic password changes." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Password Policy"
echo "Finding: If the value for the 'Minimum password age' is set to '0' days ('Password can be changed immediately.'), this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1107" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The password history must be configured to 24 passwords remembered." >> Win2012.txt
echo "Discussion:  A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change to a unique password on a regularly scheduled basis. This enables users to effectively negate the purpose of mandating periodic password changes.  The default value is 24 for Windows domain systems.  DoD has decided this is the appropriate value for all Windows systems." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Password Policy"
echo "Finding: If the value for 'Enforce password history' is less than '24' passwords remembered, this is a finding. " >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1113" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The built-in guest account must be disabled." >> Win2012.txt
echo "Discussion:  A system faces an increased vulnerability threat if the built-in guest account is not disabled.  This account is a known account that exists on all Windows systems and cannot be deleted.  This account is initialized during the installation of the operating system with no password assigned." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Security Options"
echo "Finding: If the value for 'Accounts: Guest account status' is not set to 'Disabled', this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1114" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The built-in guest account must be renamed." >> Win2012.txt
echo "Discussion:  The built-in guest account is a well-known user account on all Windows systems and, as initially installed, does not require a password.  This can allow access to system resources by unauthorized users.  Renaming this account to an unidentified name improves the protection of this account and the system." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Security Options"
echo "Finding: If the value for 'Accounts: Rename guest account' is not set to a value other than 'Guest', this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1115" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The built-in administrator account must be renamed." >> Win2012.txt
echo "Discussion:  The built-in administrator account is a well-known account subject to attack.  Renaming this account to an unidentified name improves the protection of this account and the system." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Security Options"
echo "Finding: If the value for 'Accounts: Rename administrator account' is not set to a value other than 'Administrator', this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1150" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The built-in Windows password complexity policy must be enabled." >> Win2012.txt
echo "Discussion:  The use of complex passwords increases their strength against attack. The built-in Windows password complexity policy requires passwords to contain at least 3 of the 4 types of characters (numbers, upper- and lower-case letters, and special characters), as well as preventing the inclusion of user names or parts of." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Password Policy"
echo "Finding: If the value for 'Password must meet complexity requirements' is not set to 'Enabled', this is a finding."
echo "|---------------------------------------------------------------------|" >> Win2012.txt



echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-1155" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny access to this computer from the network' user right defines the accounts that are prevented from logging on from the network.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: 
If the following accounts or groups are not defined for the 'Deny access to this computer from the network' user right, this is a finding:


Domain Systems Only:
Enterprise Admins group
Domain Admins group
'Local account and member of Administrators group' or 'Local account' (see Note below)

All Systems:
Guests group

Systems dedicated to the management of Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from denying the Enterprise Admins and Domain Admins groups.

Note: Windows Server 2012 R2 added new built-in security groups, 'Local account' and 'Local account and member of Administrators group'. 'Local account' is more restrictive but may cause issues on servers such as systems that provide Failover Clustering.
Microsoft Security Advisory Patch 2871997 adds the new security groups to Windows Server 2012.
" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-2372" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: high" >> Win2012.txt
echo "Rule Title: Reversible password encryption must be disabled." >> Win2012.txt
echo "Discussion:  Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the passwords.  For this reason, this policy must never be enabled." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Password Policy" >> Win2012.txt
echo "Finding: If the value for 'Store password using reversible encryption' is not set to 'Disabled', this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-3337" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: high" >> Win2012.txt
echo "Rule Title: Anonymous SID/Name translation must not be allowed." >> Win2012.txt
echo "Discussion:  Allowing anonymous SID/Name translation can provide sensitive information for accessing a system.  Only authorized users must be able to perform such translations." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Security Options" >> Win2012.txt
echo "Finding: If the value for 'Network access: Allow anonymous SID/Name translation' is not set to 'Disabled', this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-3380" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The system must be configured to force users to log off when their allowed logon hours expire." >> Win2012.txt
echo "Discussion:  Limiting logon hours can help protect data by only allowing access during specified times.  This setting controls whether or not users are forced to log off when their allowed logon hours expire.  If logon hours are set for users, this must be enforced." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Security Options" >> Win2012.txt
echo "Finding: If the value for 'Network security: Force logoff when logon hours expire' is not set to 'Enabled', this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-6836" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Passwords must, at a minimum, be 14 characters." >> Win2012.txt
echo "Discussion:  Information systems not protected with strong password schemes (including passwords of minimum length) provide the opportunity for anyone to crack the password, thus gaining access to the system and compromising the device, information, or the local network." >> Win2012.txt
TYPE gpresult.txt | findstr /i "Password Policy"
echo "Finding: If the value for the 'Minimum password length,' is less than '14' characters, this is a finding. " >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt

echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-18010" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: high" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Debug programs user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Debug programs' user right can attach a debugger to any process or to the kernel, providing complete access to sensitive and critical operating system components.  This right is given to Administrators in the default configuration." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Debug programs' user right, this is a finding:" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt

echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26469" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Access Credential Manager as a trusted caller user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Access Credential Manager as a trusted caller' user right may be able to retrieve the credentials of other accounts from Credential Manager." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups are granted the 'Access Credential Manager as a trusted caller' user right, this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt

echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26470" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Access this computer from the network user right on member servers." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Access this computer from the network' user right may access resources on the system, and must be limited to those that require it." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Access this computer from the network' user right, this is a finding:

Administrators
Authenticated Users " >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26472" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Allow log on locally user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Allow log on locally' user right can log on interactively to a system." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Allow log on locally' user right, this is a finding:

Administrators
 " >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26479" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: high" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Create a token object user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
The 'Create a token object' user right allows a process to create an access token. This could be used to provide elevated rights and compromise a system." >> Win2012.txt

echo "Finding: If any accounts or groups are granted the 'Create a token object' user right, this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26478" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Create a pagefile user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create a pagefile" user right can change the size of a pagefile, which could affect system performance." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: 
If any accounts or groups other than the following are granted the 'Create a pagefile' user right, this is a finding:

Administrators" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26477" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: low" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Change the time zone user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Change the time zone' user right can change the time zone of a system." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Change the time zone' user right, this is a finding:

Administrators
Local Service" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26476" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Change the system time user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
Accounts with the 'Change the system time' user right can change the system time, which can impact authentication, as well as affect time stamps on event log entries." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Change the system time' user right, this is a finding:

Administrators
Local Service " >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26475" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: low" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Bypass traverse checking user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Bypass traverse checking' user right can pass through folders when browsing even if they do not have the 'Traverse Folder' access permission. They could potentially view sensitive file and folder names.  They would not have additional access to the files and folders unless it is granted through permissions." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Bypass traverse checking' user right, this is a finding:

Administrators
Authenticated Users
Local Service
Network Service
Window Manager\Window Manager Group" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26474" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the back up files and directories user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Back up files and directories' user right can circumvent file and directory permissions and could allow access to sensitive data." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Back up files and directories' user right, this is a finding: " >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26473" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group and other approved groups." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Allow log on through Remote Desktop Services' user right can access a system through Remote Desktop." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Allow log on through Remote Desktop Services' user right, this is a finding:

Administrators" >> Win2012.txt

echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26480" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Create global objects user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
Accounts with the 'Create global objects' user right can create objects that are available to all sessions, which could affect processes in other users sessions." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Create global objects' user right, this is a finding:
Administrators
Service
Local Service
Network Service " >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt



echo "V-26481" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Create permanent shared objects user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Create permanent shared objects' user right could expose sensitive data by creating shared objects." 
TYPE gpresult.txt | findstr /i "User Rights Assignment" >> Win2012.txt
echo "Finding: If any accounts or groups other than the following are granted the 'Create global objects' user right, this is a finding:
Administrators
Service
Local Service
Network Service " >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26482" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Create symbolic links user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Create symbolic links' user right can create pointers to other objects, which could potentially expose the system to attack." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Create symbolic links' user right, this is a finding:
Administrators" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26483" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems, and from unauthenticated access on all systems." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny log on as a batch job' user right defines accounts that are prevented from logging on to the system as a batch job such, as Task Scheduler.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

The Guests group must be assigned to prevent unauthenticated access." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If the following accounts or groups are not defined for the 'Deny log on as a batch job' user right, this is a finding:

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group

All Systems:
Guests Group " >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt




echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26486" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems, and from unauthenticated access on all systems." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny log on through Remote Desktop Services' user right defines the accounts that are prevented from logging on using Remote Desktop Services.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If the following accounts or groups are not defined for the 'Deny log on through Remote Desktop Services' user right, this is a finding:

Domain Systems Only:
Enterprise Admins group
Domain Admins group
Local account (see Note below)

All Systems:
Guests group" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26487" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right on member servers." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Enable computer and user accounts to be trusted for delegation' user right allows the 'Trusted for Delegation' setting to be changed.  This could potentially allow unauthorized users to impersonate other users." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups are granted the 'Enable computer and user accounts to be trusted for delegation' user right, this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26484" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems.  No other groups or accounts must be assigned this right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The'Deny log on as a service' user right defines accounts that are denied log on as a service.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Incorrect configurations could prevent services from starting and result in a DoS." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If the following accounts or groups are not defined for the 'Deny log on as a service' user right on domain-joined systems, this is a finding:

Enterprise Admins Group
Domain Admins Group" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26485" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: The Deny log on locally user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems, and from unauthenticated access on all systems." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Deny log on locally' user right defines accounts that are prevented from logging on interactively.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

The Guests group must be assigned this right to prevent unauthenticated access." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If the following accounts or groups are not defined for the 'Deny log on locally' user right, this is a finding:

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26488" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Force shutdown from a remote system user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Force shutdown from a remote system' user right can remotely shut down a system, which could result in a DoS." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Force shutdown from a remote system' user right, this is a finding:
Administrators" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26489" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Generate security audits user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Generate security audits' user right specifies users and processes that can generate Security Log audit records, which must only be the system service accounts defined." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Generate security audits' user right, this is a finding:

Local Service
Network Service" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt



echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26490" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Impersonate a client after authentication user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Impersonate a client after authentication' user right allows a program to impersonate another user or account to run on their behalf.  An attacker could potentially use this to elevate privileges." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Impersonate a client after authentication' user right, this is a finding:

Administrators
Service
Local Service
Network Service" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26493" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Load and unload device drivers user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Load and unload device drivers' user right allows device drivers to dynamically be loaded on a system by a user.  This could potentially be used to install malicious code by an attacker." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Load and unload device drivers' user right, this is a finding:

Administrators" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26492" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Increase scheduling priority user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Increase scheduling priority' user right can change a scheduling priority causing performance issues or a DoS." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Increase scheduling priority' user right, this is a finding:
Administrators" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26494" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Lock pages in memory user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Lock pages in memory' user right allows physical memory to be assigned to processes, which could cause performance issues or a DoS." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups are granted the 'Lock pages in memory' user right, this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26497" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Modify an object label user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Modify an object label' user right can change the integrity label of an object.  This could potentially be used to execute code at a higher privilege." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups are granted the 'Modify an object label' user right, this is a finding." >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26496" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Manage auditing and security log user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Manage auditing and security log" user right can manage the security log and change auditing configurations.  This could be used to clear evidence of tampering." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Manage auditing and security log' user right, this is a finding:
Administrators" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt

echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26499" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Perform volume maintenance tasks user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Perform volume maintenance tasks' user right can manage volume and disk configurations.  They could potentially delete volumes, resulting in data loss or a DoS." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Perform volume maintenance tasks' user right, this is a finding:
Administrators" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26498" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Modify firmware environment values user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the 'Modify firmware environment values' user right can change hardware configuration environment variables.  This could result in hardware failures or a DoS." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Modify firmware environment values' user right, this is a finding:" >> Win2012.txt

echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26503" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Replace a process level token user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The 'Replace a process level token' user right allows one process or service to start another process or service with a different security access token.  A user with this right could use this to impersonate another account." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Replace a process level token' user right, this is a finding:
Local Service
Network Service" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26501" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Profile system performance user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
Accounts with the'Profile system performance' user right can monitor system processes performance.  An attacker could potentially use this to identify processes to attack." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Profile system performance' user right, this is a finding:
Administrators
NT Service\WdiServiceHost" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26500" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Profile single process user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
Accounts with the 'Profile single process' user right can monitor nonsystem processes performance.  An attacker could potentially use this to identify processes to attack." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment"
echo "Finding: If any accounts or groups other than the following are granted the 'Profile single process' user right, this is a finding:
Administrators" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt




echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26504" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Restore files and directories user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
Accounts with the 'Restore files and directories' user right can circumvent file and directory permissions and could allow access to sensitive data.  It could also be used to overwrite more current data." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment" >> Win2012.txt
echo "Finding: If any accounts or groups other than the following are granted the 'Restore files and directories' user right, this is a finding:
Administrators" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt


echo "V-26505" >> Win2012.txt
echo "Group Title:  " >> Win2012.txt
echo "Severity: medium" >> Win2012.txt
echo "Rule Title: Unauthorized accounts must not have the Shut down the system user right." >> Win2012.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
Accounts with the 'Shut down the system' user right can interactively shut down a system, which could result in a DoS." >> Win2012.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment" >> Win2012.txt
echo "Finding: If any accounts or groups other than the following are granted the 'Shut down the system' user right, this is a finding:
Administrators" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> Win2012.txt
echo "V-26506" >> file.txt
echo "Group Title:  " >> file.txt
echo "Severity: medium" >> file.txt
echo "Rule Title: Unauthorized accounts must not have the Take ownership of files or other objects user right." >> file.txt
echo "Discussion:  Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
Accounts with the 'Take ownership of files or other objects' user right can take ownership of objects and make changes." >> file.txt
TYPE gpresult.txt | findstr /i "User Rights Assignment" >> Win2012.txt
echo "Finding: If any accounts or groups other than the following are granted the 'Take ownership of files or other objects' user right, this is a finding:
Administrators" >> Win2012.txt
echo "|---------------------------------------------------------------------|" >> file.txt




timeout /t 10

@echo on
