PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79119" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types." 
PRINT "Discussion:  Database management includes the ability to control the number of users and user sessions utilizing SQL Server. Unlimited concurrent connections to SQL Server could allow a successful Denial of Service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks. 
This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts. 
The capability to limit the number of concurrent sessions per user must be configured in or added to SQL Server (for example, by use of a logon trigger), when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to SQL Server by other means. 
The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, 2 might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session. 
(Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.)
"

PRINT CHAR(13) + CHAR(10)

SELECT name FROM master.sys.server_triggers;
Go


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79121" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals." 
PRINT "Discussion:  Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization. 
A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed.  
Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers. Account management functions can also include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage. 
SQL Server must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy.  
Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements." 

PRINT CHAR(13) + CHAR(10)

SELECT name 
FROM sys.sql_logins 
WHERE type_desc = 'SQL_LOGIN' AND is_disabled = 0;

Go


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79123" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must be configured to utilize the most-secure authentication method available." 
PRINT "Discussion:  Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization. 
A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed.  
Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers. Account management functions can also include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage. 
SQL Server must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy.  
Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements. 
SQL Server supports several authentication methods to allow operation in various environments, Kerberos, NTLM, and SQL Server. An instance of SQL Server must be configured to utilize the most-secure method available. Service accounts utilized by SQL Server should be unique to a given instance." 

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79125" 
PRINT "Group Title:  " 
PRINT "Severity: high" 
PRINT "Rule Title: SQL Server must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies." 
PRINT "Discussion:  Authentication with a DoD-approved PKI certificate does not necessarily imply authorization to access SQL Server.  To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems, including databases, must be properly configured to implement access control policies.  
Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.  
Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.  
This requirement is applicable to access control enforcement applications, a category that includes database management systems.  If SQL Server does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79127" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must protect against a user falsely repudiating by ensuring all accounts are individual, unique, and not shared." 
PRINT "Discussion:  Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message.  
Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database. 
In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring SQL Server's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to SQL Server, even where the application connects to SQL Server with a standard, shared account." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79129" 
PRINT "Group Title:  " 
PRINT "Severity: high" 
PRINT "Rule Title: SQL Server must protect against a user falsely repudiating by ensuring the NT AUTHORITY SYSTEM account is not used for administration." 
PRINT "Discussion:  Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message.  
Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database. 
In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account. 
Any user with enough access to the server can execute a task that will be run as NT AUTHORITY\SYSTEM either using task scheduler or other tools. At this point, NT AUTHORITY\SYSTEM essentially becomes a shared account because the operating system and SQL Server are unable to determine who created the process. 
Prior to SQL Server 2012, NT AUTHORITY\SYSTEM was a member of the sysadmin role by default. This allowed jobs/tasks to be executed in SQL Server without the approval or knowledge of the DBA because it looked like operating system activity." 

PRINT CHAR(13) + CHAR(10)

SELECT
SERVERPROPERTY('IsClustered') AS [IsClustered],
SERVERPROPERTY('IsHadrEnabled') AS [IsHadrEnabled];

Go


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79131" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must protect against a user falsely repudiating by ensuring only clearly unique Active Directory user accounts can connect to the instance." 
PRINT "Discussion:  Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message.  
Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database. 
In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account. 
If the computer account of a remote computer is granted access to SQL Server, any service or scheduled task running as NT AUTHORITY\SYSTEM or NT AUTHORITY\NETWORK SERVICE can log into the instance and perform actions. These actions cannot be traced back to a specific user or process." 

PRINT CHAR(13) + CHAR(10)

SELECT name
FROM sys.server_principals
WHERE type in ('U','G')
AND name LIKE '%$';


Go
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79133" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must be configured to generate audit records for DoD-defined auditable events within all DBMS/database components." 
PRINT "Discussion:  Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  
Audit records can be generated from various components within SQL Server (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records. 
DoD has defined the list of events for which SQL Server will provide an audit record generation capability as the following:  
(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels); 
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and 
(iii) All account creation, modification, disabling, and termination actions. 
Organizations may define additional events requiring continuous or ad hoc auditing." 

PRINT CHAR(13) + CHAR(10)

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status;
Go 


SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1;
Go

PRINT "Finding:  All currently defined audits for the SQL server instance will be listed. If no audits are returned, this is a finding."
PRINT "Finding:  Compare the documentation to the list of generated audit events. If there are any missing events, this is a finding."
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79135" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited." 
PRINT "Discussion:  Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events. 
Suppression of auditing could permit an adversary to evade detection. 
Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one." 
PRINT CHAR(13) + CHAR(10)

SELECT-- DISTINCT 
CASE 
WHEN SP.class_desc IS NOT NULL THEN 
CASE 
WHEN SP.class_desc = 'SERVER' AND S.is_linked = 0 THEN 'SERVER' 
WHEN SP.class_desc = 'SERVER' AND S.is_linked = 1 THEN 'SERVER (linked)' 
ELSE SP.class_desc 
END 
WHEN E.name IS NOT NULL THEN 'ENDPOINT' 
WHEN S.name IS NOT NULL AND S.is_linked = 0 THEN 'SERVER' 
WHEN S.name IS NOT NULL AND S.is_linked = 1 THEN 'SERVER (linked)' 
WHEN P.name IS NOT NULL THEN 'SERVER_PRINCIPAL' 
ELSE '???' 
END AS [Securable Class], 
CASE 
WHEN E.name IS NOT NULL THEN E.name 
WHEN S.name IS NOT NULL THEN S.name 
WHEN P.name IS NOT NULL THEN P.name 
ELSE '???' 
END AS [Securable], 
P1.name AS [Grantee], 
P1.type_desc AS [Grantee Type], 
sp.permission_name AS [Permission], 
sp.state_desc AS [State], 
P2.name AS [Grantor], 
P2.type_desc AS [Grantor Type], 
R.name AS [Role Name] 
FROM 
sys.server_permissions SP 
INNER JOIN sys.server_principals P1 
ON P1.principal_id = SP.grantee_principal_id 
INNER JOIN sys.server_principals P2 
ON P2.principal_id = SP.grantor_principal_id 

FULL OUTER JOIN sys.servers S 
ON SP.class_desc = 'SERVER' 
AND S.server_id = SP.major_id 

FULL OUTER JOIN sys.endpoints E 
ON SP.class_desc = 'ENDPOINT' 
AND E.endpoint_id = SP.major_id 

FULL OUTER JOIN sys.server_principals P 
ON SP.class_desc = 'SERVER_PRINCIPAL' 
AND P.principal_id = SP.major_id 

FULL OUTER JOIN sys.server_role_members SRM 
ON P.principal_id = SRM.member_principal_id 

LEFT OUTER JOIN sys.server_principals R 
ON SRM.role_principal_id = R.principal_id 
WHERE sp.permission_name IN ('ALTER ANY SERVER AUDIT','CONTROL SERVER','ALTER ANY DATABASE','CREATE ANY DATABASE') 
OR R.name IN ('sysadmin','dbcreator')
Go

PRINT CHAR(13) + CHAR(10)

PRINT "Finding:  If any of the logins, roles, or role memberships returned have permissions that are not documented, or the documented audit maintainers do not have permissions, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79137" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when privileges/permissions are retrieved." 
PRINT "Discussion:  Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions. 
This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that SQL Server continually performs to determine if any and every action on the database is permitted."
PRINT CHAR(13) + CHAR(10)

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status ;
Go



PRINT "Finding:  Determine if an audit is configured and started by executing the following query. If no records are returned, this is a finding. "


SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
Go

PRINT "Finding: If the SCHEMA_OBJECT_ACCESS_GROUP is not returned in an active audit, this is a finding."



PRINT "|---------------------------------------------------------------------|" 

PRINT "V-79139" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful attempts to retrieve privileges/permissions occur." 
PRINT "Discussion:  Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions. 
This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that SQL Server continually performs to determine if any and every action on the database is permitted. 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones." 

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
Go


PRINT "Finding: If the documentation does not exist, this is a finding. "
PRINT "Finding: Determine if an audit is configured and started by executing the following query. If no records are returned, this is a finding."

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
Go

PRINT "Finding: If the SCHEMA_OBJECT_ACCESS_GROUP is not returned in an active audit, this is a finding."
PRINT "|---------------------------------------------------------------------|" 





PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79141" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must initiate session auditing upon startup." 
PRINT "Discussion:  Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time SQL Server is running." 

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
WHERE status_desc = 'STARTED' 
Go

PRINT "Finding: All currently defined audits for the SQL server instance will be listed. If no audits are returned, this is a finding."


PRINT "|---------------------------------------------------------------------|" 





PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79145" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject." 
PRINT "Discussion:  Information system auditing capability is critical for accurate forensic analysis. Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. To support analysis, some types of events will need information to be logged that exceeds the basic requirements of event type, time stamps, location, source, outcome, and user identity. If additional information is not available, it could negatively impact forensic investigations into user actions or other malicious events. 
The organization must determine what additional information is required for complete analysis of the audited events. The additional information required is dependent on the type of information (e.g., sensitivity of the data and the environment within which it resides). At a minimum, the organization must employ either full-text recording of privileged commands or the individual identities of users of shared accounts, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.  
Examples of detailed information the organization may require in audit records are full-text recording of privileged commands or the individual identities of shared account users." 

PRINT "Finding: ?"

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79147" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must by default shut down upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure." 
PRINT "Discussion:  It is critical that when SQL Server is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.  
When the need for system availability does not outweigh the need for a complete audit trail, SQL Server should shut down immediately, rolling back all in-flight transactions. 
Systems where audit trail completeness is paramount will most likely be at a lower MAC level than MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid a shutdown in all but the most extreme situations." 

SELECT * FROM sys.server_audits; 
Go

PRINT "Finding:  If the [on_failure_desc] is 'SHUTDOWN SERVER INSTANCE' on this/these row(s), this is not a finding. Otherwise, this is a finding."

PRINT "|---------------------------------------------------------------------|" 





PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79149" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must be configurable to overwrite audit log records, oldest first (First-In-First-Out - FIFO), in the event of unavailability of space for more audit log records." 
PRINT "Discussion:  It is critical that when SQL Server is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include; software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.  
When availability is an overriding concern, approved actions in response to an audit failure are as follows:  
(i) If the failure was caused by the lack of audit record storage capacity, SQL Server must continue generating audit records, if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.  
(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, SQL Server must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.  
Systems where availability is paramount will most likely be MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid audit data loss in all but the most extreme situations." 

SELECT a.name 'audit_name',
a.type_desc 'storage_type',
f.max_rollover_files
FROM sys.server_audits a
LEFT JOIN sys.server_file_audits f ON a.audit_id = f.audit_id
WHERE a.is_state_enabled = 1
Go


PRINT "Finding: If no records are returned, this is a finding."
PRINT "Finding: If the 'storage_type' is 'FILE' and 'max_rollover_files' is greater than zero, this is not a finding. Otherwise, this is a finding." 

PRINT "|---------------------------------------------------------------------|" 





PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79151" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: The audit information produced by SQL Server must be protected from unauthorized read access." 
PRINT "Discussion:  If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.  
To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.  
This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location. 
Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.  SQL Server is an application that is able to view and manipulate audit file data. 
Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity." 

SELECT log_file_path AS "Audit Path" 
FROM sys.server_file_audits 
Go

PRINT "Finding: If any less restrictive permissions are present (and not specifically justified and approved), this is a finding."
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79153" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: The audit information produced by SQL Server must be protected from unauthorized modification." 
PRINT "Discussion:  If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.
To ensure the veracity of audit data the information system and/or the application must protect audit information from unauthorized modification. 
This requirement can be achieved through multiple methods that will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions and limiting log data locations. 
Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.  SQL Server is an application that does provide access to audit file data. 
Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 
Modification of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database." 

SELECT log_file_path AS "Audit Path" 
FROM sys.server_file_audits 
Go



PRINT "Finding: If any less restrictive permissions are present (and not specifically justified and approved), this is a finding."
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79155" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: The audit information produced by SQL Server must be protected from unauthorized deletion." 
PRINT "Discussion:  If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 
To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods which will depend upon system architecture and design. 
Some commonly employed methods include; ensuring log files enjoy the proper file system permissions utilizing file system protections; restricting access; and backing up log data to ensure log data is retained. 
Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.  SQL Server is an application that does provide access to audit file data. 
Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 
Deletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database." 

SELECT log_file_path AS "Audit Path" 
FROM sys.server_file_audits 
Go

PRINT "Finding: If any less restrictive permissions are present (and not specifically justified and approved), this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79157" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must protect its audit features from unauthorized access." 
PRINT "Discussion:  Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. 
Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access. 
Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.  SQL Server is an application that does provide access to audit data. 
Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records. 
If an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity." 

SELECT login.name, perm.permission_name, perm.state_desc 
FROM sys.server_permissions perm 
JOIN sys.server_principals login 
ON perm.grantee_principal_id = login.principal_id 
WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT','ALTER TRACE') 
and login.name not like '##MS_%'; 
Go


PRINT "Finding: If unauthorized accounts have these privileges, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79159" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must protect its audit configuration from unauthorized modification." 
PRINT "Discussion:  Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data. 
Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.  SQL Server is an application that does provide access to audit data. 
Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators." 

SELECT login.name, perm.permission_name, perm.state_desc 
FROM sys.server_permissions perm 
JOIN sys.server_principals login 
ON perm.grantee_principal_id = login.principal_id 
WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT') 
and login.name not like '##MS_%'; 
Go


PRINT "Finding: If unauthorized accounts have these privileges, this is a finding."



PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79161" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must protect its audit features from unauthorized removal." 
PRINT "Discussion:  Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data. 
Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.  SQL Server is an application that does provide access to audit data. 
Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators." 

SELECT login.name, perm.permission_name, perm.state_desc 
FROM sys.server_permissions perm 
JOIN sys.server_principals login 
ON perm.grantee_principal_id = login.principal_id 
WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT') 
and login.name not like '##MS_%'; 
Go

PRINT "Finding: If unauthorized accounts have these privileges, this is a finding."
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79163" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must limit privileges to change software modules and links to software external to SQL Server." 
PRINT "Discussion:  If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications. 
Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations." 


PRINT "Finding: If any unauthorized users are granted modify rights or the owner is incorrect, this is a finding. "
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79165" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must limit privileges to change software modules, to include stored procedures, functions and triggers, and links to software external to SQL Server." 
PRINT "Discussion:  If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications. 
Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations."

PRINT "Finding: "
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79167" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server software installation account must be restricted to authorized users." 
PRINT "Discussion:  When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can have significant effects on the overall security of the system. 
If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. Accordingly, only qualified and authorized individuals must be allowed access to information system components for purposes of initiating changes, including upgrades and modifications. 
DBA and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a great impact on SQL Server security and operation. It is especially important to grant privileged access to only those persons who are qualified and authorized to use them." 
powershell 

PRINT "Finding: "
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79169" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Database software, including DBMS configuration files, must be stored in dedicated directories, separate from the host OS and other applications." 
PRINT "Discussion:  When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 
 
Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications." 
PRINT "Finding: "
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79171" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Default demonstration and sample databases, database objects, and applications must be removed." 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
 
It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to requirements or providing a wide array of functionality, not required for every mission, that cannot be disabled. 
 
DBMSs must adhere to the principles of least functionality by providing only essential capabilities. 
 
Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to SQL Server and host system." 

use pubs 
GO

use Northwind
GO

use AdventureWorks 
GO

use WorldwideImporters 
GO


PRINT "Finding: If any of these databases exist, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79173" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Unused database components, DBMS software, and database objects must be removed." 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
 
It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.  
 
DBMSs must adhere to the principles of least functionality by providing only essential capabilities." 
PRINT "Finding: "
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79175" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Unused database components that are integrated in SQL Server and cannot be uninstalled must be disabled." 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).  
 
It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.  
 
DBMSs must adhere to the principles of least functionality by providing only essential capabilities. 
 
Unused, unnecessary DBMS components increase the attack vector for SQL Server by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS, and the nature of the component and may include DBMS configuration settings, OS service settings, OS file access security, and DBMS user/role permissions." 
PRINT "Finding: "
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79177" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Access to xp_cmdshell must be disabled, unless specifically required and approved." 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).  
 
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives.  
 
Applications must adhere to the principles of least functionality by providing only essential capabilities. 
 
SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system. 
 
The xp_cmdshell extended stored procedure allows execution of host executables outside the controls of database access permissions. This access may be exploited by malicious users who have compromised the integrity of the SQL Server database process to control the host operating system to perpetrate additional malicious activity." 
PRINT "Finding: If the value of 'config_value' is '0', this is not a finding. "

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'xp_cmdshell'; 
GO


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79179" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Access to CLR code must be disabled or restricted, unless specifically required and approved." 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).  
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives.  
Applications must adhere to the principles of least functionality by providing only essential capabilities. 
SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system. 
The common language runtime (CLR) component of the .NET Framework for Microsoft Windows in SQL Server allows you to write stored procedures, triggers, user-defined types, user-defined functions, user-defined aggregates, and streaming table-valued functions, using any .NET Framework language, including Microsoft Visual Basic .NET and Microsoft Visual C#.  CLR packing assemblies can access resources protected by .NET Code Access Security when it runs managed code.  Specifying UNSAFE enables the code in the assembly complete freedom to perform operations in the SQL Server process space that can potentially compromise the robustness of SQL Server. UNSAFE assemblies can also potentially subvert the security system of either SQL Server or the common language runtime." 

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'clr enabled'; 


PRINT "Finding: If the value of 'config_value' is '1', review the system documentation to determine whether the use of CLR code is approved. If it is not approved, this is a finding. "

USE [master]
SELECT * 
FROM sys.assemblies 
WHERE permission_set_desc != 'SAFE' 
AND is_user_defined = 1;

PRINT "Finding: If any records are returned, review the system documentation to determine if the use of UNSAFE assemblies is approved. If it is not approved, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79181" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Access to Non-Standard extended stored procedures must be disabled or restricted, unless specifically required and approved." 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).  
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives.  
Applications must adhere to the principles of least functionality by providing only essential capabilities. 
SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system. 
Extended stored procedures are DLLs that an instance of SQL Server can dynamically load and run. Extended stored procedures run directly in the address space of an instance of SQL Server and are programmed by using the SQL Server Extended Stored Procedure API.  Non-Standard extended stored procedures can compromise the integrity of the SQL Server process.  This feature will be removed in a future version of Microsoft SQL Server. Do not use this feature in new development work, and modify applications that currently use this feature as soon as possible." 

USE [master]
GO
DECLARE @xplist AS TABLE
(
xp_name sysname,
source_dll nvarchar(255)
)
INSERT INTO @xplist
EXEC sp_helpextendedproc

SELECT X.xp_name, X.source_dll, O.is_ms_shipped FROM @xplist X JOIN sys.all_objects O ON X.xp_name = O.name WHERE O.is_ms_shipped = 0 ORDER BY X.xp_name
go


PRINT "Finding: If any records are returned, review the system documentation to determine whether the use of Non-Standard extended stored procedures are required and approved. If it is not approved, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79183" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Access to linked servers must be disabled or restricted, unless specifically required and approved." 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. Applications must adhere to the principles of least functionality by providing only essential capabilities. SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system. A linked server allows for access to distributed, heterogeneous queries against OLE DB data sources. After a linked server is created, distributed queries can be run against this server, and queries can join tables from more than one data source. If the linked server is defined as an instance of SQL Server, remote stored procedures can be executed.  This access may be exploited by malicious users who have compromised the integrity of the SQL Server." 
SELECT s.name, p.principal_id, l.remote_name 
FROM sys.servers s 
JOIN sys.linked_logins l ON s.server_id = l.server_id 
LEFT JOIN sys.server_principals p ON l.local_principal_id = p.principal_id 
WHERE s.is_linked = 1 
go

PRINT "Finding: Review the linked login mapping and check the remote name as it can impersonate sysadmin. If a login in the list is impersonating sysadmin and system documentation does not require this, it is a finding."


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79185" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must be configured to prohibit or restrict the use of organization-defined protocols as defined in the PPSM CAL and vulnerability assessments." 
PRINT "Discussion:  In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary protocols on information systems. 
Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.  
To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of protocols to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues. 
SQL Server using protocols deemed unsafe is open to attack through those protocols. This can allow unauthorized access to the database and through the database to other components of the information system." 

PRINT "Finding: If Named Pipes is enabled and not specifically required and authorized, this is a finding. If any listed protocol is enabled but not authorized, this is a finding. "

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79187" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must be configured to prohibit or restrict the use of organization-defined ports, as defined in the PPSM CAL and vulnerability assessments." 
PRINT "Discussion:  In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports on information systems. 
Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.  
To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues. 
SQL Server using ports deemed unsafe is open to attack through those ports. This can allow unauthorized access to the database and through the database to other components of the information system." 
PRINT "Finding: "
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79189" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users)." 
PRINT "Discussion:  To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.  
Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following: 
(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and  
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity." 
PRINT "Finding: "
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79191" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: If DBMS authentication, using passwords, is employed, SQL Server must enforce the DoD standards for password complexity and lifetime." 
PRINT "Discussion:  OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001).  Native DBMS authentication may be used only when circumstances make it unavoidable; and must be documented and AO-approved. 
The DoD standard for authentication is DoD-approved PKI certificates.  Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval. 
In such cases, the DoD standards for password complexity and lifetime must be implemented.  DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so.  For other DBMSs, the rules must be enforced using available configuration parameters or custom code." 
SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly') WHEN 1 THEN 'Windows Authentication' WHEN 0 THEN 'SQL Server Authentication' END as [Authentication Mode]
go
SELECT [name], is_expiration_checked, is_policy_checked
FROM sys.sql_logins
go

PRINT "Finding: If any account doesn't have both 'is_expiration_checked' and 'is_policy_checked' equal to “1”, this is a finding. Review the Operating System settings relating to password complexity. Determine whether the following rules are enforced. If any are not, this is a finding. "


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79193" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Contained databases must use Windows principals." 
PRINT "Discussion:  OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001).  Native DBMS authentication may be used only when circumstances make it unavoidable; and must be documented and AO-approved. 
The DoD standard for authentication is DoD-approved PKI certificates.  Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval. 
In such cases, the DoD standards for password complexity and lifetime must be implemented.  DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so.  For other DBMSs, the rules must be enforced using available configuration parameters or custom code." 
SELECT * FROM sys.databases WHERE containment = 1 
go

EXEC sp_MSforeachdb 'USE [?]; SELECT DB_NAME() AS DatabaseName, * FROM sys.database_principals WHERE authentication_type = 2' 
go

PRINT "Finding: If any records are returned, this is a finding."
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79195" 
PRINT "Group Title:  " 
PRINT "Severity: high" 
PRINT "Rule Title: If passwords are used for authentication, SQL Server must transmit only encrypted representations of passwords." 
PRINT "Discussion:  The DoD standard for authentication is DoD-approved PKI certificates. 
 
Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval. 
 
In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission. 
 
SQL Server passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79197" 
PRINT "Group Title:  " 
PRINT "Severity: low" 
PRINT "Rule Title: SQL Server must enforce authorized access to all PKI private keys stored/utilized by SQL Server." 
PRINT "Discussion:  The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key. 
 
If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder.  In cases where SQL Server-stored private keys are used to authenticate SQL Server to the system’s clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man in the middle attacks against SQL Server system and its clients. 
 
Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 validated cryptographic modules. 
 
All access to the private key(s) of SQL Server must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of SQL Server's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79199" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations." 
PRINT "Discussion:  Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data.  Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of SQL Server. 
Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.   
The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A. 
NSA Type- (where =1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79201" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users)." 
PRINT "Discussion:  Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). 
Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server. 
Accordingly, a risk assessment is used in determining the authentication needs of the organization. 
Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the Nation." 

SELECT name, type_desc FROM sys.server_principals WHERE type in ('S','U') 
go
PRINT "Finding: If non-organizational users are not uniquely identified and authenticated, this is a finding."


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79203" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values." 
PRINT "Discussion:  One class of man-in-the-middle, or session hijacking, attack involves the adversary guessing at valid session identifiers based on patterns in identifiers already known. 
 
The preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2 approved random number generator. 
 
However, it is recognized that available DBMS products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79205" 
PRINT "Group Title:  " 
PRINT "Severity: high" 
PRINT "Rule Title: SQL Server must protect the confidentiality and integrity of all information at rest." 
PRINT "Discussion:  This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use.  
User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate.  
If the confidentiality and integrity of SQL Server data is not protected, the data will be open to compromise and unauthorized modification." 

SELECT 
d.name AS [Database Name], 
CASE e.encryption_state 
WHEN 0 THEN 'No database encryption key present, no encryption' 
WHEN 1 THEN 'Unencrypted' 
WHEN 2 THEN 'Encryption in progress' 
WHEN 3 THEN 'Encrypted' 
WHEN 4 THEN 'Key change in progress' 
WHEN 5 THEN 'Decryption in progress' 
WHEN 6 THEN 'Protection change in progress' 
END AS [Encryption State] 
FROM sys.dm_database_encryption_keys e 
RIGHT JOIN sys.databases d ON DB_NAME(e.database_id) = d.name 
WHERE d.name NOT IN ('master','model','msdb') 
ORDER BY [Database Name] ; 

go



PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79207" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: The Service Master Key must be backed up, stored offline and off-site." 
PRINT "Discussion:  Backup and recovery of the Service Master Key may be critical to the complete recovery of the database. Creating this backup should be one of the first administrative actions performed on the server.  Not having this key can lead to loss of data during recovery." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79209" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: The Master Key must be backed up, stored offline and off-site." 
PRINT "Discussion:  Backup and recovery of the Master Key may be critical to the complete recovery of the database.  Not having this key can lead to loss of data during recovery." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79211" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must prevent unauthorized and unintended information transfer via shared system resources." 
PRINT "Discussion:  The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse." 

SELECT value_in_use
FROM sys.configurations
WHERE name = 'common criteria compliance enabled'
go


PRINT "Finding: If 'value_in_use' is set to '1' this is not a finding.If 'value_in_use' is set to "0" this is a finding.  NOTE: Enabling this feature may impact performance on highly active SQL Server instances. If an exception justifying setting SQL Server Residual Information Protection (RIP) to disabled (value_in_use set to "0") has been documented and approved, then this may be downgraded to a CAT III finding."
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79213" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must prevent unauthorized and unintended information transfer via shared system resources." 
PRINT "Discussion:  The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79215" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Access to database files must be limited to relevant processes and to authorized, administrative users." 
PRINT "Discussion:  SQL Server must prevent unauthorized and unintended information transfer via shared system resources. Permitting only SQL Server processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79217" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must reveal detailed error messages only to the ISSO, ISSM, SA, and DBA." 
PRINT "Discussion:  If SQL Server provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements. 
Some default DBMS error messages can contain information that could aid an attacker in, among others things, identifying the database type, host address, or state of the database. Custom errors may contain sensitive customer information. 
It is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, "An error has occurred. Unable to save your changes. If this problem persists, please contact your help desk." would be relevant. A message such as "Warning: your transaction generated a large number of page splits" would likely not be relevant. "ABGQ is not a valid widget code." would be appropriate; but "The INSERT statement conflicted with the FOREIGN KEY constraint "WidgetTransactionFK". The conflict occurred in database "DB7", table "dbo.WidgetMaster", column 'WidgetCode'" would not, as it reveals too much about the database structure." 

USE master 
GO
SELECT Name 
FROM syslogins 
WHERE (sysadmin = 1 or securityadmin = 1) 
and hasaccess = 1; 
go

PRINT "Finding: If any non-authorized users have access to the SQL Server Error Log located at Program Files\Microsoft SQL Server\MSSQL.n\MSSQL\LOG, this is a finding. "

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79219" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must prevent non-privileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures." 
PRINT "Discussion:  Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.  
System documentation should include a definition of the functionality considered privileged. 
Depending on circumstances, privileged functions can include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users. 
A privileged function in SQL Server/database context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:  
CREATE 
ALTER 
DROP 
GRANT 
REVOKE 
DENY 
There may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. Possible examples include: 
TRUNCATE TABLE; 
DELETE, or 
DELETE affecting more than n rows, for some n, or 
DELETE without a WHERE clause; 
UPDATE or 
UPDATE affecting more than n rows, for some n, or 
UPDATE without a WHERE clause; 
Any SELECT, INSERT, UPDATE, or DELETE to an application-defined security table executed by other than a security principal. 
Depending on the capabilities of SQL Server and the design of the database and associated applications, the prevention of unauthorized use of privileged functions may be achieved by means of DBMS security features, database triggers, other mechanisms, or a combination of these." 
SELECT 
R.name AS [Role], 
M.name AS [Member] 
FROM 
sys.server_role_members X 
INNER JOIN sys.server_principals R ON R.principal_id = X.role_principal_id 
INNER JOIN sys.server_principals M ON M.principal_id = X.member_principal_id 
go



SELECT DISTINCT 
CASE 
WHEN SP.class_desc IS NOT NULL THEN 
CASE 
WHEN SP.class_desc = 'SERVER' AND S.is_linked = 0 THEN 'SERVER' 
WHEN SP.class_desc = 'SERVER' AND S.is_linked = 1 THEN 'SERVER (linked)' 
ELSE SP.class_desc 
END 
WHEN E.name IS NOT NULL THEN 'ENDPOINT' 
WHEN S.name IS NOT NULL AND S.is_linked = 0 THEN 'SERVER' 
WHEN S.name IS NOT NULL AND S.is_linked = 1 THEN 'SERVER (linked)' 
WHEN P.name IS NOT NULL THEN 'SERVER_PRINCIPAL' 
ELSE '???' 
END AS [Securable Class], 
CASE 
WHEN E.name IS NOT NULL THEN E.name 
WHEN S.name IS NOT NULL THEN S.name 
WHEN P.name IS NOT NULL THEN P.name 
ELSE '???' 
END AS [Securable], 
P1.name AS [Grantee], 
P1.type_desc AS [Grantee Type], 
sp.permission_name AS [Permission], 
sp.state_desc AS [State], 
P2.name AS [Grantor], 
P2.type_desc AS [Grantor Type] 
FROM 
sys.server_permissions SP 
INNER JOIN sys.server_principals P1 
ON P1.principal_id = SP.grantee_principal_id 
INNER JOIN sys.server_principals P2 
ON P2.principal_id = SP.grantor_principal_id 

FULL OUTER JOIN sys.servers S 
ON SP.class_desc = 'SERVER' 
AND S.server_id = SP.major_id 

FULL OUTER JOIN sys.endpoints E 
ON SP.class_desc = 'ENDPOINT' 
AND E.endpoint_id = SP.major_id 

FULL OUTER JOIN sys.server_principals P 
ON SP.class_desc = 'SERVER_PRINCIPAL' 
AND P.principal_id = SP.major_id 
go


PRINT "Finding: If the current configuration does not match the documented baseline, this is a finding. "
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79221" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Use of credentials and proxies must be restricted to necessary cases only." 
PRINT "Discussion:  In certain situations, to provide required functionality, a DBMS needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations. 
Privilege elevation must be utilized only where necessary and protected from misuse." 

SELECT C.name AS credential_name, C.credential_identity 
FROM sys.credentials C 
GO 

SELECT P.name AS proxy_name, C.name AS credential_name, C.credential_identity 
FROM sys.credentials C 
JOIN msdb.dbo.sysproxies P ON C.credential_id = P.credential_id 
WHERE P.enabled = 1 
GO 

PRINT "Finding: If any Credentials or SQL Agent Proxy accounts are returned that are not documented and authorized, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79223" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must utilize centralized management of the content captured in audit records generated by all components of SQL Server." 
PRINT "Discussion:  Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack. 
 
The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.  
 
SQL Server may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79225" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must provide centralized configuration of the content to be captured in audit records generated by all components of SQL Server." 
PRINT "Discussion:  If the configuration of SQL Server's auditing is spread across multiple locations in the database management software, or across multiple commands, only loosely related, it is harder to use and takes longer to reconfigure in response to events. 

SQL Server must provide a unified tool for audit configuration." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79227" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements." 
PRINT "Discussion:  In order to ensure sufficient storage capacity for the audit logs, SQL Server must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism. 
 
The task of allocating audit record storage capacity is usually performed during initial installation of SQL Server and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both. 
In determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on SQL Server's ability to reuse the space formerly occupied by off-loaded records." 

SELECT max_file_size, max_rollover_files, log_file_path AS "Audit Path" 
FROM sys.server_file_audits 
go

PRINT "Finding: If the calculated product of the 'max_file_size' times the 'max_rollover_files' exceeds the size of the storage location or if 'max_file_size' or 'max_rollover_files' are set to '0' (UNLIMITED), this is a finding."
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79229" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75% of maximum audit record storage capacity." 
PRINT "Discussion:  Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to SQL Server on its own server will not be an issue. However, space will still be required on the server for SQL Server audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result. 
If support personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion.  
The appropriate support staff include, at a minimum, the ISSO and the DBA/SA. 
Monitoring of free space can be accomplished using Microsoft System Center or a third-party monitoring tool." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79231" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must provide an immediate real-time alert to appropriate support staff of all audit log failures." 
PRINT "Discussion:  It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.  

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA. 

A failure of database auditing will result in either the database continuing to function without auditing or in a complete halt to database operations. When audit processing fails, appropriate personnel must be alerted immediately to avoid further downtime or unaudited transactions

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less). Alerts can be generated using tools like the SQL Server Agent Alerts and Database Mail." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79233" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must record time stamps in audit records and application data that can be mapped to Coordinated Universal Time (UTC, formerly GMT)." 
PRINT "Discussion:  If time stamps are not consistently applied and there is no common time reference, it is difficult to perform forensic analysis. 
Time stamps generated by SQL Server must include date and time. Time is commonly expressed in Coordinated Universal Time (UTC), a modern continuation of Greenwich Mean Time (GMT), or local time with an offset from UTC." 

SELECT DEFAULT_DOMAIN()[DomainName] 
go

PRINT "Finding: If this is not NULL, this is not a finding."


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79235" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must enforce access restrictions associated with changes to the configuration of the instance." 
PRINT "Discussion:  Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.  
 
When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.  
 
Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications." 

SELECT p.name AS Principal, 
p.type_desc AS Type, 
sp.permission_name AS Permission, 
sp.state_desc AS State 
FROM sys.server_principals p 
INNER JOIN sys.server_permissions sp ON p.principal_id = sp.grantee_principal_id 
WHERE sp.permission_name = 'CONTROL SERVER' 
OR sp.state = 'W' 
go

SELECT m.name AS Member, 
m.type_desc AS Type, 
r.name AS Role 
FROM sys.server_principals m 
INNER JOIN sys.server_role_members rm ON m.principal_id = rm.member_principal_id 
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id 
WHERE r.name IN ('sysadmin','securityadmin','serveradmin') 
go

PRINT "FINDING: Check the server documentation to verify the logins and roles returned are authorized. If the logins and/or roles are not documented and authorized, this is a finding."


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79237" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Windows must enforce access restrictions associated with changes to the configuration of the SQL Server instance." 
PRINT "Discussion:  Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.  
When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.  
Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications." 

SELECT name AS 'Audit Name',
status_desc AS 'Audit Status',
audit_file_path AS 'Current Audit File'
FROM sys.dm_server_audit_status
go


PRINT "FINDING: If no records are returned, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79239" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must produce audit records of its enforcement of access restrictions associated with changes to the configuration of SQL Server or database(s)." 
PRINT "Discussion:  Without auditing the enforcement of access restrictions against changes to configuration, it would be difficult to identify attempted attacks and an audit trail would not be available for forensic investigation for after-the-fact actions.  
Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact." 

SELECT a.name AS 'AuditName',
s.name AS 'SpecName',
d.audit_action_name AS 'ActionName',
d.audited_result AS 'Result'
FROM sys.server_audit_specifications s
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
WHERE a.is_state_enabled = 1
AND d.audit_action_name IN (
'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
'AUDIT_CHANGE_GROUP',
'BACKUP_RESTORE_GROUP',
'DATABASE_CHANGE_GROUP',
'DATABASE_OBJECT_ACCESS_GROUP',
'DATABASE_OBJECT_CHANGE_GROUP',
'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
'DATABASE_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OPERATION_GROUP',
'DATABASE_OWNERSHIP_CHANGE_GROUP',
'DATABASE_PERMISSION_CHANGE_GROUP',
'DATABASE_PRINCIPAL_CHANGE_GROUP',
'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
'DATABASE_ROLE_MEMBER_CHANGE_GROUP', 
'DBCC_GROUP',
'LOGIN_CHANGE_PASSWORD_GROUP',
'SCHEMA_OBJECT_CHANGE_GROUP',
'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OBJECT_CHANGE_GROUP',
'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OPERATION_GROUP',
'SERVER_PERMISSION_CHANGE_GROUP',
'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
'SERVER_ROLE_MEMBER_CHANGE_GROUP',
'SERVER_STATE_CHANGE_GROUP',
'TRACE_CHANGE_GROUP'
)
Order by d.audit_action_name
GO



PRINT "Finding: If the identified groups are not returned, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79241" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance." 
PRINT "Discussion:  Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79243" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must maintain a separate execution domain for each executing process." 
PRINT "Discussion:  Database management systems can maintain separate execution domains for each executing process by assigning each process a separate address space.  
Each process has a distinct address space so that communication between processes is controlled through the security functions, and one process cannot modify the executing code of another process.  
Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces." 

SELECT name, value, value_in_use 
FROM sys.configurations 
WHERE name = 'clr enabled' 
Go


PRINT "FindinIf 'value_in_use' is a '1' and CLR is not required, this is a finding." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79245" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server services must be configured to run under unique dedicated user accounts." 
PRINT "Discussion:  Database management systems can maintain separate execution domains for each executing process by assigning each process a separate address space. Each process has a distinct address space so that communication between processes is controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79247" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: When updates are applied to SQL Server software, any software components that have been replaced or made unnecessary must be removed." 
PRINT "Discussion:  Previous versions of DBMS components that are not removed from the information system after updates have been installed may be exploited by adversaries.  
 
Some DBMSs' installation tools may remove older versions of software automatically from the information system. In other cases, manual review and removal will be required. In planning installations and upgrades, organizations must include steps (automated, manual, or both) to identify and remove the outdated modules. 
 
A transition period may be necessary when both the old and the new software are required. This should be taken into account in the planning." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79249" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Security-relevant software updates to SQL Server must be installed within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs)." 
PRINT "Discussion:  Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 
 
Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 
 
This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process. 
 
SQL Server will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs)." 
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79251" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must be able to generate audit records when security objects are accessed." 
PRINT "Discussion:  Changes to the security configuration must be tracked. 
 
This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality. 
 
In an SQL environment, types of access include, but are not necessarily limited to: 
SELECT 
INSERT 
UPDATE 
DELETE 
EXECUTE" 


SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status
GO

PRINT "If no records are returned, this is a finding."


SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
GO

PRINT "If the 'SCHEMA_OBJECT_ACCESS_GROUP' is not returned in an active audit, this is a finding." 


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79253" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful attempts to access security objects occur." 
PRINT "Discussion:  Changes to the security configuration must be tracked. 
This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality. 
In an SQL environment, types of access include, but are not necessarily limited to: 
SELECT 
INSERT 
UPDATE 
DELETE 
EXECUTE 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones." 

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_statu 
GO
PRINT "FINDING: If no records are returned, this is a finding."

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
go
print "FINDING: If the SCHEMA_OBJECT_ACCESS_GROUP is not returned in an active audit, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79255" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when categorized information (e.g., classification levels/security levels) is accessed." 
PRINT "Discussion:  Changes in categorized information must be tracked.  Without an audit trail, unauthorized access to protected data could go undetected. 
For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems." 
SELECT name AS 'Audit Name',
status_desc AS 'Audit Status',
audit_file_path AS 'Current Audit File'
FROM sys.dm_server_audit_status
Go
PRINT "FINDING: If no records are returned, this is a finding. "

SELECT a.name AS 'AuditName',
s.name AS 'SpecName',
d.audit_action_name AS 'ActionName',
d.audited_result AS 'Result'
FROM sys.server_audit_specifications s
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'

PRINT "FINDING: If the 'SCHEMA_OBJECT_ACCESS_GROUP' is not returned in an active audit, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79257" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur." 
PRINT "Discussion:  Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected. 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones. 
For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems." 
PRINT "FINDING: If no records are returned, this is a finding."
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
Go
PRINT "FINDING: If the 'SCHEMA_OBJECT_ACCESS_GROUP' is not returned in an active audit, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79259" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when privileges/permissions are added." 
PRINT "Discussion:  Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users. 
In an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the DENY command." 

PRINT "FINDING: Determine if an audit is configured and started by executing the following query. If no records are returned, this is a finding."

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status
Go

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1
AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
,'DATABASE_OWNERSHIP_CHANGE_GROUP'
,'DATABASE_PERMISSION_CHANGE_GROUP'
,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
,'SERVER_PERMISSION_CHANGE_GROUP'
,'SERVER_ROLE_MEMBER_CHANGE_GROUP')
Go

PRINT "FINDING: If the any of the following audit actions are not returned in an active audit, this is a finding.
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP "


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79261" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful attempts to add privileges/permissions occur." 
PRINT "Discussion:  Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.  
In an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the DENY command.  
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones." 

PRINT "FINDING: Determine if an audit is configured and started by executing the following query. If no records are returned, this is a finding."
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status
Go

PRINT "FINDING: If the any of the following audit actions are not returned in an active audit, this is a finding.
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP "

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79263" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when privileges/permissions are modified." 
PRINT "Discussion:  Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users. 
In an SQL environment, modifying permissions is typically done via the GRANT, REVOKE, and DENY commands." 
PRINT "FINDING: Determine if an audit is configured and started by executing the following query. If no records are returned, this is a finding."

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status
Go

PRINT "If the any of the following audit actions are not returned in an active audit, this is a finding.
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP "


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79265" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful attempts to modify privileges/permissions occur." 
PRINT "Discussion:  Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.  
In an SQL environment, modifying permissions is typically done via the GRANT, REVOKE, and DENY commands.  
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones." 
PRINT "FINDING: Determine if an audit is configured and started by executing the following query. If no records are returned, this is a finding."
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status
GO

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1
AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
,'DATABASE_OWNERSHIP_CHANGE_GROUP'
,'DATABASE_PERMISSION_CHANGE_GROUP'
,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
,'SERVER_PERMISSION_CHANGE_GROUP'
,'SERVER_ROLE_MEMBER_CHANGE_GROUP')
GO


PRINT "FINDING: If the any of the following audit actions are not returned in an active audit, this is a finding.
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP "
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79267" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when security objects are modified." 
PRINT "Discussion:  Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative." 
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO
PRINT "FINDING: If no records are returned, this is a finding."


SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP' 
Go
SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP' 
Go

PRINT "FINDING: If the 'SCHEMA_OBJECT_CHANGE_GROUP' is not returned in an active audit, this is a finding."


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79269" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful attempts to modify security objects occur." 
PRINT "Discussion:  Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative. 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones." 

PRINT "FINDING: If no records are returned, this is a finding."
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

PRINT "FINDING: If the 'SCHEMA_OBJECT_CHANGE_GROUP' is not returned in an active audit, this is a finding."

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP' 
Go




PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79271" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when categorized information (e.g., classification levels/security levels) is modified." 
PRINT "Discussion:  Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.  
For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems." 
PRINT "FINDING: If the documentation does not exist, this is a finding. "

PRINT "FINDING: If no records are returned, this is a finding. "
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

PRINT "FINDING: If the 'SCHEMA_OBJECT_ACCESS_GROUP' is not returned in an active audit, this is a finding."
SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
GO
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79273" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful attempts to modify categorized information (e.g., classification levels/security levels) occur." 
PRINT "Discussion:  Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected. 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones. 
For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems." 

PRINT "FINDING: If the documentation does not exist, this is a finding."

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

PRINT "FINDING: If the 'SCHEMA_OBJECT_ACCESS_GROUP' is not returned in an active audit, this is a finding."

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
GO


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79275" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when privileges/permissions are deleted." 
PRINT "Discussion:  Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users. 
 
In an SQL environment, deleting permissions is typically done via the REVOKE or DENY command." 
PRINT "FINDING:"
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79277" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful attempts to delete privileges/permissions occur." 
PRINT "Discussion:  Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.  
 
In an SQL environment, deleting permissions is typically done via the REVOKE or DENY command.  
 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones." 
PRINT "FINDING:"
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79279" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when security objects are deleted." 
PRINT "Discussion:  The removal of security objects from the database/DBMS would seriously degrade a system's information assurance posture. If such an event occurs, it must be logged." 

PRINT "FINDING: If no records are returned, this is a finding."
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP' 
GO
PRINT "FINDING: If the 'SCHEMA_OBJECT_CHANGE_GROUP' is not returned in an active audit, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79281" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful attempts to delete security objects occur." 
PRINT "Discussion:  The removal of security objects from the database/DBMS would seriously degrade a system's information assurance posture. If such an action is attempted, it must be logged. 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones." 

PRINT "FINDING: If no records are returned, this is a finding."
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
Go

PRINT "FINDING: If the 'SCHEMA_OBJECT_CHANGE_GROUP' is not returned in an active audit, this is a finding."

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP' 
GO

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79283" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when categorized information (e.g., classification levels/security levels) is deleted." 
PRINT "Discussion:  Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected. 
For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems." 

PRINT "FINDING: If no records are returned, this is a finding."

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

PRINT "FINDING: If the 'SCHEMA_OBJECT_ACCESS_GROUP' is not returned in an active audit, this is a finding."
SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
Go

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79285" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful attempts to delete categorized information (e.g., classification levels/security levels) occur." 
PRINT "Discussion:  Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected. 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones. 
For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems." 
PRINT "FINDING: If no records are returned, this is a finding. "

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

PRINT "FINDING: If the 'SCHEMA_OBJECT_ACCESS_GROUP' is not returned in an active audit, this is a finding. "
SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
GO

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79287" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when successful logons or connections occur." 
PRINT "Discussion:  For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to SQL Server." 
PRINT "FINDING: If the 'SUCCESSFUL_LOGIN_GROUP' is returned in an active audit, this is not a finding. "

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

PRINT "FINDING: If 'Both failed and successful logins' is not selected, this is a finding."
SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP' 
GO
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79289" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful logons or connection attempts occur." 
PRINT "Discussion:  For completeness of forensic analysis, it is necessary to track failed attempts to log on to SQL Server. While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured." 

PRINT "FINDING: If no records are returned, this is a finding."
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

PRINT "FINDING: If the 'FAILED_LOGIN_GROUP' is not returned in an active audit, this is a finding."
SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'FAILED_LOGIN_GROUP' 
GO

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79291" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records for all privileged activities or other system-level access." 
PRINT "Discussion:  Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  
 
System documentation should include a definition of the functionality considered privileged. 
 
A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to: 
CREATE 
ALTER 
DROP 
GRANT 
REVOKE 
DENY 
 
There may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. Possible examples in SQL include: 
 
TRUNCATE TABLE; 
DELETE, or 
DELETE affecting more than n rows, for some n, or 
DELETE without a WHERE clause; 
 
UPDATE or 
UPDATE affecting more than n rows, for some n, or 
UPDATE without a WHERE clause; 
 
any SELECT, INSERT, UPDATE, or DELETE to an application-defined security table executed by other than a security principal. 
 
Depending on the capabilities of SQL Server and the design of the database and associated applications, audit logging may be achieved by means of DBMS auditing features, database triggers, other mechanisms, or a combination of these. 
 
Note that it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity." 

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

PRINT "FINDING: If no records are returned, this is a finding. "
SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'FAILED_LOGIN_GROUP' 
GO


PRINT "FINDING: If the 'FAILED_LOGIN_GROUP' is not returned in an active audit, this is a finding."


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79293" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur." 
PRINT "Discussion:  Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  
System documentation should include a definition of the functionality considered privileged. 
A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to: 
CREATE 
ALTER 
DROP 
GRANT 
REVOKE 
DENY 
Note that it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity. 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones." 

PRINT "FINDING: If no records are returned, this is a finding."

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

PRINT "FINDING: If the identified groups are not returned, this is a finding."

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 
AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
'AUDIT_CHANGE_GROUP',
'BACKUP_RESTORE_GROUP',
'DATABASE_CHANGE_GROUP',
'DATABASE_OBJECT_CHANGE_GROUP',
'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
'DATABASE_OPERATION_GROUP',
'DATABASE_OWNERSHIP_CHANGE_GROUP',
'DATABASE_PERMISSION_CHANGE_GROUP',
'DATABASE_PRINCIPAL_CHANGE_GROUP',
'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
'DBCC_GROUP',
'LOGIN_CHANGE_PASSWORD_GROUP',
'LOGOUT_GROUP',
'SCHEMA_OBJECT_CHANGE_GROUP',
'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OBJECT_CHANGE_GROUP',
'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OPERATION_GROUP',
'SERVER_PERMISSION_CHANGE_GROUP',
'SERVER_PRINCIPAL_CHANGE_GROUP',
'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
'SERVER_ROLE_MEMBER_CHANGE_GROUP',
'SERVER_STATE_CHANGE_GROUP',
'TRACE_CHANGE_GROUP',
'USER_CHANGE_PASSWORD_GROUP'
)
Order by d.audit_action_name
GO



PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79295" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records showing starting and ending time for user access to the database(s)." 
PRINT "Discussion:  For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to SQL Server lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs.  
Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged." 
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

PRINT "If no records are returned, this is a finding."

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 
AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
'AUDIT_CHANGE_GROUP',
'BACKUP_RESTORE_GROUP',
'DATABASE_CHANGE_GROUP',
'DATABASE_OBJECT_CHANGE_GROUP',
'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
'DATABASE_OPERATION_GROUP',
'DATABASE_OWNERSHIP_CHANGE_GROUP',
'DATABASE_PERMISSION_CHANGE_GROUP',
'DATABASE_PRINCIPAL_CHANGE_GROUP',
'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
'DBCC_GROUP',
'LOGIN_CHANGE_PASSWORD_GROUP',
'LOGOUT_GROUP',
'SCHEMA_OBJECT_CHANGE_GROUP',
'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OBJECT_CHANGE_GROUP',
'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OPERATION_GROUP',
'SERVER_PERMISSION_CHANGE_GROUP',
'SERVER_PRINCIPAL_CHANGE_GROUP',
'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
'SERVER_ROLE_MEMBER_CHANGE_GROUP',
'SERVER_STATE_CHANGE_GROUP',
'TRACE_CHANGE_GROUP',
'USER_CHANGE_PASSWORD_GROUP'
)
Order by d.audit_action_name
Go

PRINT "If the identified groups are not returned, this is a finding."



PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79297" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when concurrent logons/connections by the same user from different workstations occur." 
PRINT "Discussion:  For completeness of forensic analysis, it is necessary to track who logs on to SQL Server. 
 
Concurrent connections by the same user from multiple workstations may be valid use of the system; or such connections may be due to improper circumvention of the requirement to use the CAC for authentication; or they may indicate unauthorized account sharing; or they may be because an account has been compromised. 
 
(If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events (logons/connections; voluntary and involuntary disconnections), then it is not mandatory to create additional log entries specifically for this.)" 
PRINT "FINDING: If no records are returned, this is a finding. "

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP' 
GO

PRINT "If the 'SUCCESSFUL_LOGIN_GROUP' is returned in an active audit, this is not a finding. "


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79299" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when successful accesses to objects occur." 
PRINT "Discussion:  Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.  
 
In an SQL environment, types of access include, but are not necessarily limited to: 
SELECT 
INSERT 
UPDATE 
DELETE 
EXECUTE" 


PRINT "FINDING: If this is not required, this is not a finding."
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO


PRINT "FINDING: If the 'SCHEMA_OBJECT_ACCESS_GROUP' is not returned in an active audit, this is a finding."

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
Go

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79301" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records when unsuccessful accesses to objects occur." 
PRINT "Discussion:  Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.  
 
In an SQL environment, types of access include, but are not necessarily limited to: 
SELECT 
INSERT 
UPDATE 
DELETE 
EXECUTE 
 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones." 
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
GO


PRINT "FINDING: If no records are returned, this is a finding."

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
GO

PRINT "FINDING: If the 'SCHEMA_OBJECT_ACCESS_GROUP' is not returned in an active audit, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79303" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must generate audit records for all direct access to the database(s)." 
PRINT "Discussion:  In this context, direct access is any query, command, or call to SQL Server that comes from any source other than the application(s) that it supports. Examples would be the command line or a database management utility program. The intent is to capture all activity from administrative and non-standard sources." 

PRINT "FINDING: If any audits are configured to exclude administrative activities, this is a finding."
SELECT name AS AuditName, predicate AS AuditFilter 
FROM sys.server_audits 
WHERE predicate IS NOT NULL 
GO


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79305" 
PRINT "Group Title:  " 
PRINT "Severity: high" 
PRINT "Rule Title: SQL Server must implement NIST FIPS 140-2 validated cryptographic modules to provision digital signatures." 
PRINT "Discussion:  Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated. 
For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant." 

PRINT "FINDING: If the Security Setting for this option is 'Disabled' this is a finding."



PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79307" 
PRINT "Group Title:  " 
PRINT "Severity: high" 
PRINT "Rule Title: SQL Server must implement NIST FIPS 140-2 validated cryptographic modules to generate and validate cryptographic hashes." 
PRINT "Discussion:  Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated. 
 
For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant." 
PRINT "FINDING:"
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79309" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must implement NIST FIPS 140-2 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owners requirements." 
PRINT "Discussion:  Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated. 
 
It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards. 
 
For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant." 
PRINT "FINDING:"
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79311" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: The system SQL Server must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems." 
PRINT "Discussion:  Information stored in one location is vulnerable to accidental or incidental deletion or alteration. 
 
Off-loading is a common process in information systems with limited audit storage capacity. 
 
The system SQL Server may write audit records to database tables, to files in the file system, to other kinds of local repository, or directly to a centralized log management system. Whatever the method used, it must be compatible with off-loading the records to the centralized system." 
PRINT "FINDING:"
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79313" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must configure Customer Feedback and Error Reporting." 
PRINT "Discussion:  By default, Microsoft SQL Server enables participation in the customer experience improvement program (CEIP). This program collects information about how its customers are using the product. Specifically, SQL Server collects information about the installation experience, feature usage, and performance. This information helps Microsoft improve the product to better meet customer needs." 
PRINT "FINDING:"
PRINT "|---------------------------------------------------------------------|" 




PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79315" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server must configure SQL Server Usage and Error Reporting Auditing." 
PRINT "Discussion:  By default, Microsoft SQL Server enables participation in the customer experience improvement program (CEIP). This program collects information about how its customers are using the product. Specifically, SQL Server collects information about the installation experience, feature usage, and performance. This information helps Microsoft improve the product to better meet customer needs. The Local Audit component of SQL Server Usage Feedback collection writes data collected by the service to a designated folder, representing the data (logs) that will be sent to Microsoft. The purpose of the Local Audit is to allow customers to see all data Microsoft collects with this feature, for compliance, regulatory or privacy validation reasons." 
PRINT "FINDING: If the registry key do not exist or the value is blank, this is a finding."

SELECT name 
FROM sys.server_principals 
WHERE name LIKE '%SQLTELEMETRY%' 
GO

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79317" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: The SQL Server default account [sa] must be disabled." 
PRINT "Discussion:  SQL Server's [sa] account has special privileges required to administer the database. The [sa] account is a well-known SQL Server account and is likely to be targeted by attackers and thus more prone to providing unauthorized access to the database. 
This [sa] default account is administrative and could lead to catastrophic consequences, including the complete loss of control over SQL Server. If the [sa] default account is not disabled, an attacker might be able to gain access through the account. SQL Server by default, at installation, disables the [sa] account. 
Some applications that run on SQL Server require the [sa] account to be enabled in order for the application to function properly. These applications that require the [sa] account to be enabled are usually legacy systems." 

PRINT "FINDING: If the 'is_disabled' column is not set to '1', this is a finding."

USE master;
GO
SELECT name, is_disabled
FROM sys.sql_logins
WHERE principal_id = 1;
GO

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79319" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server default account [sa] must have its name changed." 
PRINT "Discussion:  SQL Server's [sa] account has special privileges required to administer the database. The [sa] account is a well-known SQL Server account name and is likely to be targeted by attackers, and is thus more prone to providing unauthorized access to the database. 

Since the SQL Server [sa] is administrative in nature, the compromise of a default account can have catastrophic consequences, including the complete loss of control over SQL Server. Since SQL Server needs for this account to exist and it should not be removed, one way to mitigate this risk is to change the [sa] account name." 
PRINT "FINDING: If the login account name 'SA' or 'sa' appears in the query output, this is a finding."
USE master; 
GO 
SELECT * 
FROM sys.sql_logins 
WHERE [name] = 'sa' OR [principal_id] = 1; 
GO 

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79321" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Execution of startup stored procedures must be restricted to necessary cases only." 
PRINT "Discussion:  In certain situations, to provide required functionality, a DBMS needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.
When 'Scan for startup procs' is enabled, SQL Server scans for and runs all automatically run stored procedures defined on the server.  The execution of start-up stored procedures will be done under a high privileged context, therefore it is a commonly used post-exploitation vector." 
PRINT "FINDING: If any stored procedures are returned that are not documented, this is a finding."

Select [name] as StoredProc
From sys.procedures
Where OBJECTPROPERTY(OBJECT_ID, 'ExecIsStartup') = 1
GO


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79323" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server Mirroring endpoint must utilize AES encryption." 
PRINT "Discussion:  Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

SQL Mirroring endpoints support different encryption algorithms, including no-encryption. Using a weak encryption algorithm or plaintext in communication protocols can lead to data loss, data manipulation and/or connection hijacking." 

SELECT name, type_desc, encryption_algorithm_desc
FROM sys.database_mirroring_endpoints
WHERE encryption_algorithm != 2
GO


PRINT "FINDING: If any records are returned, this is a finding."

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79325" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server Service Broker endpoint must utilize AES encryption." 
PRINT "Discussion:  Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.
Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 
SQL Server Service Broker endpoints support different encryption algorithms, including no-encryption. Using a weak encryption algorithm or plaintext in communication protocols can lead to data loss, data manipulation and/or connection hijacking." 
PRINT "FINDING: If any records are returned, this is a finding."

SELECT name, type_desc, encryption_algorithm_desc
FROM sys.service_broker_endpoints
WHERE encryption_algorithm != 2
GO



PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79327" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server execute permissions to access the registry must be revoked, unless specifically required and approved." 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 
Applications must adhere to the principles of least functionality by providing only essential capabilities.
SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system.
The registry contains sensitive information, including password hashes as well as clear text passwords. Registry extended stored procedures allow Microsoft SQL Server to access the machine's registry. The sensitivity of these procedures are exacerbated if Microsoft SQL Server is run under the Windows account LocalSystem. LocalSystem can read and write nearly all values in the registry, even those not accessible by the Administrator. Unlike the xp_cmdshell extended stored procedure, which runs under a separate context if executed by a login not in the sysadmin role, the registry extended stored procedures always execute under the security context of the MSSQLServer service. Because the sensitive information is stored in the registry, it is essential that access to that information be properly guarded." 
PRINT "FINDING: If any records are returned, review the system documentation to determine whether the accessing of the registry via extended stored procedures are required and authorized. If it is not authorized, this is a finding."

SELECT OBJECT_NAME(major_id) AS [Stored Procedure]
,dpr.NAME AS [Principal]
FROM sys.database_permissions AS dp
INNER JOIN sys.database_principals AS dpr ON dp.grantee_principal_id = dpr.principal_id
WHERE major_id IN (
OBJECT_ID('xp_regaddmultistring')
,OBJECT_ID('xp_regdeletekey')
,OBJECT_ID('xp_regdeletevalue')
,OBJECT_ID('xp_regenumvalues')
,OBJECT_ID('xp_regenumkeys')
,OBJECT_ID('xp_regremovemultistring')
,OBJECT_ID('xp_regwrite')
,OBJECT_ID('xp_instance_regaddmultistring')
,OBJECT_ID('xp_instance_regdeletekey')
,OBJECT_ID('xp_instance_regdeletevalue')
,OBJECT_ID('xp_instance_regenumkeys')
,OBJECT_ID('xp_instance_regenumvalues')
,OBJECT_ID('xp_instance_regremovemultistring')
,OBJECT_ID('xp_instance_regwrite')
)
AND dp.[type] = 'EX'
ORDER BY dpr.NAME;
GO


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79329" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Filestream must be disabled, unless specifically required and approved." 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 
Applications must adhere to the principles of least functionality by providing only essential capabilities.
The most significant potential for attacking an instance is through the use of features that expose an external interface or ad hoc execution capability. FILESTREAM integrates the SQL Server Database Engine with an NTFS file system by storing varbinary(max) binary large object (BLOB) data as files on the file system. Transact-SQL statements can insert, update, query, search, and back up FILESTREAM data." 

PRINT "FINDING: If 'run_value' is greater than '0', this is a finding."
EXEC sp_configure 'filestream access level'
GO


PRINT "FINDING: If the above query returns 'Yes' in the 'FileStreamEnabled' field, this is a finding."

SELECT CASE 
WHEN EXISTS (SELECT * 
FROM sys.configurations 
WHERE Name = 'filestream access level' 
AND Cast(value AS INT) = 0) THEN 'No' 
ELSE 'Yes'
END AS TSQLFileStreamAccess;
GO

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79333" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Ole Automation Procedures feature must be disabled, unless specifically required and approved. " 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 
Applications must adhere to the principles of least functionality by providing only essential capabilities.
SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system.
SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.
The Ole Automation Procedures option controls whether OLE Automation objects can be instantiated within Transact-SQL batches. These are extended stored procedures that allow SQL Server users to execute functions external to SQL Server in the security context of SQL Server.
The Ole Automation Procedures extended stored procedure allows execution of host executables outside the controls of database access permissions. This access may be exploited by malicious users who have compromised the integrity of the SQL Server database process to control the host operating system to perpetrate additional malicious activity." 
PRINT "FINDING: If the value of 'config_value' is '1', review the system documentation to determine whether the use of 'Ole Automation Procedures' is required and authorized. If it is not authorized, this is a finding."

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'Ole Automation Procedures'; 
GO



PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79335" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server User Options feature must be disabled, unless specifically required and approved." 
PRINT "Discussion:  SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.

The user options option specifies global defaults for all users. A list of default query processing options is established for the duration of a user's work session. The user options option allows you to change the default values of the SET options (if the server's default settings are not appropriate)." 
PRINT "FINDING: If the value of 'config_value' is '1', review the system documentation to determine whether the use of 'user options' is required and authorized. If it is not authorized, this is a finding."

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'user options'; 
GO


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79337" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Remote Access feature must be disabled, unless specifically required and approved." 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 
Applications must adhere to the principles of least functionality by providing only essential capabilities.
SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system.
SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.
The Remote Access option controls the execution of local stored procedures on remote servers or remote stored procedures on local server.  'Remote access' functionality can be abused to launch a Denial-of-Service (DoS) attack on remote servers by off-loading query processing to a target." 

PRINT "FINDING: If the value of 'config_value' is '1', review the system documentation to determine whether the use of 'Remote Access' is required (linked servers) and authorized. If it is not authorized, this is a finding"

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'remote access'; 
GO





PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79341" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Hadoop Connectivity feature must be disabled, unless specifically required and approved. " 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 
Applications must adhere to the principles of least functionality by providing only essential capabilities.
SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system.
SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.
The Hadoop Connectivity feature allows multiple types of external data sources to be created and used across all sessions on the server.  An exploit to the SQL Server instance could result in a compromise of the host system and external SQL Server resources." 
PRINT "FINDING: If the value of 'config_value' is '1', review the system documentation to determine whether the use of 'Hadoop Connectivity' option is required and authorized. If it is not authorized, this is a finding."

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'hadoop connectivity'; 
GO

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79343" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Allow Polybase Export feature must be disabled, unless specifically required and approved. " 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 
Applications must adhere to the principles of least functionality by providing only essential capabilities.
SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system.
SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.
The Allow Polybase Export feature allows an export of data to an external data source such as Hadoop File System or Azure Data Lake. An exploit to the SQL Server instance could result in a compromise of the host system and external SQL Server resources." 

PRINT "FINDING: If the value of 'config_value' is '1', review the system documentation to determine whether the use of 'Allow Polybase Export' is required and authorized. If it is not authorized, this is a finding"

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'allow polybase export'; 
GO


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79345" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Remote Data Archive feature must be disabled, unless specifically required and approved. " 
PRINT "Discussion:  Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 
Applications must adhere to the principles of least functionality by providing only essential capabilities.
SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system.
SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.
The Remote Data Archive feature allows an export of local SQL Server data to an Azure SQL Database. An exploit to the SQL Server instance could result in a compromise of the host system and external SQL Server resources." 
EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'remote data archive'; 
GO

PRINT "FINDING: If the value of 'config_value' is '1', review the system documentation to determine whether the use of 'Remote Data Archive' is required and authorized. If it is not authorized, this is a finding"

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79347" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server External Scripts Enabled feature must be disabled, unless specifically required and approved." 
PRINT "Discussion:  SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.
The External Scripts Enabled feature allows scripts external to SQL such as files located in an R library to be executed." 

PRINT "FINDING: If the value of 'config_value' is '1', review the system documentation to determine whether the use of 'External Scripts Enabled' is required and authorized. If it is not authorized, this is a finding."
EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'external scripts enabled'; 
GO
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79349" 
PRINT "Group Title:  " 
PRINT "Severity: low" 
PRINT "Rule Title: The SQL Server Browser service must be disabled unless specifically required and approved." 
PRINT "Discussion:  The SQL Server Browser simplifies the administration of SQL Server, particularly when multiple instances of SQL Server coexist on the same computer. It avoids the need to hard-assign port numbers to the instances and to set and maintain those port numbers in client systems. It enables administrators and authorized users to discover database management system instances, and the databases they support, over the network. SQL Server uses the SQL Server Browser service to enumerate instances of the Database Engine installed on the computer. This enables client applications to browse for a server, and helps clients distinguish between multiple instances of the Database Engine on the same computer.
This convenience also presents the possibility of unauthorized individuals gaining knowledge of the available SQL Server resources. Therefore, it is necessary to consider whether the SQL Server Browser is needed. Typically, if only a single instance is installed, using the default name (MSSQLSERVER) and port assignment (1433), the Browser is not adding any value. The more complex the installation, the more likely SQL Server Browser is to be helpful. 
This requirement is not intended to prohibit use of the Browser service in any circumstances.  It calls for administrators and management to consider whether the benefits of its use outweigh the potential negative consequences of it being used by an attacker to browse the current infrastructure and retrieve a list of running SQL Server instances." 
PRINT "FINDING:"
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79351" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: SQL Server Replication Xps feature must be disabled, unless specifically required and approved." 
PRINT "Discussion:  SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.
Enabling the replication XPs opens a significant attack surface area that can be used by an attacker to gather information about the system and potentially abuse the privileges of SQL Server." 
PRINT "FINDING: If the value of 'config_value' is '1', review the system documentation to determine whether the use of 'Replication Xps' is required and authorized. If it is not authorized, this is a finding."

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'replication xps'; 
GO

PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79353" 
PRINT "Group Title:  " 
PRINT "Severity: low" 
PRINT "Rule Title: If the SQL Server Browser Service is specifically required and approved, SQL instances must be hidden." 
PRINT "Discussion:  The SQL Server Browser simplifies the administration of SQL Server, particularly when multiple instances of SQL Server coexist on the same computer. It avoids the need to hard-assign port numbers to the instances and to set and maintain those port numbers in client systems. It enables administrators and authorized users to discover database management system instances, and the databases they support, over the network. SQL Server uses the SQL Server Browser service to enumerate instances of the Database Engine installed on the computer. This enables client applications to browse for a server, and helps clients distinguish between multiple instances of the Database Engine on the same computer.
This convenience also presents the possibility of unauthorized individuals gaining knowledge of the available SQL Server resources. Therefore, it is necessary to consider whether the SQL Server Browser is needed. Typically, if only a single instance is installed, using the default name (MSSQLSERVER) and port assignment (1433), the Browser is not adding any value. The more complex the installation, the more likely SQL Server Browser is to be helpful. 
This requirement is not intended to prohibit use of the Browser service in any circumstances.  It calls for administrators and management to consider whether the benefits of its use outweigh the potential negative consequences of it being used by an attacker to browse the current infrastructure and retrieve a list of running SQL Server instances.  In order to prevent this, the SQL instance(s) can be hidden." 

DECLARE @HiddenInstance INT 
EXEC master.dbo.Xp_instance_regread 
 N'HKEY_LOCAL_MACHINE', 
 N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib', 
 N'HideInstance', 
 @HiddenInstance output 

SELECT CASE 
        WHEN @HiddenInstance = 0 
             AND Serverproperty('IsClustered') = 0 THEN 'No' 
        ELSE 'Yes' 
      END AS [Hidden]

PRINT "FINDING: If the value of 'Hidden' is 'No' and the startup type of the 'SQL Server Browser' service is not 'Disabled', this is a finding."


PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79355" 
PRINT "Group Title:  " 
PRINT "Severity: high" 
PRINT "Rule Title: When using command-line tools such as SQLCMD in a mixed-mode authentication environment, users must use a logon method that does not expose the password." 
PRINT "Discussion:  To prevent the compromise of authentication information, such as passwords and PINs, during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism.
Obfuscation of user-provided information when typed into the system is a method used in addressing this risk.
For example, displaying asterisks when a user types in a password or PIN, is an example of obscuring feedback of authentication information.
This requirement is applicable when mixed-mode authentication is enabled.  When this is the case, password-authenticated accounts can be created in and authenticated by SQL Server.  Other STIG requirements prohibit the use of mixed-mode authentication except when justified and approved.  This deals with the exceptions.
SQLCMD and other command-line tools are part of any SQL Server installation. These tools can accept a plain-text password, but do offer alternative techniques. Since the typical user of these tools is a database administrator, the consequences of password compromise are particularly serious. Therefore, the use of plain-text passwords must be prohibited, as a matter of practice and procedure." 


PRINT "FINDING:"
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-79357" 
PRINT "Group Title:  " 
PRINT "Severity: high" 
PRINT "Rule Title: Applications must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals." 
PRINT "Discussion:  To prevent the compromise of authentication information, such as passwords and PINs, during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk.

For example, displaying asterisks when a user types in a password or PIN, is an example of obscuring feedback of authentication information.

Database applications may allow for entry of the account name and password as a visible parameter of the application execution command. This practice must be prohibited and disabled to prevent shoulder surfing." 
PRINT "FINDING:"
PRINT "|---------------------------------------------------------------------|" 


PRINT "|---------------------------------------------------------------------|" 
PRINT "V-97521" 
PRINT "Group Title:  " 
PRINT "Severity: medium" 
PRINT "Rule Title: Confidentiality of controlled information during transmission through the use of an approved TLS version." 
PRINT "Discussion:  Transport Layer Security (TLS) encryption is a required security setting as a number of known vulnerabilities have been reported against Secure Sockets Layer (SSL) and earlier versions of TLS. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party.  SQL Server must use a minimum of FIPS 140-2-approved TLS version 1.2, and all non-FIPS-approved SSL and TLS versions must be disabled. NIST SP 800-52 Rev.2 specifies the preferred configurations for government systems.

References:
TLS Support 1.2 for SQL Server: https://support.microsoft.com/en-us/kb/3135244 
TLS Registry Settings:  https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
" 
PRINT "|---------------------------------------------------------------------|" 