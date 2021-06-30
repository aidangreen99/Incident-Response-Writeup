# Incident Response Policy Writeup

Incident Response 
​Table of Contents 

 

 

 

 

 

 

 

 

 

 

 

 

 

 

 

 

​

## Preventative Actions To Be Taken By Users

* Keep personal resources up to date. IS will keep organizational resources up to date, but to protect the integrity of the network personal devices should also be up to date. 
* Know the warning signs of spam emails. If you doubt the authenticity of an email, forward it to IS so they can verify it. 

## Incident Risk Situations 
Incident risk situations are actions or events that put a system at risk of being compromised. After any system experiences a risk situation, IS should be contacted immediately and given all relevant information, such as originating country, links clicked, files downloaded, or information stolen. Incident risk situations include various circumstances, such as:  

* Clicking a malicious email link. 
* Opening a compromised attachment. 
* Connecting to unsecured Wi-Fi networks.  
* Physical compromise (e.g. stolen laptop or phone, or unauthorized access).  
* Giving account passwords away via social engineering or phishing. 
* In certain countries deemed cybersecurity risks<sup>[1]</sup>, leaving systems unattended, even in personal rooms. 

[1]:https://travel.state.gov/content/travel/en/traveladvisories/traveladvisories.html/ "Countries that should be considered security risks can be found at the linked URL under the Level 4 category."

 

## Incident Actions To Be Taken By Users 
* Disconnect the computer from the network if possible.  
* Contact COB IS with as much detail as possible. Include actions that may have resulted in infection, services or network resources accessed, accounts used, and    relevant contact information.
* Change passwords. Any account you accessed through the compromised system is at risk.
* Monitor accounts for suspicious activity. If emails are being sent through your account or files are being modified, report it to IS immediately.
* Notify other users of service interruption. If you share the resource with other users, explain that the computer is not to be used or affected in any way, including power cycles or logins.
* Wait for further instructions from COB IS. If another IS entity contacts you, verify the action with COB IS to ensure all departments are in the loop. 

## Procedures for IS Agents 
* Disconnect the computer from the network if possible. Shutting the computer down or rebuilding the computer could destroy vital evidence, so the best way to achieve immediate containment is simply removal from the network. If the computer is connected by ethernet, remove the ethernet. If it is connected wirelessly, disconnect the Wi-Fi or disable the wireless adapter.
* Gather as much info from the user as possible. Inquire about sites they may have visited, files they may have downloaded, what they clicked on, and what occurred. <u>DO NOT RECREATE THE USER’S STEPS.</u>
* Create an isolated environment for the computer. Keep the computer disconnected from all networks and services.
* Download latest Windows Defender definitions via a known clean USB. The latest definitions can be found here: https://www.microsoft.com/en-us/wdsi/defenderupdates 
* Run Windows Defender on the infected computer. Follow instructions given to clean the computer.
* Install Malwarebytes with latest definitions via USB. 
* Run a Malwarebytes scan. If issues are found, attempt to resolve them per Malwarebytes’ instructions.  
* Backup necessary data once computer is clean. Work with the user to ensure their vital documents are backed up. Do not simply copy over the user’s entire profile as that may proliferate the spread of the malware.  
* Reimage, if necessary. 

## NIST Standards For Incident Response 

### Phase 0: Preparation 

#### 0.1	Security Controls 

Proper security controls can mitigate the risk of a compromised system by disallowing the spread of the infection, as well as preventing the initial infection. For the sake of this procedure, properly implemented controls will be assumed.  

#### 0.2	Channels of Communication 

Communication is very important as it allows a rapid response to an incident. All employees are encouraged to keep multiple channels open (i.e. cell phone, email, or encrypted messaging). During an incident response, or IR, delegated employees may be required to keep multiple channels open.  

#### 0.3 	Gather Relevant Information 

To assist with 0.2 Channels of Communication it is vital that all information directly and indirectly relevant to the incident be gathered and accessible. The NIST Computer Security Incident Handling Guide (Cihonski, et al. 2012) lists the following as relevant resources and facilities: 
* Contact Information for team members and others within and outside the organization, such as law enforcement and other incident response teams. Information may include phone numbers, email addresses, public encryption keys, and contact identity verification processes.  
* Incident reporting mechanisms such as phone numbers, email addresses, online forms, and secure instant messaging systems that users can use to report suspected incidents. To encourage reporting, at least one method should permit users to report anonymously.  
* War room if necessary, to allow for centralized dissemination of relevant information to whichever IR team member needs it, as well as real time creation of a customized IR plan. 
* Secure storage for securing evidence and other sensitive materials. 
* Encryption software to be used for communications among team members.  

 

#### 0.4	IR Analysis Hardware and Software 
Proper hardware and software play a huge role in the IR as well as in other stages of the control process. NIST SP.800-61 (Cihonski, et al. 2012) lists the following as hardware and software for an IR: 
* Digital forensic workstations for creating disk images, preserving log files, and saving any other relevant data.
* Laptops for activities that benefit from a degree of freedom, such as analyzing data, sniffing packets, and writing reports.
* Spare workstations, servers, and networking equipment, or the virtual equivalent for various purposes including restoring backups and testing malware.
* Blank removable media for transportation of data. 
* Portable printer for printing logs from non-networked resources.
* Removable media containing trusted versions of software for gathering evidence from systems. 
* Evidence gathering accessories such as hard-bound notebooks, digital cameras, audio recorders, and evidence storage bags and tags to preserve evidence for possible legal action. 

 

### Phase 1: Detection and Analysis 

#### 1.1	Attack Vectors 

Incidents can occur in many ways, so organizations should be generally prepared to handle any incident, but should focus on the most commonly known attack vectors. From NISP SP.800-61 Section 3.2.1 (Cihonski, et al. 2012), a list of common methods of attack: 

External/Removable Media: An attack executed from removable media or a peripheral device—for example, malicious code spreading onto a system from an infected USB flash drive.  

Attrition: An attack that employs brute force methods to compromise, degrade, or destroy systems, networks, or services (e.g., a DDoS intended to impair or deny access to a service or application; a brute force attack against an authentication mechanism, such as passwords, CAPTCHAS, or digital signatures).  

Web: An attack executed from a website or web-based application—for example, a cross-site scripting attack used to steal credentials or a redirect to a site that exploits a browser vulnerability and installs malware.  

Email: An attack executed via an email message or attachment—for example, exploit code disguised as an attached document or a link to a malicious website in the body of an email message. 

Impersonation: An attack involving replacement of something benign with something malicious— for example, spoofing, man in the middle attacks, rogue wireless access points, and SQL injection attacks all involve impersonation.  

Improper Usage: Any incident resulting from violation of an organization’s acceptable usage policies by an authorized user, excluding the above categories; for example, a user installs file-sharing software, leading to the loss of sensitive data; or a user performs illegal activities on a system.  

Loss or Theft of Equipment: The loss or theft of a computing device or media used by the organization, such as a laptop, smartphone, or authentication token. 

1.2	Signs of an Incident 

For many organizations, detection is the most challenging aspect of assessing potential incidents. This difficulty is mainly due to a combination of three factors: 

    Incidents can be detected through a variety of means, including manual (user-reported) and automatic (IDPSs). The level of detail varies between detection methods. 

    Typical reports of potential incidents are quite high. 

    Deep and specialized technical knowledge and extensive experience are necessary for proper and efficient analysis of incident data. 

There are two categories of incident signals: precursors and indicators. Precursors are signs that an incident may be pending, while indicators are signs that an incident may have already occurred.  

Precursors are a rare luxury, and often there will not be any identifiable precursors from the target’s perspective. Examples of precursors include web server log entries showing usage of a vulnerability scanner, an announcement of a new exploit that targets various known systems, or a threat from a group or individual against an organization.  

Indicators are much more common. Some examples include antivirus software alerts, a new file with an unusual name, a buffer overflow alert sensor, or a large number of bounced emails with suspicious contents.  

1.3	Incident Analysis Practices 

Performing the initial analysis can be quite difficult. The NIST has created a list of recommendations to make the process easier. These recommended standards include: 

    Profile Networks and Systems. A profile is a measure of the expected activity. This allows changes to be more easily detected. Examples of profiling are file integrity checking and monitoring network bandwidth usage. 

    Log Retention Policy. The length of time to store logs is determined by an organization’s retention policies and the expected volume of data. 

    Event Correlation. Evidence of an incident may be captured in a variety of logs across a variety of services. Correlating events between multiple logs helps validate that an event occurred.  

    Keep All Host Clocks Synchronized. To assist with event correlation, synchronized clocks are invaluable. If logs report the same event at different times, it can be impossible to know whether there is any correlation. If all clocks are kept synchronized, correlation can be considered valid. 

    Run Packet Sniffers to Collect Additional Data. Permission may be necessary for the IR team to collect the data due to privacy concerns.  

 

Phase 2: Containment, Eradication, and Recovery 

2.1	Containment Strategy 

Containment is important for a variety of reasons. It can keep the incident from overwhelming resources, and it can provide time for a remediation strategy. Determining the containment strategy is equally important. Important criteria to consider could be: 

    Potential damage and theft of resources 

    Need to preserve evidence 

    Availability of services 

    Time and resources needed to implement 

    Effectiveness of the strategy (e.g. strategy strength if full containment is not necessary) 

    Duration of solution 

Sandboxing can be a useful tool for containment. By putting the attacking entity into a closely controlled environment, additional information can be gained. The attack should not be allowed to continue in any capacity besides inside the sandbox. This leaves other systems vulnerable. A potential issue regarding containment is the chance that containment may cause additional damage. For example, if an attacking entity is set to periodically check that it can maintain external connections, containment may make the check fail. This could trigger the entity to overwrite or encrypt all data on the host drive. 

2.2	Identifying Attacking Hosts 

While IR teams should generally stay focused on containment, eradication, and recovery, system owners and others may want or need to identify the attacking host or hosts. SP.800-61 describes a few commonly performed activities: 

    Validating the Attacking Host’s IP Address. New incident handlers often focus on the attacking host’s IP address. The handler may attempt to validate that the address was not spoofed by verifying connectivity to it; however, this simply indicates that a host at that address does or does not respond to the requests. A failure to respond does not mean the address is not real—for example, a host may be configured to ignore pings and traceroutes. Also, the attacker may have received a dynamic address that has already been reassigned to someone else. 

    Researching the Attacking Host through Search Engines. Performing an Internet search using the apparent source IP address of an attack may lead to more information on the attack—for example, a mailing list message regarding a similar attack. 

    Using Incident Databases. Several groups collect and consolidate incident data from various organizations into incident databases. This information sharing may take place in many forms, such as trackers and real-time blacklists. The organization can also check its own knowledge base or issue tracking system for related activity. 

    Monitoring Possible Attacker Communication Channels. Incident handlers can monitor communication channels that may be used by an attacking host. For example, many bots use IRC as their primary means of communication. Also, attackers may congregate on certain IRC channels to brag about their compromises and share information. However, incident handlers should treat any such information that they acquire only as a potential lead, not as fact. 

2.3 	Eradication and Recovery 

After an incident has been adequately contained, eradication may be necessary to eliminate components of the incident, such as deleting malware and disabling breached user accounts. In some cases, however, eradication may not be necessary.  

During recovery, administrators restore systems to their normal operation, confirm their normal function, and remediate discovered vulnerabilities. Recovery can include many actions, such as restoring systems from clean backups, replacing compromised files, patching, and tightening network perimeter safety. Heightened system logging and/or network monitoring are often included, as once a resource is successfully attacked, it will often be attacked again.  

## References 

Cihonski, Paul, Tom Millar, Tim Grance, and Karen Scarfone. 2012. Computer Security Incident Handling Guide Special Publicaation 800-61 Rev. 2. National Institute of Standards and Technology. 

 

 

 

 

 
