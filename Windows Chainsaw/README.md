# Windows Chainsaw Integration [![N|Solid](https://cdn-icons-png.flaticon.com/128/6939/6939131.png)](https://myservice.socfortress.co/explore?left=%7B%22datasource%22:%22WAZUH%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22query%22:%22_id:$get_alert_id.hits.hits.#._id%22,%22alias%22:%22%22,%22metrics%22:%5B%7B%22id%22:%221%22,%22type%22:%22logs%22,%22settings%22:%7B%22limit%22:%22500%22%7D%7D%5D,%22bucketAggs%22:%5B%5D,%22timeField%22:%22timestamp%22%7D%5D,%22range%22:%7B%22from%22:%22now-6h%22,%22to%22:%22now%22%7D%7D) [![N|Solid](https://cdn-icons-png.flaticon.com/128/406/406217.png)](https://hunt.socfortress.co) [![N|Solid](https://cdn-icons-png.flaticon.com/128/4840/4840332.png)](https://servicedesk.socfortress.co/help/2979687893)
Wazuh and Chainsaw integration to run forensic analysis.

From Chainsaw’s Github page: Chainsaw provides a powerful ‘first-response’ capability to quickly identify threats within Windows event logs. It offers a generic and fast method of searching through event logs for keywords, and by identifying threats using built-in detection logic and via support for Sigma detection rules.

Chainsaw is a free tool developed by F-Secure.

Some use cases:

After deploying Wazuh in your environment, you can use Chainsaw to collect past artifacts still present in the WinEvtLogs and take Chainsaw’s output to the Wazuh manager for centralised analysis and triage of past events that might still require attention. This centralised collection of artifacts provides a valuable insight of past security events that might have been missed, since there was no EDR tool in place. It can also help to identify persistent footholds.
Apply DFIR at any given time. By using Wazuh’s wodle commands capability all artifacts in WinEvtLogs can be taken to the manager for analysis.
Chainsaw - Overview
Chainsaw can be used in search or hunt modes. When run in search mode, parameters such as event IDs or even regex can be used as input. In this integration though chainsaw will be used in hunt mode.

In hunt mode, chainsaw can be executed with built-in capabilities only (see Github page for details) but where it really shines is when Sigma rules are added to the WinEvtLogs analysis, along with lateral movement analysis.

The following subsections cover the metadata collected for each category.

```---
name: Chainsaw's Sigma mappings for Event Logs
kind: evtx
rules: sigma

ignore:
  - Defense evasion via process reimaging
  - Exports Registry Key To an Alternate Data Stream
  - NetNTLM Downgrade Attack
  - Non Interactive PowerShell
  - Wuauclt Network Connection

groups:
  - name: Suspicious Process Creation
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 1
      Provider: Microsoft-Windows-Sysmon
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: Image
        from: Image
        to: Event.EventData.Image
      - name: Command Line
        from: CommandLine
        to: Event.EventData.CommandLine
      - name: Original File Name
        from: OriginalFileName
        to: Event.EventData.OriginalFileName
      - name: Parent Image
        from: ParentImage
        to: Event.EventData.ParentImage
      - name: Parent Command Line
        from: ParentCommandLine
        to: Event.EventData.ParentCommandLine

  - name: Suspicious Network Connection
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 3
      Provider: Microsoft-Windows-Sysmon
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: User
        from: User
        to: Event.EventData.User
      - name: Image
        from: Image
        to: Event.EventData.Image
      - name: Destination IP
        from: DestinationIp
        to: Event.EventData.DestinationIp
      - name: Destination Port
        from: DestinationPort
        to: Event.EventData.DestinationPort
      - name: Destination Hostname
        from: DestinationHostname
        to: Event.EventData.DestinationHostname
      - name: Destination Is IPv6
        from: DestinationIsIpv6
        to: Event.EventData.DestinationIsIpv6
        visible: false
      - name: Initiated
        from: Initiated
        to: Event.EventData.Initiated
      - name: Source Port
        from: SourcePort
        to: Event.EventData.SourcePort

  - name: Suspicious Image Load
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 7
      Provider: Microsoft-Windows-Sysmon
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: Image
        from: Image
        to: Event.EventData.Image
      - name: Image Loaded
        from: ImageLoaded
        to: Event.EventData.ImageLoaded

  - name: Suspicious File Creation
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 11
      Provider: Microsoft-Windows-Sysmon
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: Image
        from: Image
        to: Event.EventData.Image
      - name: Target File Name
        from: TargetFilename
        to: Event.EventData.TargetFilename

  - name: Suspicious Registry Event
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 13
      Provider: Microsoft-Windows-Sysmon
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: Image
        from: Image
        to: Event.EventData.Image
      - name: Details
        from: Details
        to: Event.EventData.Details
      - name: Target Object
        from: TargetObject
        to: Event.EventData.TargetObject

  - name: Suspicious Service Installed
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 7045
      Provider: Service Control Manager
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: Service
        from: ServiceName
        to: Event.EventData.ServiceName
      # TODO: Can someone check if this is a typo...?
      - name: Command Line
        from: CommandLine
        to: Event.EventData.ImagePath

  - name: Suspicious Command Line
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 4688
      Provider: Microsoft-Windows-Security-Auditing
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: User
        from: UserName
        to: Event.EventData.SubjectUserName
      # TODO: Can someone check if this is a typo...?
      - name: Process
        from: Image
        to: Event.EventData.NewProcessName
      - name: Command Line
        from: CommandLine
        to: Event.EventData.CommandLine

  - name: Suspicious Scheduled Task Created
    timestamp: Event.System.TimeCreated
    filter:
      int(EventID): 4698
      Provider: Microsoft-Windows-Security-Auditing
    fields:
      - from: Provider
        to: Event.System.Provider
        visible: false
      - name: Event ID
        from: EventID
        to: Event.System.EventID
      - name: Record ID
        from: EventRecordID
        to: Event.System.EventRecordID
      - name: Computer
        from: Computer
        to: Event.System.Computer
      - name: User
        from: UserName
        to: Event.EventData.SubjectUserName
      - name: Name
        from: TaskName 
        to: Event.EventData.TaskName
      # TODO: Can someone check if this is a typo...?
      - name: Command Line
        from: CommandLine
        to: Event.EventData.TaskContent
```
Workflow
Whatever the execution approach (locally in a single machine or in several machines, triggered in all windows machines via wodle command, etc.) the powershell script (see below) will execute chainsaw, will output to CSV files, will convert these CSVs to JSON that’ll be appended to the active responses log file.
While looping thru, a flow control (sleep timer) will prevent filling up the agent’s queue.
Detection rules in the Wazuh Manager will generate alerts accordingly.
NOTE: There’s an issue in Chainsaw’s CSV file generation where columns with “\r” cause a break in that line/row and get splitted in 2 different lines.

The folder “c:\Program Files” is used to store the chainsaw folder with the executable and all the sigma rules. Change folder location and settings in the powershell script as per your requirement.

Chainsaw powershell script execution:

powershell.exe  -ExecutionPolicy Bypass -File "C:\Program Files\Sysinternals\chainsaw\chainsaw.ps1"
Chainsaw can also be regularly executed, triggered by a wodle command config on Wazuh manager.

Based on Chainsaw categories mentioned earlier, we can now build Wazuh’s detection rules.
----------------------------------------------------------------------------------

<p align="center">
  <a href="https://www.socfortress.co/">
<img src="https://user-images.githubusercontent.com/95670863/183437012-6ed70011-b40d-4597-8678-e3d601b6cf4d.png" alt="logo_website (1)" width="400" height="400">
  </a>
</p>
