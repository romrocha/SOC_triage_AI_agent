#!/usr/bin/env python3
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


REPO_ROOT = Path(__file__).resolve().parents[1]
ROUND1_DIR = REPO_ROOT / "input" / "round1_no_ioc"


@dataclass(frozen=True)
class EventSpec:
    alert_type: str
    source: str
    title: str
    description: str
    severity: int
    date_ms: int
    observables: List[Dict[str, Any]]
    tlp: int = 2
    pap: int = 2


UTC = timezone.utc
TIMELINE_START = datetime(2024, 11, 27, tzinfo=UTC)
NOISE_TIMELINE_START = datetime(2024, 11, 27, 12, 0, tzinfo=UTC)


def ts(hour: int, minute: int) -> int:
    return int(datetime(2024, 11, 27, hour, minute, tzinfo=UTC).timestamp() * 1000)


def observable(data_type: str, values: Iterable[str] | str, message: str) -> Dict[str, Any]:
    if isinstance(values, str):
        values = [values]
    return {
        "dataType": data_type,
        "data": list(values),
        "message": message,
        "tlp": 2,
    }


_MITRE_BY_TITLE = {
    "Credential phishing delivered to finance mailbox": ["T1566.001"],
    "User click on credential phishing URL": ["T1204.001"],
    "Risky sign-in after suspected credential theft": ["T1078"],
    "WINWORD spawned encoded PowerShell on finance laptop": ["T1059.001"],
    "Suspicious PowerShell network beacon from finance laptop": ["T1071.001"],
    "LSASS memory access from unsigned loader": ["T1003.001"],
    "Abnormal SMB authentication to finance file share": ["T1021.002"],
    "Lateral movement over SMB from compromised finance host": ["T1021.002"],
    "Remote service creation consistent with PsExec": ["T1569.002"],
    "Shadow copy deletion attempt on finance workstation": ["T1490"],
    "HTTPS beaconing to ransomware staging domain": ["T1071.001"],
    "Mass file rename behavior on finance share": ["T1486"],
    "Correlated ransomware precursor activity in finance": ["T1486"],
    "Backup tampering against finance file server": ["T1490"],
    "Ransom note dropped on finance endpoints": ["T1486"],
    "Unusual after-hours sign-in to HR applications": ["T1078"],
    "Mass download from HR compensation site": ["T1530"],
    "Archive creation of salary data on HR laptop": ["T1560.001"],
    "Removable media mounted on HR laptop": ["T1052.001"],
    "Upload to personal Dropbox from HR endpoint": ["T1567.002"],
    "Large outbound transfer to personal cloud storage": ["T1048"],
    "Sensitive HR files accessed after midnight-equivalent off-hours": ["T1005"],
    "Sensitive HR files accessed after midnight": ["T1005"],
    "Correlation: HR data access and exfil indicators": ["T1567.002"],
    "Correlation: after-hours HR data access and exfil indicators": ["T1567.002"],
    "Salary workbook sent to personal webmail draft": ["T1048.003"],
    "Repeated download of compensation exports": ["T1530"],
    "Connection to personal cloud storage upload endpoint": ["T1567.002"],
    "Archive split into password-protected volumes": ["T1560.001"],
    "USB write burst after archive creation": ["T1052.001"],
    "Upload of HR archive to personal Dropbox resumed": ["T1567.002"],
    "Insider data exfiltration pattern against HR compensation data": ["T1567.002"],
    "Sign-in from unrecognized geographic location": ["T1078"],
    "Service enumeration and port scanning on production host": ["T1046"],
    "PowerShell execution with elevated privileges on endpoint": ["T1059.001"],
    "High-volume outbound data transfer detected": [],
    "Internal network port scanning from corporate subnet": ["T1046"],
    "Inbound email with suspicious sender domain": ["T1566"],
    "Remote administration tool execution via SMB": ["T1021.002"],
    "File upload to cloud storage platform detected": ["T1567.002"],
    "Impossible travel sign-in anomaly detected": ["T1078"],
    "Repeated authentication failures for service account": ["T1110"],
    "Anomalous outbound data transfer volume": ["T1048"],
    "Unsigned binary execution on macOS endpoint": ["T1204.002"],
    "RDP and WinRM connection probing detected": ["T1021.001"],
    "Suspicious script interpreter chain at logon": ["T1059.001"],
}


def alert_from_spec(source_ref: str, spec: EventSpec) -> Dict[str, Any]:
    mitre = _MITRE_BY_TITLE.get(spec.title, [])
    return {
        "type": spec.alert_type,
        "source": spec.source,
        "sourceRef": source_ref,
        "title": spec.title,
        "description": spec.description,
        "severity": spec.severity,
        "date": spec.date_ms,
        "tags": [spec.source] + mitre,
        "tlp": spec.tlp,
        "pap": spec.pap,
        "flag": False,
        "status": "New",
        "observables": spec.observables,
    }


def load_existing_ids(path: Path) -> List[str]:
    items = json.loads(path.read_text(encoding="utf-8"))
    return [str(item["sourceRef"]) for item in items]


def campaign_a_specs() -> List[EventSpec]:
    return [
        EventSpec(
            alert_type="Email",
            source="Google Workspace Security",
            title="Credential phishing delivered to finance mailbox",
            severity=3,
            date_ms=ts(12, 0),
            description=(
                "Google Workspace flagged a message sent to b.smith@corp.local from "
                "invoices@acme-payables.co with DMARC fail and a link to "
                "hxxps://sharepoint-acme-files[.]com/ReviewInvoice. Message subject: "
                '"Updated ACH instructions - November".'
            ),
            observables=[
                observable("mail", "b.smith@corp.local", "Target mailbox"),
                observable("domain", "acme-payables.co", "Spoofed sender domain"),
                observable("url", "https://sharepoint-acme-files.com/ReviewInvoice", "Phishing URL"),
            ],
        ),
        EventSpec(
            alert_type="Email",
            source="Proofpoint TAP",
            title="User click on credential phishing URL",
            severity=3,
            date_ms=ts(12, 8),
            description=(
                "Proofpoint TAP recorded b.smith clicking the rewritten invoice lure from FIN-LT-204. "
                "Browser telemetry shows redirect to a fake Microsoft 365 sign-in page."
            ),
            observables=[
                observable("username", "b.smith", "Affected user"),
                observable("hostname", "FIN-LT-204", "Endpoint used for click"),
                observable(
                    "url",
                    "https://urldefense.proofpoint.com/v2/url?u=sharepoint-acme-files.com",
                    "Rewritten click URL",
                ),
            ],
        ),
        EventSpec(
            alert_type="Identity",
            source="Microsoft Entra ID Protection",
            title="Risky sign-in after suspected credential theft",
            severity=3,
            date_ms=ts(12, 15),
            description=(
                "Microsoft Entra ID Protection generated a risky sign-in for b.smith from "
                "103.124.92.77 using legacy authentication minutes after the phishing click."
            ),
            observables=[
                observable("username", "b.smith", "Compromised account"),
                observable("ip", "103.124.92.77", "Risky sign-in IP"),
            ],
        ),
        EventSpec(
            alert_type="Endpoint",
            source="Cortex XDR",
            title="WINWORD spawned encoded PowerShell on finance laptop",
            severity=4,
            date_ms=ts(12, 24),
            description=(
                "Cortex XDR detected WINWORD.EXE spawning powershell.exe -enc on FIN-LT-204 "
                "under user b.smith. The command downloaded hxxps://cdn-sharepoint-acme-files[.]com/update.dat."
            ),
            observables=[
                observable("hostname", "FIN-LT-204", "Affected endpoint"),
                observable("username", "b.smith", "Logged-on user"),
                observable("url", "https://cdn-sharepoint-acme-files.com/update.dat", "Payload URL"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Endpoint",
            source="Microsoft Defender for Endpoint",
            title="Suspicious PowerShell network beacon from finance laptop",
            severity=4,
            date_ms=ts(12, 31),
            description=(
                "Defender for Endpoint correlated encoded PowerShell on FIN-LT-204 with repeated "
                "outbound HTTPS connections to 185.225.17.81."
            ),
            observables=[
                observable("hostname", "FIN-LT-204", "Affected endpoint"),
                observable("ip", "185.225.17.81", "Command-and-control IP"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Credential Access",
            source="CrowdStrike Falcon",
            title="LSASS memory access from unsigned loader",
            severity=4,
            date_ms=ts(12, 38),
            description=(
                "CrowdStrike Falcon flagged update_check.exe opening LSASS memory on FIN-LT-204 "
                "from C:\\Users\\b.smith\\AppData\\Local\\Temp\\7zS4A1\\update_check.exe."
            ),
            observables=[
                observable("hostname", "FIN-LT-204", "Affected endpoint"),
                observable(
                    "file",
                    "C:\\Users\\b.smith\\AppData\\Local\\Temp\\7zS4A1\\update_check.exe",
                    "Unsigned loader path",
                ),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Identity",
            source="Microsoft Defender for Identity",
            title="Abnormal SMB authentication to finance file share",
            severity=3,
            date_ms=ts(12, 52),
            description=(
                "Microsoft Defender for Identity observed b.smith authenticating from FIN-LT-204 "
                "to FS-FIN-01 and FS-FIN-02 over SMB outside the finance team's normal access pattern."
            ),
            observables=[
                observable("username", "b.smith", "Account used for SMB access"),
                observable("hostname", "FS-FIN-01", "Primary file server"),
            ],
        ),
        EventSpec(
            alert_type="Network",
            source="Cisco Secure Firewall",
            title="Lateral movement over SMB from compromised finance host",
            severity=4,
            date_ms=ts(13, 4),
            description=(
                "Cisco Secure Firewall detected FIN-LT-204 initiating repeated SMB sessions to "
                "FIN-WS-118, FIN-WS-221 and FS-FIN-01 using the same credentials."
            ),
            observables=[
                observable("hostname", "FIN-LT-204", "Source workstation"),
                observable("ip", "10.42.18.44", "SMB source IP"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Endpoint",
            source="Cortex XDR",
            title="Remote service creation consistent with PsExec",
            severity=4,
            date_ms=ts(13, 17),
            description=(
                "Cortex XDR saw psexesvc.exe service creation on FIN-WS-118 after an inbound admin$ "
                "connection from FIN-LT-204."
            ),
            observables=[
                observable("hostname", "FIN-WS-118", "Remote host receiving service creation"),
                observable("hostname", "FIN-LT-204", "Originating host"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Endpoint",
            source="CrowdStrike Falcon",
            title="Shadow copy deletion attempt on finance workstation",
            severity=4,
            date_ms=ts(13, 29),
            description=(
                "CrowdStrike detected vssadmin.exe Delete Shadows /All /Quiet executed on FIN-WS-118 "
                "under a token derived from b.smith."
            ),
            observables=[
                observable("hostname", "FIN-WS-118", "Host with shadow copy deletion"),
                observable("username", "b.smith", "Associated identity"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Network",
            source="Zscaler Internet Access",
            title="HTTPS beaconing to ransomware staging domain",
            severity=3,
            date_ms=ts(13, 36),
            description=(
                "Zscaler logged FIN-WS-118 reaching hxxps://cdn-helpdesk-portal[.]com/api/v1/checkin "
                "every 180 seconds."
            ),
            observables=[
                observable("domain", "cdn-helpdesk-portal.com", "Beaconing domain"),
                observable("hostname", "FIN-WS-118", "Impacted endpoint"),
            ],
        ),
        EventSpec(
            alert_type="Endpoint",
            source="Microsoft Defender for Endpoint",
            title="Mass file rename behavior on finance share",
            severity=4,
            date_ms=ts(13, 44),
            description=(
                "Defender for Endpoint raised a ransomware behavior alert when FIN-WS-118 renamed "
                "finance files on \\\\FS-FIN-01\\Finance\\AP and \\\\FS-FIN-01\\Finance\\Treasury "
                "using the .locked2024 extension."
            ),
            observables=[
                observable("hostname", "FIN-WS-118", "Host performing renames"),
                observable("file", "\\\\FS-FIN-01\\Finance\\AP", "Primary impacted share"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="SIEM",
            source="Splunk Enterprise Security",
            title="Correlated ransomware precursor activity in finance",
            severity=4,
            date_ms=ts(13, 52),
            description=(
                "Splunk Enterprise Security correlation search linked the phishing click, risky sign-ins, "
                "PowerShell execution, SMB spread and shadow copy deletion to one finance incident."
            ),
            observables=[
                observable("username", "b.smith", "Correlated user"),
                observable("hostname", "FIN-LT-204", "Initial access host"),
                observable("hostname", "FIN-WS-118", "Encryption host"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Backup",
            source="Rubrik Security Cloud",
            title="Backup tampering against finance file server",
            severity=4,
            date_ms=ts(14, 1),
            description=(
                "Rubrik Security Cloud recorded failed deletion and retention-change attempts against "
                "snapshots for FS-FIN-01 from an account tied to b.smith."
            ),
            observables=[
                observable("hostname", "FS-FIN-01", "Protected asset"),
                observable("username", "b.smith", "Account seen in API actions"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Endpoint",
            source="Microsoft Defender for Endpoint",
            title="Ransom note dropped on finance endpoints",
            severity=4,
            date_ms=ts(14, 10),
            description=(
                "Defender for Endpoint observed creation of README_RECOVER_FILES.txt across "
                "FIN-WS-118 and FIN-WS-221 after encryption activity on finance shares."
            ),
            observables=[
                observable("file", "C:\\README_RECOVER_FILES.txt", "Ransom note name"),
                observable("hostname", "FIN-WS-221", "Second impacted workstation"),
            ],
            tlp=3,
        ),
    ]


def campaign_b_specs() -> List[EventSpec]:
    return [
        EventSpec(
            alert_type="Identity",
            source="Microsoft Entra ID Protection",
            title="Unusual after-hours sign-in to HR applications",
            severity=3,
            date_ms=ts(12, 18),
            description=(
                "Microsoft Entra ID Protection generated a medium-risk sign-in for h.potter from "
                "a residential ISP in Campinas against Workday and SharePoint Online."
            ),
            observables=[
                observable("username", "h.potter", "HR employee account"),
                observable("ip", "177.52.19.144", "Residential source IP"),
            ],
        ),
        EventSpec(
            alert_type="Cloud",
            source="Microsoft Defender for Cloud Apps",
            title="Mass download from HR compensation site",
            severity=3,
            date_ms=ts(12, 27),
            description=(
                "Defender for Cloud Apps recorded h.potter downloading 186 files from "
                "the SharePoint path HR/Compensation/2024 during one session."
            ),
            observables=[
                observable("username", "h.potter", "User performing bulk download"),
                observable(
                    "file",
                    "https://tenant.sharepoint.com/sites/HR/Compensation/2024",
                    "Sensitive SharePoint path",
                ),
            ],
        ),
        EventSpec(
            alert_type="Endpoint",
            source="Cortex XDR",
            title="Archive creation of salary data on HR laptop",
            severity=3,
            date_ms=ts(12, 36),
            description=(
                "Cortex XDR detected 7z.exe creating C:\\Users\\h.potter\\Downloads\\Q1_comp_review.7z "
                "on HR-LT-118 from HR compensation files."
            ),
            observables=[
                observable("hostname", "HR-LT-118", "Endpoint creating archive"),
                observable("file", "C:\\Users\\h.potter\\Downloads\\Q1_comp_review.7z", "Created archive"),
            ],
        ),
        EventSpec(
            alert_type="Endpoint",
            source="CrowdStrike Falcon",
            title="Removable media mounted on HR laptop",
            severity=3,
            date_ms=ts(12, 43),
            description=(
                "CrowdStrike Falcon saw a newly inserted SanDisk Extreme USB device on HR-LT-118 "
                "followed by writes to removable media."
            ),
            observables=[
                observable("hostname", "HR-LT-118", "Endpoint with USB activity"),
                observable("username", "h.potter", "Logged-on user"),
            ],
        ),
        EventSpec(
            alert_type="DLP",
            source="Netskope",
            title="Upload to personal Dropbox from HR endpoint",
            severity=4,
            date_ms=ts(12, 51),
            description=(
                "Netskope observed h.potter uploading Q1_comp_review.7z from HR-LT-118 to an "
                "unsanctioned personal Dropbox tenant over HTTPS."
            ),
            observables=[
                observable("username", "h.potter", "User tied to upload"),
                observable("domain", "dropbox.com", "Destination cloud app"),
                observable("file", "Q1_comp_review.7z", "Archive uploaded"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Network",
            source="Cisco Secure Firewall",
            title="Large outbound transfer to personal cloud storage",
            severity=3,
            date_ms=ts(12, 59),
            description=(
                "Cisco Secure Firewall logged 1.2 GB of outbound HTTPS from HR-LT-118 to Dropbox "
                "IP space over 26 minutes."
            ),
            observables=[
                observable("hostname", "HR-LT-118", "Source endpoint"),
                observable("ip", "162.125.66.19", "Dropbox destination IP"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Endpoint",
            source="Microsoft Defender for Endpoint",
            title="Sensitive HR files accessed after midnight-equivalent off-hours",
            severity=3,
            date_ms=ts(13, 12),
            description=(
                "Defender for Endpoint tracked h.potter opening files under "
                "\\\\FS-HR-02\\Compensation\\2024\\Salary_Adjustments outside the employee's normal schedule."
            ),
            observables=[
                observable("hostname", "HR-LT-118", "Endpoint accessing files"),
                observable(
                    "file",
                    "\\\\FS-HR-02\\Compensation\\2024\\Salary_Adjustments",
                    "Sensitive network path",
                ),
            ],
        ),
        EventSpec(
            alert_type="SIEM",
            source="Splunk Enterprise Security",
            title="Correlation: HR data access and exfil indicators",
            severity=3,
            date_ms=ts(13, 21),
            description=(
                "Splunk ES notable grouped the Entra sign-in, SharePoint downloads, archive creation, "
                "USB insertion and Dropbox upload into one insider-risk sequence for h.potter."
            ),
            observables=[
                observable("username", "h.potter", "Correlated identity"),
                observable("hostname", "HR-LT-118", "Primary endpoint"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="DLP",
            source="Microsoft Purview",
            title="Salary workbook sent to personal webmail draft",
            severity=4,
            date_ms=ts(13, 34),
            description=(
                "Microsoft Purview DLP detected HR_L3_Salary_Adjustments.xlsx attached to a draft "
                "addressed to harry.personal@proton.me in Outlook Web."
            ),
            observables=[
                observable("mail", "harry.personal@proton.me", "Personal destination mailbox"),
                observable("file", "HR_L3_Salary_Adjustments.xlsx", "Sensitive attachment"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Cloud",
            source="Microsoft Defender for Cloud Apps",
            title="Repeated download of compensation exports",
            severity=3,
            date_ms=ts(13, 45),
            description=(
                "Defender for Cloud Apps observed h.potter exporting another batch of compensation "
                "reports from the SharePoint HR site."
            ),
            observables=[
                observable("username", "h.potter", "User account"),
                observable(
                    "file",
                    "https://tenant.sharepoint.com/sites/HR/Compensation/2024/Q2_Planning",
                    "Downloaded site path",
                ),
            ],
        ),
        EventSpec(
            alert_type="Network",
            source="Zscaler Internet Access",
            title="Connection to personal cloud storage upload endpoint",
            severity=3,
            date_ms=ts(13, 54),
            description=(
                "Zscaler logged HR-LT-118 sending multipart HTTPS POST requests to "
                "content.dropboxapi.com and api.dropboxapi.com."
            ),
            observables=[
                observable("hostname", "HR-LT-118", "Source endpoint"),
                observable("domain", "content.dropboxapi.com", "Upload endpoint"),
            ],
        ),
        EventSpec(
            alert_type="Endpoint",
            source="Cortex XDR",
            title="Archive split into password-protected volumes",
            severity=4,
            date_ms=ts(14, 2),
            description=(
                "Cortex XDR identified 7z.exe creating password-protected multi-volume archives "
                "named comp_apr_2024.7z.001 through .004 in C:\\Users\\h.potter\\Desktop\\Personal."
            ),
            observables=[
                observable("hostname", "HR-LT-118", "Host performing archive split"),
                observable(
                    "file",
                    "C:\\Users\\h.potter\\Desktop\\Personal\\comp_apr_2024.7z.001",
                    "First archive volume",
                ),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="Endpoint",
            source="CrowdStrike Falcon",
            title="USB write burst after archive creation",
            severity=3,
            date_ms=ts(14, 8),
            description=(
                "CrowdStrike observed 612 MB written from HR-LT-118 to a Kingston DataTraveler USB "
                "device within minutes of the password-protected archive creation."
            ),
            observables=[
                observable("hostname", "HR-LT-118", "Endpoint writing to USB"),
                observable("username", "h.potter", "Associated employee"),
            ],
        ),
        EventSpec(
            alert_type="DLP",
            source="Netskope",
            title="Upload of HR archive to personal Dropbox resumed",
            severity=4,
            date_ms=ts(14, 16),
            description=(
                "Netskope captured h.potter uploading comp_apr_2024.7z.001 from HR-LT-118 "
                "to the same personal Dropbox tenant seen earlier that afternoon."
            ),
            observables=[
                observable("username", "h.potter", "User performing upload"),
                observable("file", "comp_apr_2024.7z.001", "Archive volume uploaded"),
            ],
            tlp=3,
        ),
        EventSpec(
            alert_type="SIEM",
            source="Splunk Enterprise Security",
            title="Insider data exfiltration pattern against HR compensation data",
            severity=4,
            date_ms=ts(14, 24),
            description=(
                "Splunk Enterprise Security correlation search linked the day's off-hours sign-ins, "
                "mass downloads, local archiving, removable media use and personal cloud uploads "
                "around h.potter and HR-LT-118."
            ),
            observables=[
                observable("username", "h.potter", "Correlated subject"),
                observable("hostname", "HR-LT-118", "Primary endpoint"),
            ],
            tlp=3,
        ),
    ]


def noise_specs(source_refs: List[str]) -> List[Dict[str, Any]]:
    templates = [
        {
            "alert_type": "Identity", "source": "Okta",
            "title": "Sign-in from unrecognized geographic location",
            "severities": [2, 3, 2, 3, 3],
            "entity_type": "username",
            "entities": ["a.ferreira", "l.melo", "c.ramos", "t.almeida", "j.gomes"],
            "entity_msg": "Authenticating user", "entity_ioc": False,
            "secondary_type": "hostname",
            "secondary": ["VPN-GW-01", "VPN-GW-02", "SSO-EDGE-01", "SSO-EDGE-02", "VPN-GW-03"],
            "secondary_msg": "Gateway appliance", "secondary_ioc": False,
            "extra_type": "ip",
            "extra_values": [None, None, "179.23.55.80", None, "187.45.10.33"],
            "extra_msg": "Source IP address", "extra_ioc": False,
            "weight": 8,
            "description": (
                "Okta detected a sign-in for {entity} from {ip}. The source IP geolocated to a "
                "different state than the user's baseline. Authentication completed using MFA from "
                "a device registered in Intune."
            ),
        },
        {
            "alert_type": "Vulnerability", "source": "Qualys VMDR",
            "title": "Service enumeration and port scanning on production host",
            "severities": [1, 2, 1, 1, 2],
            "entity_type": "hostname",
            "entities": ["APP-SRV-12", "DB-SQL-04", "WEB-PRD-07", "ERP-API-02", "FS-OPS-01"],
            "entity_msg": "Scanned host", "entity_ioc": False,
            "secondary_type": "ip",
            "secondary": ["10.10.5.20", "10.10.5.21", "10.10.5.22", "10.10.5.23", "10.10.5.24"],
            "secondary_msg": "Scanner source IP", "secondary_ioc": False,
            "weight": 3,
            "description": (
                "Qualys VMDR recorded scan activity from {secondary} targeting {entity}. Multiple "
                "TCP ports were probed including 445, 3389, and 5985. The source IP belongs to the "
                "vulnerability management VLAN."
            ),
        },
        {
            "alert_type": "Endpoint", "source": "Microsoft Defender for Endpoint",
            "title": "PowerShell execution with elevated privileges on endpoint",
            "severities": [3, 2, 3, 4, 2],
            "entity_type": "hostname",
            "entities": ["FIN-WS-042", "HR-WS-019", "ENG-LT-223", "OPS-WS-301", "MKT-LT-114"],
            "entity_msg": "Executing endpoint", "entity_ioc": False,
            "secondary_type": "username",
            "secondary": ["svc_sccm", "svc_patch", "svc_tanium", "svc_itops", "svc_softdist"],
            "secondary_msg": "Service account", "secondary_ioc": False,
            "extra_type": "file",
            "extra_values": [None, "C:\\Windows\\SCCM\\Scripts\\deploy.ps1", None, None, "C:\\ProgramData\\Tanium\\stage.ps1"],
            "extra_msg": "Script path", "extra_ioc": False,
            "weight": 6,
            "description": (
                "Defender for Endpoint recorded PowerShell on {entity} launched under account "
                "{secondary}. The process tree shows a Configuration Manager client as the parent. "
                "The command line included encoded arguments and an InstallPackage cmdlet."
            ),
        },
        {
            "alert_type": "Backup", "source": "Veeam Backup & Replication",
            "title": "High-volume outbound data transfer detected",
            "severities": [1, 1, 2, 1, 2],
            "entity_type": "hostname",
            "entities": ["FS-FIN-01", "VM-ERP-02", "SQL-HR-01", "VM-WEB-09", "FS-ENG-03"],
            "entity_msg": "Backup source", "entity_ioc": False,
            "secondary_type": "ip",
            "secondary": ["172.18.40.21", "172.18.40.22", "172.18.40.23", "172.18.40.24", "172.18.40.25"],
            "secondary_msg": "Repository destination", "secondary_ioc": False,
            "weight": 2,
            "description": (
                "Veeam Backup & Replication reported a large data transfer from {entity} to "
                "{secondary}. Transfer volume exceeded the short-term rolling average. The job ran "
                "during the configured replication window."
            ),
        },
        {
            "alert_type": "Network", "source": "Cisco Secure Firewall",
            "title": "Internal network port scanning from corporate subnet",
            "severities": [2, 1, 2, 3, 2],
            "entity_type": "ip",
            "entities": ["10.60.10.15", "10.60.10.16", "10.60.10.17", "10.60.10.18", "10.60.10.19"],
            "entity_msg": "Scanner source", "entity_ioc": False,
            "secondary_type": "hostname",
            "secondary": ["Nessus-SCAN-01", "Nessus-SCAN-02", "Rapid7-SCAN-01", "Rapid7-SCAN-02", "SEC-SCAN-INT-01"],
            "secondary_msg": "Scanner appliance", "secondary_ioc": False,
            "extra_type": "ip",
            "extra_values": [None, None, None, "10.42.3.80", None],
            "extra_msg": "Probed destination", "extra_ioc": False,
            "weight": 4,
            "description": (
                "Cisco Secure Firewall logged {secondary} probing multiple internal ports from source "
                "IP {entity}. The scan targeted management interfaces across three VLANs. The source "
                "system is registered in the vulnerability management VLAN."
            ),
        },
        {
            "alert_type": "Email", "source": "Google Workspace Security",
            "title": "Inbound email with suspicious sender domain",
            "severities": [2, 3, 2, 2, 3],
            "entity_type": "mail",
            "entities": [
                "finance@corp.local", "procurement@corp.local", "hr@corp.local",
                "helpdesk@corp.local", "legal@corp.local",
            ],
            "entity_msg": "Recipient mailbox", "entity_ioc": False,
            "secondary_type": "domain",
            "secondary": [
                "invoice-portal.co", "docs-review.net", "shipment-alerts.com",
                "secure-signature.org", "vendor-update.info",
            ],
            "secondary_msg": "Sender domain", "secondary_ioc": True,
            "extra_type": "url",
            "extra_values": [
                "https://invoice-portal.co/view/doc-2024", None,
                "https://shipment-alerts.com/track/ref-119",
                "https://secure-signature.org/sign/pending", None,
            ],
            "extra_msg": "Embedded URL", "extra_ioc": True,
            "weight": 5,
            "description": (
                "Google Workspace flagged an inbound message targeting {entity} from domain "
                "{secondary}. DMARC validation failed and the message body contained a URL with "
                "brand impersonation characteristics."
            ),
        },
        {
            "alert_type": "Endpoint", "source": "CrowdStrike Falcon",
            "title": "Remote administration tool execution via SMB",
            "severities": [3, 3, 2, 3, 4],
            "entity_type": "hostname",
            "entities": ["IT-ADM-01", "IT-ADM-02", "IT-ADM-03", "IT-ADM-04", "IT-ADM-05"],
            "entity_msg": "Admin workstation", "entity_ioc": False,
            "secondary_type": "hostname",
            "secondary": ["FIN-WS-118", "HR-LT-052", "OPS-WS-010", "ENG-LT-014", "MKT-WS-077"],
            "secondary_msg": "Target endpoint", "secondary_ioc": False,
            "weight": 4,
            "description": (
                "CrowdStrike Falcon detected PsExec-style remote execution when {entity} connected "
                "to {secondary} over admin$ share. A service was created on the remote host and "
                "executed commands via cmd.exe."
            ),
        },
        {
            "alert_type": "DLP", "source": "Netskope",
            "title": "File upload to cloud storage platform detected",
            "severities": [2, 3, 2, 1, 3],
            "entity_type": "username",
            "entities": ["s.souza", "m.castro", "r.nunes", "f.lima", "g.oliveira"],
            "entity_msg": "Uploading user", "entity_ioc": False,
            "secondary_type": "domain",
            "secondary": [
                "box.corp.local", "tenant-my.sharepoint.com", "onedrive.corp.local",
                "box.corp.local", "tenant-my.sharepoint.com",
            ],
            "secondary_msg": "Cloud storage destination", "secondary_ioc": False,
            "extra_type": "file",
            "extra_values": ["Q3_forecast.xlsx", None, None, "project_plan.docx", None],
            "extra_msg": "Uploaded file", "extra_ioc": False,
            "weight": 5,
            "description": (
                "Netskope identified {entity} uploading files to {secondary}. The upload session "
                "involved multiple file transfers over HTTPS to a cloud storage endpoint."
            ),
        },
        {
            "alert_type": "Identity", "source": "Microsoft Entra ID Protection",
            "title": "Impossible travel sign-in anomaly detected",
            "severities": [3, 2, 3, 4, 3],
            "entity_type": "username",
            "entities": ["p.freitas", "d.araujo", "k.barbosa", "n.teixeira", "v.cardoso"],
            "entity_msg": "Flagged user", "entity_ioc": False,
            "secondary_type": "ip",
            "secondary": ["45.182.21.10", "45.182.21.11", "45.182.21.12", "45.182.21.13", "45.182.21.14"],
            "secondary_msg": "Anomalous source IP", "secondary_ioc": False,
            "extra_type": "ip",
            "extra_values": ["200.150.30.5", None, None, None, "200.150.30.88"],
            "extra_msg": "Previous session IP", "extra_ioc": False,
            "weight": 8,
            "description": (
                "Microsoft Entra ID Protection flagged {entity} for impossible travel. A session "
                "shift was observed between IPs in different geographic regions, including "
                "{secondary}. The sign-in used cached tokens via a GlobalProtect VPN tunnel."
            ),
        },
        {
            "alert_type": "SIEM", "source": "Splunk Enterprise Security",
            "title": "Repeated authentication failures for service account",
            "severities": [2, 3, 3, 2, 3],
            "entity_type": "username",
            "entities": ["svc_oracle", "svc_backup", "svc_etl", "svc_batch", "svc_monitor"],
            "entity_msg": "Failing account", "entity_ioc": False,
            "secondary_type": "hostname",
            "secondary": ["APP-SRV-01", "APP-SRV-02", "DB-SQL-02", "ERP-JOB-01", "MON-CORE-01"],
            "secondary_msg": "Target server", "secondary_ioc": False,
            "extra_type": "ip",
            "extra_values": ["10.40.5.15", None, None, "10.40.5.20", None],
            "extra_msg": "Authentication source IP", "extra_ioc": False,
            "weight": 6,
            "description": (
                "Splunk ES correlated multiple failed authentication attempts for {entity} on "
                "{secondary}. The failures occurred over a 15-minute window and triggered the "
                "brute-force detection threshold."
            ),
        },
        {
            "alert_type": "Network", "source": "Darktrace",
            "title": "Anomalous outbound data transfer volume",
            "severities": [2, 1, 2, 3, 1],
            "entity_type": "hostname",
            "entities": ["DR-SYNC-01", "DR-SYNC-02", "DR-SYNC-03", "DR-SYNC-04", "DR-SYNC-05"],
            "entity_msg": "Transferring host", "entity_ioc": False,
            "secondary_type": "ip",
            "secondary": ["10.90.2.41", "10.90.2.42", "10.90.2.43", "10.90.2.44", "10.90.2.45"],
            "secondary_msg": "DR replication target", "secondary_ioc": False,
            "weight": 3,
            "description": (
                "Darktrace flagged elevated outbound traffic from {entity} to {secondary}. "
                "The transfer volume exceeded the 30-day baseline by 340 percent. The destination "
                "IP belongs to the disaster recovery subnet."
            ),
        },
        {
            "alert_type": "Endpoint", "source": "Jamf Protect",
            "title": "Unsigned binary execution on macOS endpoint",
            "severities": [3, 2, 3, 4, 2],
            "entity_type": "hostname",
            "entities": ["MAC-FIN-14", "MAC-DES-03", "MAC-MKT-19", "MAC-EXEC-02", "MAC-ENG-08"],
            "entity_msg": "Affected Mac", "entity_ioc": False,
            "secondary_type": "username",
            "secondary": ["u.campos", "l.azevedo", "p.vieira", "e.martins", "c.brito"],
            "secondary_msg": "Logged-on user", "secondary_ioc": False,
            "extra_type": "file",
            "extra_values": ["/usr/local/bin/helper_agent", None, None, "/usr/local/bin/updater_svc", None],
            "extra_msg": "Unsigned binary path", "extra_ioc": True,
            "weight": 2,
            "description": (
                "Jamf Protect detected an unsigned helper binary running on {entity} under user "
                "{secondary}. The binary was launched from /usr/local/bin/ and made network "
                "connections to an internal distribution server."
            ),
        },
        {
            "alert_type": "Vulnerability", "source": "Rapid7 InsightVM",
            "title": "RDP and WinRM connection probing detected",
            "severities": [2, 1, 2, 3, 2],
            "entity_type": "hostname",
            "entities": ["DC-01", "DC-02", "APP-CRM-01", "APP-CRM-02", "FILE-OPS-02"],
            "entity_msg": "Probed host", "entity_ioc": False,
            "secondary_type": "ip",
            "secondary": ["10.10.8.31", "10.10.8.32", "10.10.8.33", "10.10.8.34", "10.10.8.35"],
            "secondary_msg": "Probing source IP", "secondary_ioc": False,
            "weight": 4,
            "description": (
                "Rapid7 InsightVM logged RDP and WinRM connection attempts from {secondary} toward "
                "{entity}. The probing targeted standard management ports 3389 and 5985."
            ),
        },
        {
            "alert_type": "Endpoint", "source": "SentinelOne",
            "title": "Suspicious script interpreter chain at logon",
            "severities": [3, 2, 4, 3, 2],
            "entity_type": "hostname",
            "entities": ["BR-WS-011", "BR-WS-012", "BR-WS-013", "BR-WS-014", "BR-WS-015"],
            "entity_msg": "Affected workstation", "entity_ioc": False,
            "secondary_type": "file",
            "secondary": ["logon.ps1", "printer_map.vbs", "vpn_bootstrap.ps1", "drives.vbs", "teams_cleanup.ps1"],
            "secondary_msg": "Logon script", "secondary_ioc": False,
            "extra_type": "file",
            "extra_values": [None, "C:\\Windows\\Temp\\print_config.dat", None, None, "C:\\Windows\\Temp\\teams_cache.dat"],
            "extra_msg": "Dropped temp file", "extra_ioc": False,
            "weight": 6,
            "description": (
                "SentinelOne detected wscript.exe spawning powershell.exe on {entity} during user "
                "logon. The parent script was {secondary}, which executed encoded commands and made "
                "registry modifications."
            ),
        },
    ]

    assignments: List[tuple] = []
    for t_idx, t in enumerate(templates):
        for v in range(t["weight"]):
            assignments.append((t_idx, v % 5))

    n_standard = len(assignments)
    alerts: List[Dict[str, Any]] = []
    total_span_minutes = 531

    for i in range(n_standard):
        source_ref = source_refs[i]
        t_idx, variant = assignments[i]
        t = templates[t_idx]
        entity = t["entities"][variant]
        secondary = t["secondary"][variant]
        severity = t["severities"][variant]
        date_ms = int(
            (NOISE_TIMELINE_START + timedelta(
                minutes=round(i * total_span_minutes / max(len(source_refs) - 1, 1))
            )).timestamp() * 1000
        )
        ip = f"179.{20 + (i % 7)}.{40 + ((i * 3) % 50)}.{10 + ((i * 7) % 200)}"
        description = t["description"].format(entity=entity, secondary=secondary, ip=ip)

        observables = [
            observable(t["entity_type"], entity, t["entity_msg"], ioc=t["entity_ioc"]),
            observable(t["secondary_type"], secondary, t["secondary_msg"], ioc=t["secondary_ioc"]),
        ]

        if "extra_type" in t:
            extra_val = t["extra_values"][variant]
            if extra_val is not None:
                observables.append(
                    observable(t["extra_type"], extra_val, t["extra_msg"], ioc=t.get("extra_ioc", False))
                )

        alerts.append(alert_from_spec(source_ref, EventSpec(
            alert_type=t["alert_type"], source=t["source"], title=t["title"],
            description=description, severity=severity, date_ms=date_ms,
            observables=observables,
        )))

    overlap_specs = [
        EventSpec(
            alert_type="Vulnerability", source="Qualys VMDR",
            title="Service enumeration and port scanning on production host",
            description=(
                "Qualys VMDR recorded scan activity from 10.10.5.20 targeting FIN-LT-204. "
                "Ports 445, 3389, and 5985 were probed during a scheduled assessment window."
            ),
            severity=1,
            date_ms=int((NOISE_TIMELINE_START + timedelta(minutes=120)).timestamp() * 1000),
            observables=[
                observable("hostname", "FIN-LT-204", "Scanned host"),
                observable("ip", "10.10.5.20", "Scanner source IP"),
            ],
        ),
        EventSpec(
            alert_type="Endpoint", source="CrowdStrike Falcon",
            title="Remote administration tool execution via SMB",
            description=(
                "CrowdStrike Falcon detected PsExec-style remote execution when IT-ADM-02 "
                "connected to HR-LT-118 over admin$ share for scheduled patch deployment."
            ),
            severity=3,
            date_ms=int((NOISE_TIMELINE_START + timedelta(minutes=240)).timestamp() * 1000),
            observables=[
                observable("hostname", "IT-ADM-02", "Admin workstation"),
                observable("hostname", "HR-LT-118", "Target endpoint"),
            ],
        ),
        EventSpec(
            alert_type="Backup", source="Veeam Backup & Replication",
            title="High-volume outbound data transfer detected",
            description=(
                "Veeam Backup & Replication reported a large incremental backup from FS-FIN-01 "
                "to 172.18.40.21. Transfer volume exceeded the rolling average by 180 percent."
            ),
            severity=1,
            date_ms=int((NOISE_TIMELINE_START + timedelta(minutes=360)).timestamp() * 1000),
            observables=[
                observable("hostname", "FS-FIN-01", "Backup source"),
                observable("ip", "172.18.40.21", "Repository destination"),
            ],
        ),
        EventSpec(
            alert_type="Identity", source="Okta",
            title="Sign-in from unrecognized geographic location",
            description=(
                "Okta detected a sign-in for b.smith from 179.20.88.15. The source IP "
                "geolocated to Campinas. MFA challenge completed using registered Yubikey."
            ),
            severity=2,
            date_ms=int((NOISE_TIMELINE_START + timedelta(minutes=480)).timestamp() * 1000),
            observables=[
                observable("username", "b.smith", "Authenticating user"),
                observable("ip", "179.20.88.15", "Source IP address"),
            ],
        ),
    ]
    for j, spec in enumerate(overlap_specs):
        alerts.append(alert_from_spec(source_refs[n_standard + j], spec))

    return alerts


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    camp_a_path = ROUND1_DIR / "campaing-a" / "finance-ransomware-alerts.json"
    camp_b_path = ROUND1_DIR / "campaing-b" / "hr-insider-threat-alerts.json"
    noise_path = ROUND1_DIR / "noise" / "noise-alerts.json"

    camp_a_ids = load_existing_ids(camp_a_path)
    camp_b_ids = load_existing_ids(camp_b_path)
    noise_ids = load_existing_ids(noise_path)

    camp_a_events = [alert_from_spec(source_ref, spec) for source_ref, spec in zip(camp_a_ids, campaign_a_specs(), strict=True)]
    camp_b_events = [alert_from_spec(source_ref, spec) for source_ref, spec in zip(camp_b_ids, campaign_b_specs(), strict=True)]
    noise_events = noise_specs(noise_ids)

    write_json(camp_a_path, camp_a_events)
    write_json(camp_b_path, camp_b_events)
    write_json(noise_path, noise_events)

    manifest = {
        "schema": "Same as input/round2 (TheHive-style alert JSON)",
        "scenario": "Synthetic SOC dataset with realistic vendor products, single-product tags, and interleaved campaign/noise events within one day.",
        "derived_from": "round1 redesign for realistic SOC telemetry",
        "anchor_utc": "2024-11-27",
        "window_days": 1,
        "window_end_utc": "2024-11-27",
        "timeline": "All 100 alerts are distributed across a single day on 2024-11-27 UTC, with noise, finance-ransomware activity, and HR insider-exfil activity intentionally mixed in time.",
        "source_convention": "source uses real product names, such as Cortex XDR, Google Workspace Security, Netskope, and CrowdStrike Falcon.",
        "tag_convention": "tags contains exactly one value: the same product name used in source.",
        "source_ref_policy": "Existing round1 sourceRef values were preserved so historical references remain stable.",
        "files": {
            "campaing-a/finance-ransomware-alerts.json": len(camp_a_events),
            "campaing-b/hr-insider-threat-alerts.json": len(camp_b_events),
            "noise/noise-alerts.json": len(noise_events),
        },
    }
    write_json(ROUND1_DIR / "manifest.json", manifest)


if __name__ == "__main__":
    main()
