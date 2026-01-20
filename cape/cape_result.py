import json
import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from hashlib import sha256
from ipaddress import IPv4Network, ip_address, ip_network
from logging import getLogger, DEBUG
from re import compile as re_compile
from re import match as re_match
from re import search, sub, findall
from typing import Any, Dict, List, Optional, Set, Tuple
import pefile
import lief
from peutils import is_valid
from time import strptime
from cerberus import Validator

from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.common.attack_map import revoke_map
from assemblyline.common.identify import CUSTOM_BATCH_ID, CUSTOM_PS1_ID
from assemblyline.common.isotime import epoch_to_local_with_ms, format_time, local_to_local_with_ms, LOCAL_FMT_WITH_MS, ensure_time_format, iso_to_epoch
from assemblyline.common.net import is_valid_ip, is_valid_domain
from assemblyline.common.str_utils import safe_str, truncate
from assemblyline.odm.base import FULL_URI, DOMAIN_REGEX, IP_REGEX, IPV4_REGEX, URI_PATH, IPV6_REGEX, PORT_REGEX
from assemblyline.odm.models.ontology.results import Process as ProcessModel
from assemblyline.odm.models.ontology.results import Sandbox as SandboxModel
from assemblyline.odm.models.ontology.results import Signature as SignatureModel
from assemblyline.odm.models.ontology.results.network import NetworkConnection as NetworkConnectionModel
from assemblyline_service_utilities.common.dynamic_service_helper import (
    MIN_DOMAIN_CHARS,
    MIN_TIME,
    Attribute,
    NetworkConnection,
    NetworkHTTP,
    OntologyResults,
    Process,
    Sandbox,
    Signature,
    attach_dynamic_ontology,
    extract_iocs_from_text_blob,
)
from assemblyline_service_utilities.common.network_helper import convert_url_to_https
from assemblyline_service_utilities.common.safelist_helper import is_tag_safelisted, contains_safelisted_value
from assemblyline_service_utilities.common.tag_helper import add_tag
from assemblyline_v4_service.common.result import (
    Heuristic,
    KVSectionBody,
    ResultKeyValueSection,
    ResultMultiSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
    TextSectionBody,
    ResultSandboxSection,
    SandboxAnalysisMetadata,
    SandboxAttackItem,
    SandboxNetflowItem,
    SandboxNetworkDNS,
    SandboxNetworkHTTP,
    SandboxNetworkSMTP,
    SandboxProcessItem,
    SandboxSignatureItem,
)
from cape.signatures import CAPE_DROPPED_SIGNATURES, SIGNATURE_TO_ATTRIBUTE_ACTION_MAP, get_category
from cape.standard_http_headers import STANDARD_HTTP_HEADERS
from multidecoder.decoders.shell import (
    find_cmd_strings,
    find_powershell_strings,
    get_cmd_command,
    get_powershell_command,
)

al_log.init_logging("service.cape.cape_result")
log = getLogger("assemblyline.service.cape.cape_result")
# Global variable used for containing the system safelist
global_safelist: Optional[Dict[str, Dict[str, List[str]]]] = None

#Processing values
SCORE_TRANSLATION = {
    0: 0,
    1: 10,
    2: 30,
    3: 50,
    4: 500,
    5: 750,
    6: 1000,
    7: 1000,
    8: 1000,
}  # dead_host signature
Classification = forge.get_classification()
API_CALLS = [
    {
        "event": "Load",
        "object": "DLL",
        "apis": ["LdrLoadDll", "LoadLibraryA", "LoadLibraryW"],
        "arguments": [("DLLName", "filename")],
    },
    {
        "event": "Load",
        "object": "DLL",
        "apis": ["LoadLibraryExA", "LoadLibraryExW"],
        "arguments": [("DLLName", "lplibfilename")],
    },
    {
        "event": "Load",
        "object": "DLL",
        "apis": ["LdrGetDllHandle"],
        "arguments": [("DLLName", "filename")],
    },
    {
        "event": "Load",
        "object": "Function",
        "apis": ["LdrGetProcedureAddress"],
        "arguments": [("FunctionName", "functionname"), ("Module", "modulename"), ("Ordinal", "ordinal")],
    },
    {
        "event": "Load",
        "object": "Function",
        "apis": ["LdrGetProcedureAddressForCaller"],
        "arguments": [("FunctionName", "functionname")],
    },
    {
        "event": "Load",
        "object": "Driver",
        "apis": ["NtLoadDriver"],
        "arguments": [("DriverName", "driverservicename")],
    },
    {
        "event": "Control",
        "object": "Driver",
        "apis": ["NtDeviceIoControlFile"],
        "arguments": [("Handle", "filehandle"), ("HandleName", "fname"), ("ControlCode", "iocontrolcode")],
    },
    {
        "event": "Create",
        "object": "Service",
        "apis": ["CreateServiceA", "CreateServiceW"],
        "arguments": [("Service", "servicename"), ("Target", "binarypathname")],
    },
    {
        "event": "Start",
        "object": "Service",
        "apis": ["StartServiceA", "StartServiceW"],
        "arguments": [("Service", "servicename"), ("Arguments", "arguments")],
    },
    {
        "event": "Control",
        "object": "Service",
        "apis": ["ControlService"],
        "arguments": [("Service", "servicename"), ("ControlCode", "controlcode")],
    },
    {
        "event": "Write",
        "object": "Registry",
        "apis": ["RegSetValueExA", "RegSetValueExW"],
        "arguments": [("RegKey", "fullname"), ("Content", "Buffer")],
    },
    {
        "event": "Write",
        "object": "Registry",
        "apis": ["RegCreateKeyExA", "RegCreateKeyExW"],
        "arguments": [("RegKey", "fullname")],
    },
    {
        "event": "Read",
        "object": "Registry",
        "apis": ["RegQueryValueExA", "RegQueryValueExW"],
        "arguments": [("RegKey", "fullname"), ("Content", "data")],
    },
    {
        "event": "Read",
        "object": "Registry",
        "apis": ["NtQueryValueKey"],
        "arguments": [("RegKey", "fullname"), ("Content", "information")],
    },
    {
        "event": "Read",
        "object": "Registry",
        "apis": ["RegOpenKeyExA", "RegOpenKeyExW"],
        "arguments": [("RegKey", "registry"), ("SubKey", "subkey"), ("FullName", "fullname")],
    },
    {
        "event": "Delete",
        "object": "Registry",
        "apis": ["RegDeleteKeyA", "RegDeleteKeyW", "RegDeleteValueA", "RegDeleteValueW", "NtDeleteValueKey"],
        "arguments": [("RegKey", "fullname"), ("SubKey", "subkey")],
    },
    {
        "event": "Delete",
        "object": "Registry",
        "apis": ["RegDeleteKeyExW", "RegDeleteKeyExA"],
        "arguments": [("RegKey", "fullname"), ("SubKey", "subkey")],
    },
    {
        "event": "Delete",
        "object": "Registry",
        "apis": ["NtDeleteKey"],
        "arguments": [("Handle", "keyhandle")],
    },
    {
        "event": "Create",
        "object": "Registry",
        "apis": ["NtCreateKey"],
        "arguments": [("Handle", "keyhandle")],
    },
    {
        "event": "Open",
        "object": "Registry",
        "apis": ["NtOpenKey", "NtOpenKeyEx"],
        "arguments": [("Handle", "keyhandle")],
    },
    {
        "event": "Load",
        "object": "Registry",
        "apis": ["NtLoadKey", "NtLoadKey2", "NtLoadKeyEx"],
        "arguments": [("Handle", "targetkeyhandle"), ("Key", "targetkey"), ("Source", "sourcefile")],
    },
    {
        "event": "Write",
        "object": "Registry",
        "apis": ["NtSetValueKey"],
        "arguments": [("Handle", "keyhandle"), ("Value", "valuename")],
    },
    {
        "event": "Read",
        "object": "Registry",
        "apis": ["NtQueryValueKey", "NtQueryMultipleValueKey"],
        "arguments": [("Handle", "keyhandle"), ("Value", "valuename")],
    },
    {
        "event": "Connect",
        "object": "Network",
        "apis": ["connect", "connectex", "WSAConnect"],
        "arguments": [("IP", "ip"), ("Port", "port")],
    },
    {
        "event": "Connect",
        "object": "Network",
        "apis": ["InternetConnectW", "InternetConnectA"],
        "arguments": [("HostName", "servername"), ("Port", "serverport"), ("Service", "service")],
    },
    {
        "event": "Connect",
        "object": "Network",
        "apis": ["WSAConnectByNameW"],
        "arguments": [("HostName", "nodename"), ("Service", "servicename")],
    },
    {
        "event": "Connect",
        "object": "Network",
        "apis": ["InternetOpenUrlA", "InternetOpenUrlW"],
        "arguments": [("URL", "url")],
    },
    {
        "event": "Connect",
        "object": "Network",
        "apis": ["WinHttpConnect"],
        "arguments": [("HostName", "servername"), ("Port", "serverport")],
    },
    {
        "event": "DNS",
        "object": "Network",
        "apis": ["getaddrinfo", "GetAddrInfoW"],
        "arguments": [("HostName", "nodename"), ("Service", "servicename")],
    },
    {
        "event": "DNS",
        "object": "Network",
        "apis": ["GetAddrInfoExW"],
        "arguments": [("HostName", "name"), ("Service", "servicename")],
    },
    {
        "event": "DNS",
        "object": "Network",
        "apis": ["gethostbyname"],
        "arguments": [("HostName", "name")],
    },
    {
        "event": "DNS",
        "object": "Network",
        "apis": ["DnsQuery_A", "DnsQuery_UTF8", "DnsQuery_W"],
        "arguments": [("HostName", "name"), ("Type", "type"), ("DNS", "dns servers")],
    },
    {
        "event": "Request_response",
        "object": "Network",
        "apis": ["send", "sendto", "recv", "recvfrom", "WSASend", "WSARecv"],
        "arguments": [("Buffer", "buffer")],
    },
    {
        "event": "Request_response",
        "object": "Network",
        "apis": ["URLDownloadToFileW", "URLDownloadToFileA", "URLDownloadToCacheFileW"],
        "arguments": [("URL", "url"), ("FileName", "filename")],
    },
    {
        "event": "Request_response",
        "object": "Network",
        "apis": ["InternetCrackUrlA", "InternetCrackUrlW"],
        "arguments": [("URL", "url")],
    },
    {
        "event": "Request_response",
        "object": "Network",
        "apis": ["WinHttpSendRequest", "WinHttpReceiveResponse"],
        "arguments": [("Handle", "InternetHandle")],
    },
    {
        "event": "Request_response",
        "object": "Network",
        "apis": ["HttpOpenRequestW", "HttpOpenRequestA"],
        "arguments": [("Handle", "InternetHandle"), ("Path", "path")],
    },
    {
        "event": "Request_response",
        "object": "Network",
        "apis": ["WSARecvFrom", "WSASendTo"],
        "arguments": [("Buffer", "buffer"), ("IP", "ip"), ("Port", "port")],
    },
    {
        "event": "Request_response",
        "object": "Network",
        "apis": ["WSASendMsg"],
        "arguments": [("Buffer", "msgbuffer"), ("IP", "ip"), ("Port", "port")],
    },
    {
        "event": "Request_response",
        "object": "Network",
        "apis": ["InternetReadFile", "InternetWriteFile"],
        "arguments": [("Buffer", "buffer"), ("Handle", "internethandle")],
    },
    {
        "event": "Proxying",
        "object": "Network",
        "apis": ["InternetOpenW"],
        "arguments": [("Proxy", "proxyname"), ("Bypass", "proxybypass")],
    },
    {
        "event": "Proxying",
        "object": "Network",
        "apis": ["WinHttpGetProxyForUrl"],
        "arguments": [("Handle", "sessionhandle"), ("URL", "url")],
    },
    {
        "event": "SSL",
        "object": "Crypt",
        "apis": ["SslEncryptPacket", "SslDecryptPacket"],
        "arguments": [("Buffer", "buffer")],
    },
    {
        "event": "Crypt_Decrypt",
        "object": "Crypt",
        "apis": ["CryptDecrypt", "CryptEncrypt"],
        "arguments": [("Buffer", "buffer"), ("Key", "cryptkey"), ("Hash", "crypthash")],
    },
    {
        "event": "Crypt_Decrypt",
        "object": "Crypt",
        "apis": ["BCryptDecrypt", "NCryptDecrypt", "NCryptEncrypt"],
        "arguments": [("Buffer", "output"), ("Key", "cryptkey"), ("Hash", "iv")],
    },
    {
        "event": "Crypt_Decrypt",
        "object": "Crypt",
        "apis": ["BCryptEncrypt"],
        "arguments": [("Buffer", "input"), ("Key", "cryptkey"), ("Hash", "iv")],
    },
    {
        "event": "Crypt_Decrypt",
        "object": "Crypt",
        "apis": ["CryptProtectData", "CryptUnprotectData", "CryptProtectMemory", "CryptUnprotectMemory", "CryptEncryptMessage"],
        "arguments": [("Buffer", "buffer")],
    },
    {
        "event": "Misc",
        "object": "DebugString",
        "apis": ["OutputDebugStringA", "OutputDebugStringW"],
        "arguments": [("Buffer", "outputstring")],
    },
    {
        "event": "Hooking",
        "object": "Function",
        "apis": ["SetWindowsHookExA", "SetWindowsHookExW"],
        "arguments": [("Identifier", "hookidentifier"), ("Address", "procedureaddress"), ("Module", "ModuleAddress"), ("Thread", "threadid")],
    },
    {
        "event": "Unhooking",
        "object": "Function",
        "apis": ["UnhookWindowsHookEx"],
        "arguments": [("Handle", "hookhandle")],
    },
    {
        "event": "Read_attributes",
        "object": "File",
        "apis": ["SHGetFileInfoW"],
        "arguments": [("Path", "path")],
    },
     {
        "event": "Write_attributes",
        "object": "File",
        "apis": ["NtSetInformationFile"],
        "arguments": [("Handle", "filehandle" ), ("Path", "handlename"), ("Information class", "fileinformationclass")],
    },
    {
        "event": "Execute",
        "object": "File",
        "apis": ["ShellExecuteExW", "ShellExecuteExA"],
        "arguments": [("Path", "filepath"), ("Parameters", "parameters")],
    },
    {
        "event": "Delete",
        "object": "File",
        "apis": ["NtDeleteFile", "DeleteFileA", "DeleteFileW"],
        "arguments": [("Path", "filename")],
    },
    {
        "event": "Move",
        "object": "File",
        "apis": ["MoveFileWithProgressW", "MoveFileWithProgressTransactedW"],
        "arguments": [("OldPath", "existingfilename"), ("NewPath", "newfilename")],
    },
    {
        "event": "Copy",
        "object": "File",
        "apis": ["CopyFileA", "CopyFileW", "CopyFileExW", "CopyFileExA"],
        "arguments": [("from", "existingfilename"), ("to", "newfilename")],
    },
    {
        "event": "Read",
        "object": "File",
        "apis": ["NtReadFile"],
        "arguments": [("Path", "handlename")],
    },
    {
        "event": "Write",
        "object": "File",
        "apis": ["NtWriteFile"],
        "arguments": [("Path", "handlename")],
    },
    {
        "event": "Create",
        "object": "File",
        "apis": ["NtCreateFile"],
        "arguments": [("Path", "handlename"), ("FileName", "filename")],
    },
    {
        "event": "Open",
        "object": "File",
        "apis": ["NtOpenFile"],
        "arguments": [("Path", "handlename"), ("FileName", "filename")],
    },
    #NtQueryDirectoryFile
    #NtQueryInformationFile
    #NtQueryVolumeInformationFile
    #NtQueryAttributesFile
    #NtQueryFullAttributesFile
    #NtSetInformationFile
    {
        "event": "Delete",
        "object": "Dir",
        "apis": ["RemoveDirectoryA", "RemoveDirectoryW"],
        "arguments": [("Folder", "directoryname")],
    },
    {
        "event": "Create",
        "object": "Dir",
        "apis": ["CreateDirectoryW", "CreateDirectoryExW"],
        "arguments": [("Folder", "directoryname")],
    },
    {
        "event": "Create",
        "object": "Process",
        "apis": ["NtCreateUserProcess"],
        "arguments": [("Path", "processfileName"), ("CommandLine", "commandline"), ("PID", "processid"), ("ImagePath", "imagepathname")],
    },
    {
        "event": "Create",
        "object": "Process",
        "apis": ["CreateProcessInternalW"],
        "arguments": [("CommandLine", "commandline"), ("PID", "processid"), ("ThreadID", "threadid")],
    },
    {
        "event": "Create",
        "object": "Process",
        "apis": ["CreateProcessWithTokenW", "CreateProcessWithLogonW"],
        "arguments": [("ApplicationName", "applicationame"), ("CommandLine", "commandline"), ("PID", "processid"), ("ThreadID", "threadid")],
    },
    {
        "event": "Create",
        "object": "Process",
        "apis": ["NtCreateProcess", "NtCreateProcessEx"],
        "arguments": [("Path", "filename"), ("PID", "pid")],
    },
    {
        "event": "Create",
        "object": "Process",
        "apis": ["CreateProcessA", "CreateProcessW"],
        "arguments": [("Name", "applicationname"), ("CommandLine", "commandline"), ("PID", "processid"), ("ThreadID", "threadid")],
    },
    {
        "event": "Create",
        "object": "NamedPipe",
        "apis": ["NtCreateNamedPipeFile"],
        "arguments": [("Name", "pipename")],
    },
    {
        "event": "Create",
        "object": "Event",
        "apis": ["NtCreateEvent"],
        "arguments": [("Name", "eventname")],
    },
    {
        "event": "Open",
        "object": "Event",
        "apis": ["NtOpenEvent"],
        "arguments": [("Name", "eventname")],
    }
]
 #Value uses by Sysmon which are essentially the ones from the Win32 API https://learn.microsoft.com/en-us/windows/win32/dns/dns-constants
DNS_TYPE = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TEXT", 
    28: "AAAA",
}
SUSPICIOUS_USER_AGENTS = ["Microsoft BITS", "Excel Service"]
SYSTEM_PROCESS_ID = 4
MARK_KEYS_TO_NOT_DISPLAY = ["data_being_encrypted"]
SKIPPED_FAMILIES = ["generic"]
PE_INDICATORS = [b"MZ", b"This program cannot be run in DOS mode"]

SUPPORTED_EXTENSIONS = [
    "au3",
    "a3x",
    "bat",
    "bin",
    "cpl",
    "dll",
    "doc",
    "docm",
    "docx",
    "dotm",
    "elf",
    "eml",
    "exe",
    "hta",
    "htm",
    "html",
    "hwp",
    "iso",
    "jar",
    "js",
    "lnk",
    "mht",
    "msg",
    "msi",
    "pdf",
    "potm",
    "potx",
    "pps",
    "ppsm",
    "ppsx",
    "ppt",
    "pptm",
    "pptx",
    "ps1",
    "pub",
    "py",
    "pyc",
    "rar",
    "rtf",
    "sh",
    "swf",
    "udf",
    "vbs",
    "vhd",
    "wsf",
    "xls",
    "xlsm",
    "xlsx",
    "zip",
    "7z",
]

#Error global variables
# https://github.com/cuckoosandbox/cuckoo/blob/50452a39ff7c3e0c4c94d114bc6317101633b958/cuckoo/core/guest.py#L561
GUEST_LOSING_CONNNECTIVITY = "Virtual Machine /status failed. This can indicate the guest losing network connectivity"
# Substring of Error Message from
# https://github.com/cuckoosandbox/cuckoo/blob/50452a39ff7c3e0c4c94d114bc6317101633b958/cuckoo/core/scheduler.py#L572
GUEST_CANNOT_REACH_HOST = (
    "it appears that this Virtual Machine hasn't been configured properly "
    "as the CAPE Host wasn't able to connect to the Guest."
)

#Limits
UNIQUE_IP_LIMIT = 100
GUEST_LOST_CONNECTIVITY = 5
ENCRYPTED_BUFFER_LIMIT = 25
BUFFER_ROW_LIMIT_PER_SOURCE_PER_PROCESS = 10
DWORD_MAX = 2**32 - 1
MAX_PORT_NUMBER = 65,535

#Section title
SIGNATURES_SECTION_TITLE = "Signatures"
NETWORK_SECTION_TITLE = "Network Activity"
CURTAIN_SECTION_TITLE = "PowerShell Activity"
HOLLOWSHUNTER_SECTION_TITLE = "HollowsHunter Analysis"
BUFFERS_SECTION_TITLE = "Buffers"
INFO_SECTION_TITLE = "Analysis Information"
CONFIG_EXTRACT_SECTION_TITLE = "Configs Extracted By CAPE"
PROCESS_TREE_AND_EVENTS_SECTION_TITLE = "Processes"
ANALYSIS_ERRORS = "Analysis Errors"

#Regexes and data types
HTTP_REQUEST_REGEX = f"Host: ({DOMAIN_REGEX})\\r"
YARA_RULE_EXTRACTOR = r"(?:(?:PID )?([0-9]{2,4}))?.*'(.\w+)'"
BYTE_CHAR = "x[a-z0-9]{2}"
DNS_TYPE_REGEX = r"^type:  (\d{1,2}) "
REVERSE_DNS_REGEX = r"^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}in-addr\.arpa$"
ETW_SOCK_ADDR_REGEX = f"^\[::ffff:({IP_REGEX}|0:0).*:({PORT_REGEX})"
ETW_ADDR_REGEX = f"^({IP_REGEX}:({PORT_REGEX}))"

#Machine related tags
x86_IMAGE_SUFFIX = "x86"
x64_IMAGE_SUFFIX = "x64"
LINUX_IMAGE_PREFIX = "ub"
WINDOWS_IMAGE_PREFIX = "win"
OFFLINE_IMAGE_PREFIX = "_off"
ONLINE_IMAGE_PREFIX = "_on"
MACHINE_NAME_REGEX = (
    f"(?:{'|'.join([LINUX_IMAGE_PREFIX, WINDOWS_IMAGE_PREFIX])})(.*)"
    f"(?:{'|'.join([x64_IMAGE_SUFFIX, x86_IMAGE_SUFFIX])})"
)

#Network related name
INETSIM = "INetSim"
ROUTING_LIST = ["none", "inetsim", "drop", "internet", "tor", "vpn"]

#Ouptut file location
BAT_COMMANDS_PATH = os.path.join("/tmp", "commands.bat")
PS1_COMMANDS_PATH = os.path.join("/tmp", "commands.ps1")
BUFFER_PATH = os.path.join("/tmp", "buffers")
ETW_PATH = "ETW"
ETW_DNS_PATH = os.path.join(ETW_PATH, "etw_dns.json")
ETW_NET_PATH = os.path.join(ETW_PATH, "etw_netevent.json")
ETW_PROC_PATH = os.path.join(ETW_PATH, "etw_proc_spoof.json")
ETW_WMI_PATH = os.path.join(ETW_PATH, "wmi_etw.json")

# noinspection PyBroadException
def generate_al_result(
    api_report: Dict[str, Any],
    al_result: ResultSection,
    file_ext: str,
    random_ip_range: str,
    routing: str,
    safelist: Dict[str, Dict[str, List[str]]],
    machine_info: Dict[str, Any],
    ontres: OntologyResults,
    processtree_id_safelist: List[str],
    inetsim_dns_servers: List[str],
    uses_https_proxy_in_sandbox: bool,
    suspicious_accepted_languages: List[str],
    signature_map: Dict[str, Dict[str, Any]] = {},
    task_dir = None
) -> Tuple[List[Dict[str, str]], List[Tuple[int, str]]]:
    """
    This method is the main logic that generates the Assemblyline report from the CAPE analysis report
    :param api_report: The JSON report for the CAPE analysis
    :param al_result: The overarching result section detailing what image this task is being sent to
    :param file_ext: The file extension of the file to be submitted
    :param random_ip_range: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param routing: What method of routing is being used in the CAPE environment
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param machine_name: The name of the machine that analyzed
    :param machine_info: The details about the machine that analyzed the file
    :param ontres: The Ontology Results class object
    :param processtree_id_safelist: A list of hashes used for safelisting process tree IDs
    :param inetsim_dns_servers: A list of IPs that represent the locations where INetSim is serving DNS services
    :param uses_https_proxy_in_sandbox: A boolean indicating if a proxy is used in the sandbox architecture that
    decrypts and forwards HTTPS traffic
    :param suspicious_accepted_languages: A list of suspicious accepted languages in HTTP headers
    :param signature_map: A map of all YARA signatures processed by Assemblyline and their current properties
    :return: A list of dictionaries with details about the payloads and the pids that they were hollowed out of, and a list of tuples representing both the PID of
             the initial process and the process name
    """
    global global_safelist
    global_safelist = safelist
    validated_random_ip_range = ip_network(random_ip_range)

    info: Dict[str, Any] = api_report.get("info", {})
    debug: Dict[str, Any] = api_report.get("debug", {})
    sigs: List[Dict[str, Any]] = api_report.get("signatures", [])
    network: Dict[str, Any] = api_report.get("network", {})
    behaviour: Dict[str, Any] = api_report.get("behavior", {})  # Note conversion from American to Canadian spelling eh
    curtain: Dict[str, Any] = api_report.get("curtain", {})
    sysmon: List[Dict[str, Any]] = api_report.get("sysmon", [])
    hollowshunter: Dict[str, Any] = api_report.get("hollowshunter", {})
    cape: Dict[str, Any] = api_report.get("CAPE", {})

    parsed_sysmon = None
    parsed_etw = None
    dns_servers = None
    dns_requests = None 
    low_level_flow = None
    http_calls = None
    signatures = None 
     #Info section
    if info:
        process_info(info, al_result, ontres)

    if debug:
        # Ransomware tends to cause issues with CAPE's analysis modules, and including the associated analysis errors
        # creates unnecessary noise to include this
        if not any("ransomware" in sig["name"] for sig in sigs):
            process_debug(debug, al_result)
    #Process the API calls
    process_map = get_process_map(behaviour.get("processes", {}), safelist)
    #Process all the sysmon events
    if sysmon:
        parsed_sysmon = process_sysmon(sysmon, safelist)

    if task_dir is not None:
        ETW_artifacts = {
            "dns": os.path.join(task_dir, ETW_DNS_PATH),
            "network": os.path.join(task_dir, ETW_NET_PATH),
            "processes": os.path.join(task_dir, ETW_PROC_PATH),
        }
        available_artifacts = {}
        for artifact, path in ETW_artifacts.items():
            if os.path.exists(path) and os.path.isfile(path):
                available_artifacts[artifact] = path
        parsed_etw = process_ETW(available_artifacts)

    main_process_tuples: List[Tuple(int, str)] = []
    if behaviour:
        sample_executed = [
            len(behaviour.get("processtree", [])),
            len(behaviour.get("processes", [])),
        ]
        # Since CAPE does not have behavioural analysis for Linux files in a production state, we should not raise
        # this result section, because the file can still run, it just won't have a processtree or processes sections.
        if (
            not any(item > 0 for item in sample_executed)
            and machine_info
            # Behaviour monitoring is not supported by CAPE and is in a development state
            and machine_info.get("Platform") != "linux"
            # If the user has requested that no monitor be used, we should not raise this result section
            and info.get("options", {}).get("free") != "yes"
        ):
            noexec_res = ResultTextSection("Sample Did Not Execute")
            noexec_res.add_line(
                "Either no program is available to execute a file with the extension: "
                f"{safe_str(file_ext)} OR see the '{ANALYSIS_ERRORS}' section for details."
            )
            al_result.add_subsection(noexec_res)
        main_process_tuples = process_behavior(behaviour)
    #Process the network events from the report which came from PCAP
    if network:
        dns_servers, dns_requests, low_level_flow, http_calls = get_network_map(
            network,
            validated_random_ip_range,
            routing,
            process_map,
            safelist,
            inetsim_dns_servers,
            uses_https_proxy_in_sandbox,
            suspicious_accepted_languages,
            parsed_sysmon,
            parsed_etw
        )
    #Process the signature raised in the report
    if sigs:
        signatures = process_signatures(sigs)
    
    #Load the powershell commands and cmd commands
    ps1_commands = []
    bat_commands = []
    if parsed_sysmon is not None:
        for _, events in parsed_sysmon.items():
            for event in events:
                if event["event_id"] == 1:
                    if event.get("command_line"):   
                        ps1_matches = find_powershell_strings(event["command_line"].encode())
                        for match in ps1_matches:
                            command = get_powershell_command(match.value)
                            if command and command + b"\n" not in ps1_commands:
                                ps1_commands.append(command + b"\n")

                        cmd_matches = find_cmd_strings(event["command_line"].encode())
                        for match in cmd_matches:
                            command = get_cmd_command(match.value)
                            if command and command + b"\n" not in bat_commands:
                                bat_commands.append(command + b"\n")   
                    
    if ps1_commands:
        with open(PS1_COMMANDS_PATH, "wb") as f:
            ps1_commands.insert(0, CUSTOM_PS1_ID)
            f.writelines(ps1_commands)

    if bat_commands:
        with open(BAT_COMMANDS_PATH, "wb") as f:
            bat_commands.insert(0, CUSTOM_BATCH_ID)
            f.writelines(bat_commands)

    process_events = load_ontology_and_result_section(ontres, al_result, process_map, parsed_sysmon, dns_servers, validated_random_ip_range, dns_requests, low_level_flow, http_calls, uses_https_proxy_in_sandbox, signatures, safelist, processtree_id_safelist, routing, inetsim_dns_servers, signature_map, parsed_etw)

    #Process all the info from auxiliaries
        # Powershell logger
    if curtain:
        process_curtain(curtain, al_result, process_map)
        # Memory hunter
    if hollowshunter:
        process_hollowshunter(hollowshunter, al_result, process_map)

    #Look for buffers in calls and all relevant tables
    if process_map:
        process_buffers(process_map, safelist, al_result)
    #Process the CAPE report section
    cape_artifact_pids: Dict[str, int] = {}
    if cape:
        cape_artifact_pids = process_cape(cape, al_result)

    #Machine information mostly for debugging purpose so last section
    if machine_info:
        process_machine_info(machine_info, ontres)

    return cape_artifact_pids, main_process_tuples, process_events

def load_ontology_and_result_section(
    ontres: OntologyResults, 
    al_result: ResultSection, 
    process_map: Dict[int, Dict[str, Any]],
    parsed_sysmon: Dict,
    dns_servers: List[str],
    inetsim_network: IPv4Network,
    dns_requests: Dict[str, List[Dict[str, Any]]],
    low_level_flow: List[Dict[str, Any]],
    http_calls: List[Dict[str, Any]],
    uses_https_proxy_in_sandbox: bool,
    signatures: List[Dict[str, Any]],
    safelist:  Dict[str, Dict[str, List[str]]],
    processtree_id_safelist: List[str],
    routing: str,
    inetsim_dns_servers: List[str],
    signature_map: Dict[str, Dict[str, Any]] = {},
    parsed_etw: Dict[str, Any] = {}
    ):
    if len(ontres.sandboxes) == 0:
        return
    session = ontres.sandboxes[-1].objectid.session
    process_res = ResultSandboxSection(PROCESS_TREE_AND_EVENTS_SECTION_TITLE)
    sigs_res = ResultSection(SIGNATURES_SECTION_TITLE, auto_collapse=True)
    network_res = ResultSection(NETWORK_SECTION_TITLE, auto_collapse=True)
    process_events = {
        "signatures": [],
        "network_connections": [],
        "processes": [],
    }
    #Gather the analysis information and metadata
    sandbox = ontres.sandboxes[-1]
    analysis_information = sandbox.as_primitives()
    analysis_information.pop("objectid")
    process_events["analysis_information"] = analysis_information
    #Process ontology building 
    pids_of_interest = process_map.keys()
    sysmon_enrichment = {}
    processes_still_to_create = list(pids_of_interest)
    possible_spoofing = {}
    if parsed_etw and isinstance(parsed_etw, Dict) and len(parsed_etw) > 0 and parsed_etw.get("processes", False): 
        for pid in pids_of_interest:
            if pid in parsed_etw["processes"].keys():
                if parsed_etw["processes"][pid]["real_ppid"] != parsed_etw["processes"][pid]["claimed_ppid"]:
                    possible_spoofing[pid] = {"claimed_ppid": parsed_etw["processes"][pid]["claimed_ppid"], "real_ppid": parsed_etw["processes"][pid]["real_ppid"]}
                if parsed_etw["processes"][pid]["real_ppid"] != process_map[pid]["ppid"]:
                    process_map[pid]["ppid"] = parsed_etw["processes"][pid]["real_ppid"]
                    if pid not in possible_spoofing.keys():
                        possible_spoofing[pid] = {"claimed_ppid": parsed_etw["processes"][pid]["claimed_ppid"], "real_ppid": parsed_etw["processes"][pid]["real_ppid"]}
            
    if parsed_sysmon is not None:
        for process_id, process_details in parsed_sysmon.items():
            created_process = False
            for event in process_details:
                if event["event_id"] == 1:
                    if ontres.is_guid_in_gpm(event["guid"]):
                        ontres.update_process(**event)
                    else:
                        if event["pid"] in pids_of_interest:
                            services = []
                            for service_event in process_map[event["pid"]]["services_events"]:
                                if service_event["arguments"]["Service"] not in services:
                                    services.append(service_event["arguments"]["Service"])
                            modules = []
                            for module_event in process_map[event["pid"]]["loaded_modules"]:
                                if module_event["object"] == "DLL":
                                    if module_event["arguments"]["DLLName"] not in modules:
                                        modules.append(module_event["arguments"]["DLLName"])
                                elif module_event["object"] == "Function":
                                    if module_event["arguments"].get("FunctionName", None) and module_event["arguments"]["FunctionName"] not in modules:
                                        modules.append(module_event["arguments"]["FunctionName"])
                            if len(services) > 0:
                                event["services_involved"] = services
                            if len(modules) > 0:
                                event["loaded_modules"] = modules
                        if process_id in possible_spoofing.keys():
                            event["ppid"] = possible_spoofing[process_id]["real_ppid"]
                            if event["ppid"] in parsed_etw["processes"].keys():
                                event["pimage"] = parsed_etw["processes"][event["ppid"]]["image"]
                            else:
                                event["pimage"] = None
                            event["pcommand)line"] = None
                            event["pguid"] = None
                        p_oid = ProcessModel.get_oid(
                            {
                                "pid": event["pid"],
                                "ppid": event.get("ppid"),
                                "image": event["image"],
                                "command_line": event.get("command_line"),
                            }
                        )
                        safelisted = event["safelisted"]
                        event.pop("safelisted", None)
                        event.pop("event_id", None)
                        p = ontres.create_process(
                                objectid=ontres.create_objectid(
                                    tag=Process.create_objectid_tag(event["image"]),
                                    ontology_id=p_oid,
                                    guid=event.get("guid"),
                                    session=session,
                                    ),
                                **event,
                            )
                        ontres.add_process(p)
                        created_process = True
                        process_dict = p.as_primitives()
                        process_dict["safelisted"] = safelisted
                        if process_dict["pid"] in sysmon_enrichment.keys():
                            process_dict["end_time"] = sysmon_enrichment[process_dict["pid"]]
                        if event["pid"] in pids_of_interest:
                            process_dict["file_count"] = len(process_map[event["pid"]]["file_events"])
                            process_dict["registry_count"] = len(process_map[event["pid"]]["registry_events"])
                            process_dict["sources"] = ["capemon", "sysmon"]
                        else:
                            process_dict["sources"] = ["sysmon"]
                        process_dict.pop("objectid")
                        process_dict.pop("pimage")
                        process_dict.pop("pcommand_line")
                        process_dict.pop("pobjectid")
                        process_dict.pop("loaded_modules")
                        process_dict.pop("services_involved")
                        validity = validate_sandbox_event(process_dict, "process")
                        if validity:
                            if isinstance(validity,bool):
                                process_events["processes"].append(process_dict)  
                            elif isinstance(validity,Dict):
                                process_events["processes"].append(validity)
                            else:
                                log.debug(f"Validator misbehaving for processes {process_dict}") 
                elif created_process and event["event_id"] == 5:
                    end_time = event.get("end_time", "-")
                    for proc in process_events["processes"]:
                        if proc["pid"] == event["pid"]:
                            proc["end_time"] = end_time
                elif event["event_id"] == 5:
                    sysmon_enrichment[event["pid"]] = event.get("end_time", "-")

            if created_process and process_id in pids_of_interest:
                processes_still_to_create.remove(process_id)
        
    for process_id in processes_still_to_create:
        this_process = {
            "pid": process_id,
            "image": process_map[process_id]["image"],
            "ppid": process_map[process_id]["ppid"],
            "start_time": process_map[process_id]["start_time"],
            "command_line": process_map[process_id]["command_line"]
        }
        services = []
        for service_event in process_map[process_id]["services_events"]:
            if service_event["arguments"]["Service"] not in services:
                services.append(service_event["arguments"]["Service"])
        modules = []
        for module_event in process_map[process_id]["loaded_modules"]:
            if module_event["object"] == "DLL":
                if module_event["arguments"]["DLLName"] not in modules:
                    modules.append(module_event["arguments"]["DLLName"])
            elif module_event["object"] == "Function":
                if module_event["arguments"].get("FunctionName", None):
                    if module_event["arguments"]["FunctionName"] not in modules:
                        modules.append(module_event["arguments"]["FunctionName"])
                elif module_event["arguments"].get("Identifier", None):
                    modules.append(module_event["arguments"]["Identifier"])
            if len(services) > 0:
                this_process["services_involved"] = services
            if len(modules) > 0:
                this_process["loaded_modules"] = modules
        p_oid = ProcessModel.get_oid(
            {
                "pid": this_process["pid"],
                "ppid": this_process.get("ppid"),
                "image": this_process["image"],
                "command_line": this_process.get("command_line"),
            }
        )
        p = ontres.create_process(
                objectid=ontres.create_objectid(
                    tag=Process.create_objectid_tag(this_process["image"]),
                    ontology_id=p_oid,
                    session=session,
                    ),
                **this_process,
            )
        ontres.add_process(p)
        process_dict = p.as_primitives()
        process_dict["safelisted"] = False
        if process_dict["pid"] in sysmon_enrichment.keys():
            process_dict["end_time"] = sysmon_enrichment[process_dict["pid"]]
        else:
            process_dict["end_time"] = "-"
        process_dict["file_count"] = len(process_map[process_id]["file_events"])
        process_dict["registry_count"] = len(process_map[process_id]["registry_events"])
        process_dict.pop("objectid")
        process_dict.pop("pimage")
        process_dict.pop("pcommand_line")
        process_dict.pop("pobjectid")
        process_dict.pop("loaded_modules")
        process_dict.pop("services_involved")
        process_dict["sources"] = ["capemon"]
        validity = validate_sandbox_event(process_dict, "process")
        if validity:
            if isinstance(validity,bool):
                process_events["processes"].append(process_dict)  
            elif isinstance(validity,Dict):
                process_events["processes"].append(validity)
            else:
                log.debug(f"Validator misbehaving for processes {process_dict}")

    #DNS section
    dns_server_heur = Heuristic(1008)
    dns_server_sec = ResultTextSection(
        dns_server_heur.name, heuristic=dns_server_heur, body=dns_server_heur.description
    )
    dns_server_hit = False
    if dns_servers is not None:
        for dns_server in dns_servers:
            if (
                add_tag(dns_server_sec, "network.dynamic.ip", dns_server, safelist)
                and not ip_address(dns_server) in inetsim_network
                and (routing == INETSIM.lower() and dns_server not in inetsim_dns_servers)
            ):
                dns_server_sec.add_line(f"\t-\t{dns_server}")
                dns_server_hit = True
    if dns_server_hit:
        network_res.add_subsection(dns_server_sec)

    dns_res_sec: Optional[ResultTableSection] = _get_dns_sec(dns_requests, safelist)

    if dns_res_sec and len(dns_res_sec.tags.get("network.dynamic.domain", [])) > 0:
        network_res.add_subsection(dns_res_sec)

    #DNS ontology
    if dns_requests is not None:
        for request, attempts in dns_requests.items():
            if contains_safelisted_value(request, safelist):
                continue
            for attempt in attempts:
                have_domain_answers = False
                have_ip_answers = False
                ip_answers = []
                domain_answers = []
                all_answers = []
                for answer in attempt["answers"]:
                    if answer in ["", " "] or None:
                        continue
                    all_answers.append(answer["answer"])
                    if is_valid_ip(answer["answer"]) or search(IP_REGEX, answer["answer"]):
                        have_ip_answers = True
                        ip_answers.append(answer["answer"])
                    elif is_valid_domain(answer["answer"]):
                        have_domain_answers = True
                        domain_answers.append(answer["answer"])
                if have_ip_answers and have_domain_answers:
                    nd = ontres.create_network_dns(
                        domain=request, resolved_ips=ip_answers, resolved_domains=domain_answers, lookup_type=attempt.get("type")
                    )
                elif have_domain_answers:
                    nd = ontres.create_network_dns(
                        domain=request, resolved_ips=None, resolved_domains=domain_answers, lookup_type=attempt.get("type")
                    )
                elif have_ip_answers:
                    nd = ontres.create_network_dns(
                        domain=request, resolved_ips=ip_answers, resolved_domains=None, lookup_type=attempt.get("type")
                    )
                else:
                    if len(all_answers) == 0:
                        all_answers.append("")
                    nd = ontres.create_network_dns(
                        domain=request, resolved_ips=all_answers, resolved_domains=None, lookup_type=attempt.get("type")
                    )
                destination_ip = dns_servers[0] if dns_servers else None
                destination_port = 53
                transport_layer_protocol = NetworkConnection.UDP
                nc_oid = NetworkConnectionModel.get_oid(
                    {
                        "destination_ip": destination_ip,
                        "destination_port": destination_port,
                        "transport_layer_protocol": transport_layer_protocol,
                        "connection_type": NetworkConnection.DNS,
                        "dns_details": nd.as_primitives(),
                        "lookup_type": attempt.get("type"),
                    }
                )
                objectid = ontres.create_objectid(
                    tag=NetworkConnectionModel.get_tag(
                        {
                            "destination_ip": destination_ip,
                            "destination_port": destination_port,
                        }
                    ),
                    ontology_id=nc_oid,
                    session=session,
                    time_observed=attempt["time"],
                )
                objectid.assign_guid()
                try:
                    nc = ontres.create_network_connection(
                        objectid=objectid,
                        destination_ip=destination_ip,
                        destination_port=destination_port,
                        transport_layer_protocol=transport_layer_protocol,
                        direction=NetworkConnection.OUTBOUND,
                        dns_details=nd,
                        connection_type=NetworkConnection.DNS,
                    )
                except ValueError as e:
                    log.warning(
                        f"{e}. The required values passed were:\n"
                        f"objectid={objectid}\n"
                        f"destination_ip={destination_ip}\n"
                        f"destination_port={destination_port}\n"
                        f"transport_layer_protocol={transport_layer_protocol}"
                    )
                    continue
                if nc:
                    p = ontres.get_process_by_guid(attempt["guid"])
                    if not p:
                        p = ontres.get_process_by_pid_and_time(attempt["process_id"], nc.objectid.time_observed)
                    if p:
                        nc.set_process(p)
                    ontres.add_network_connection(nc)
                    ontres.add_network_dns(nd)
                    if not nc.process and attempt["process_id"]:
                        # A OntologyResults process should exist for every pid in the process map
                        p = ontres.get_process_by_pid(attempt["process_id"])
                        nc.set_process(p)
                    elif attempt["process_id"] and attempt["process_name"]:
                        nc.update_process(image=attempt["process_name"], pid=attempt["process_id"])

                    net_dict = nc.as_primitives()
                    net_dict["time_observed"] = net_dict["objectid"].get("time_observed", "")
                    net_dict.pop("objectid")
                    net_dict["sources"] = attempt["sources"]
                    validity = validate_sandbox_event(net_dict, "network_connection")
                    if validity:
                        if isinstance(validity,bool):
                            process_events["network_connections"].append(net_dict)  
                        elif isinstance(validity,Dict):
                            process_events["network_connections"].append(validity)
                        else:
                            log.debug(f"Validator misbehaving for network connection {net_dict}")

    #TCP/UDP section and ontology
    netflows_sec = ResultTableSection("TCP/UDP Network Traffic")
    netflows_sec.set_column_order(
        ["timestamp", "protocol", "src_ip", "src_port", "domain", "dest_ip", "dest_port", "image", "pid"]
    )
    tcp_seen = False
    udp_seen = False
    unique_netflows: List[Dict[str, Any]] = []
    if low_level_flow is not None:
        for flow in low_level_flow:
            _ = add_tag(netflows_sec, "network.dynamic.domain", flow["domain"])
            _ = add_tag(netflows_sec, "network.protocol", flow["protocol"])
            _ = add_tag(netflows_sec, "network.dynamic.ip", flow["dest_ip"], safelist)
            _ = add_tag(netflows_sec, "network.dynamic.ip", flow["src_ip"], safelist)
            _ = add_tag(netflows_sec, "network.port", flow["dest_port"])
            _ = add_tag(netflows_sec, "network.port", flow["src_port"])
            flow["timestamp"] =  (datetime.strptime(process_events["analysis_information"]["analysis_metadata"]["start_time"], LOCAL_FMT_WITH_MS) + timedelta(seconds=flow["timestamp"])).strftime(LOCAL_FMT_WITH_MS)
            nc = _create_network_connection_for_network_flow(flow, session, ontres)
            if nc:
                if not nc.process and flow["pid"]:
                    # A OntologyResults process should exist for every pid in the process map
                    p = ontres.get_process_by_pid(flow["pid"])
                    nc.set_process(p)
                elif flow["pid"] and flow["image"]:
                    nc.update_process(image=flow["image"], pid=flow["pid"])
                netflow_dict = nc.as_primitives()
                if netflow_dict.get("process"):
                    if isinstance(netflow_dict.get("process"), Dict):
                        netflow_dict["process"] = netflow_dict["process"]["pid"]
                    elif not isinstance(netflow_dict.get("process"), int):
                        net_dict["process"] = flow.get("pid", None)
                elif flow.get("pid"):
                    netflow_dict["process"] = flow.get("pid", None)
                netflow_dict["time_observed"] = netflow_dict["objectid"].get("time_observed", "")
                netflow_dict.pop("objectid")
                netflow_dict["sources"] = flow["sources"]
                validity = validate_sandbox_event(netflow_dict, "network_connection")
                if validity:
                    if isinstance(validity,bool):
                        process_events["network_connections"].append(netflow_dict) 
                    elif isinstance(validity,Dict):
                        process_events["network_connections"].append(validity)
                    else:
                        log.debug(f"Validator misbehaving for network_connection {netflow_dict}")

                if flow not in unique_netflows:  # Remove duplicates
                    unique_netflows.append(flow)
                    netflows_sec.add_row(TableRow(**flow))
                    if flow["protocol"] == "tcp":
                        tcp_seen = True
                    elif flow["protocol"] == "udp":
                        udp_seen = True

        if tcp_seen:
            netflows_sec.add_subsection(
                ResultSection("TCP Network Traffic Detected", auto_collapse=True, heuristic=Heuristic(1010))
            )
        if udp_seen:
            netflows_sec.add_subsection(
                ResultSection("UDP Network Traffic Detected", auto_collapse=True, heuristic=Heuristic(1011))
            )

        netflows_sec.set_heuristic(1004)
        network_res.add_subsection(netflows_sec)

    # HTTP/HTTPS section
    http_sec = ResultTableSection("Protocol: HTTP/HTTPS")
    http_header_sec = ResultTableSection("IOCs found in HTTP/HTTPS Headers")
    remote_file_access_sec = ResultTextSection("Access Remote File")
    remote_file_access_sec.add_line("The sample attempted to download the following files:")
    suspicious_user_agent_sec = ResultTextSection("Suspicious User Agent(s)")
    suspicious_user_agent_sec.add_line("The sample made HTTP calls via the following user agents:")
    http_header_anomaly_sec = ResultTableSection("Non-Standard HTTP Headers")
    http_header_anomaly_sec.set_heuristic(1012)
    sus_user_agents_used = []
    if http_calls is not None:
        if len(http_calls) > 0:
            http_sec.set_heuristic(1002)
            _ = add_tag(http_sec, "network.protocol", "http")
        else:
            _process_non_http_traffic_over_http(network_res, unique_netflows)
        for http_call in http_calls:
            _ = add_tag(http_sec, "network.dynamic.uri", http_call["uri"], safelist)
            for _, value in http_call["request_headers"].items():
                extract_iocs_from_text_blob(value, http_header_sec, is_network_static=True)
            if http_call["download"]:
                if not remote_file_access_sec.body:
                    remote_file_access_sec.add_line(f'\t{{http_call["uri"]}}')
                elif f'\t{{http_call["uri"]}}' not in remote_file_access_sec.body:
                    remote_file_access_sec.add_line(f'\t{{http_call["uri"]}}')
                if not remote_file_access_sec.heuristic:
                    remote_file_access_sec.set_heuristic(1003)
                    _ = add_tag(
                        remote_file_access_sec,
                        "network.dynamic.uri",
                        http_call["uri"],
                        safelist,
                    )
            if http_call["Suspicious_agent"]:
                if suspicious_user_agent_sec.heuristic is None:
                    suspicious_user_agent_sec.set_heuristic(1007)
                if http_call["user-agent"] not in sus_user_agents_used:
                    _ = add_tag(
                        suspicious_user_agent_sec,
                        "network.user_agent",
                        http_call["user-agent"],
                        safelist,
                    )
                    suspicious_user_agent_sec.add_line(f'\t{{http_call["user-agent"]}}')
                    sus_user_agents_used.append(http_call["user-agent"])
                for lang in http_call["Flagged_language"]:
                    http_header_anomaly_sec.heuristic.add_signature_id(
                        f"suspicious_language_accepted_{lang.split('-')[1].lower()}", 750
                    )
                for header, header_value in http_call["Non_standard_request_headers"].items():
                    http_header_anomaly_sec.add_row(TableRow(header=header, header_value=header_value))
            nh_to_add = False
            nh = ontres.get_network_http_by_details(
                request_uri=http_call["uri"],
                request_method=http_call["method"],
                request_headers=http_call["request_headers"],
            )
            if not nh:
                nc, nh = _setup_network_connection_with_network_http(
                    http_call["uri"],
                    http_call,
                    http_call["request_headers"],
                    http_call["response_headers"],
                    http_call["request_body_path"],
                    http_call["response_body_path"],
                    http_call["port"],
                    http_call["dst"],
                    ontres,
                )
                nh_to_add = True
            else:
                nc = ontres.get_network_connection_by_network_http(nh)
            if nc:
                if nh_to_add:
                    ontres.add_network_http(nh)
                if not nc.process and http_call["pid"]:
                    # A OntologyResults process should exist for every pid in the process map
                    p = ontres.get_process_by_pid(http_call["pid"])
                    nc.set_process(p)
                elif http_call["pid"] and http_call["image"]:
                    nc.update_process(image=http_call["image"], pid=http_call["pid"])
    
                netflow_dict = nc.as_primitives()
                netflow_dict["time_observed"] = netflow_dict["objectid"].get("time_observed", "")
                netflow_dict.pop("objectid")
                netflow_dict["sources"] = http_call["sources"]
                validity = validate_sandbox_event(netflow_dict, "network_connection")
                if validity:
                    if isinstance(validity,bool):
                        process_events["network_connections"].append(netflow_dict) 
                    elif isinstance(validity,Dict):
                        process_events["network_connections"].append(validity)
                    else:
                        log.debug(f"Validator misbehaving for network_connection {netflow_dict}")

                http_sec.add_row(
                    TableRow(
                        process_name=f'{{http_call["image"]}} ({{http_call["pid"]}})' if http_call["pid"] or http_call["image"] else "None (None)",
                        method=http_call["method"],
                        request=http_call["request_headers"],
                        uri=http_call["uri"],
                    )
                )

    if remote_file_access_sec.heuristic:
        http_sec.add_subsection(remote_file_access_sec)
    if http_header_sec.body:
        http_sec.add_subsection(http_header_sec)
    if suspicious_user_agent_sec.heuristic:
        suspicious_user_agent_sec.add_line(" | ".join(sus_user_agents_used))
        http_sec.add_subsection(suspicious_user_agent_sec)
    if http_header_anomaly_sec.body or http_header_anomaly_sec.heuristic.signatures:
        http_sec.add_subsection(http_header_anomaly_sec)
    if http_sec.body or http_sec.subsections:
        network_res.add_subsection(http_sec)
    _process_unseen_iocs(network_res, process_map, ontres, safelist)
        
    #Signature section and ontology
    if signatures is not None:
        for signature in signatures:
            data = {
                "name": signature["name"],
                "type": signature["type"],
                "classification": signature["classification"],
            }
            s_tag = SignatureModel.get_tag(data)
            s_oid = SignatureModel.get_oid(data)
            ontres_sig = ontres.create_signature(
                objectid=ontres.create_objectid(
                    tag=s_tag,
                    ontology_id=s_oid,
                    session=session,
                ),
                name=signature["name"],
                type=signature["type"],
                score=signature["score"],
                classification=signature["classification"],
            )
            sig_res, pids = _create_signature_result_section(
                signature["name"],
                signature,
                signature["score"],
                ontres_sig,
                ontres,
                process_map,
                safelist,
                uses_https_proxy_in_sandbox,
                signature_map,
            )

            if sig_res:
                ontres.add_signature(ontres_sig)
                sigs_res.add_subsection(sig_res)
            if ontres_sig:
                signature_dict = ontres_sig.as_primitives()
                interesting_data = []
                for data in signature["data"]:
                    if "type" not in data.keys() or data["type"]!="call":
                        interesting_data.append(data) 
                signature_dict["data"] = interesting_data 
                signature_dict["score"] = signature["score"]
                if len(pids) > 0:
                    signature_dict["pid"] = pids
                else:
                    signature_dict["pid"] = None
                signature_dict.pop("objectid")
                signature_dict.pop("attributes")
                signature_dict["description"] = signature["description"]
                source_name = "CAPE"
                if signature_map:
                    for sig_info in signature_map.values():
                        if sig_info["name"] == signature["name"]:
                            source_name = sig_info["source"]
                signature_dict["sources"] = [source_name]

                validity = validate_sandbox_event(signature_dict, "signature")
                if validity:
                    if isinstance(validity,bool):
                        process_events["signatures"].append(signature_dict) 
                    elif isinstance(validity,Dict):
                        process_events["signatures"].append(validity)
                    else:
                        log.debug(f"Validator misbehaving for signature {signature_dict}")
            
    validity = validate_sandbox_event(process_events, "complete")
    if not validity:
        log.debug("Invalid Sandbox format")
    elif isinstance(validity, Dict):
        process_events = validity

    #Build the process tree 
    _, signature_list = ontres.get_process_tree(processtree_id_safelist, True)

    if len(signature_list) > 0:
        process_res.set_heuristic(3)
        signature_dict = Counter(signature_list)
        for signature,occurence in signature_dict.items():
            process_res.heuristic.add_signature_id(signature, 0, occurence)
    
    #if len(possible_spoofing) > 0:
    #    .set_heuristic(4)
    #    .heuristic.add_signature_id("Parent_Process_Spoofing", 0, len(possible_spoofing))

    #Build the sandbox section
    final_analysis_information = process_events["analysis_information"]
    process_res.set_analysis_information(
        sandbox_name = final_analysis_information["sandbox_name"],
        sandbox_version = final_analysis_information["sandbox_version"],
        analysis_metadata=SandboxAnalysisMetadata(
            task_id = final_analysis_information["analysis_metadata"]["task_id"],
            start_time = final_analysis_information["analysis_metadata"]["start_time"],
            end_time = final_analysis_information["analysis_metadata"]["end_time"],
            routing = final_analysis_information["analysis_metadata"]["routing"],
            machine_metadata=None
        ),
    )

    for process in process_events["processes"]:
        process_res.add_process(
            SandboxProcessItem(
                image = process["image"],
                start_time = process["start_time"],
                end_time = process["end_time"],
                pid = process["pid"],
                ppid = process["ppid"],
                command_line = process["command_line"],
                integrity_level = process["integrity_level"],
                image_hash = process["image_hash"],
                original_file_name = process["original_file_name"],
                safelisted = process["safelisted"],
                sources = process["sources"],
            )
        )
    for netevent in process_events["network_connections"]:
        if netevent["connection_type"] == "http":
            process_res.add_network_connection(
                SandboxNetflowItem(
                    destination_ip = netevent["destination_ip"],
                    destination_port = netevent["destination_port"],
                    source_ip = netevent["source_ip"],
                    source_port = netevent["source_port"],
                    time_observed = netevent["time_observed"],
                    process = netevent["process"],
                    direction = netevent["direction"],
                    transport_layer_protocol = netevent["transport_layer_protocol"],
                    http_details=SandboxNetworkHTTP(
                        request_uri = netevent["http_details"]["request_uri"],
                        request_method = netevent["http_details"]["request_method"],
                        response_status_code = netevent["http_details"]["response_status_code"],
                        response_headers = netevent["http_details"]["response_headers"],
                        request_headers = netevent["http_details"]["request_headers"],
                        response_body_path = netevent["http_details"]["response_body_path"],
                        request_body_path = netevent["http_details"]["request_body_path"] 
                    ),
                    connection_type = "http",
                    sources = netevent["sources"],
                )
            )
        elif netevent["connection_type"] == "dns":
            process_res.add_network_connection(
                SandboxNetflowItem(
                    destination_ip = netevent["destination_ip"],
                    destination_port = netevent["destination_port"],
                    source_ip = netevent["source_ip"],
                    source_port = netevent["source_port"],
                    time_observed = netevent["time_observed"],
                    process = netevent["process"],
                    direction = netevent["direction"],
                    dns_details=SandboxNetworkDNS(
                        domain = netevent["dns_details"]["domain"],
                        lookup_type = netevent["dns_details"]["lookup_type"],
                        resolved_ips = netevent["dns_details"]["resolved_ips"],
                        resolved_domains = netevent["dns_details"]["resolved_domains"]
                    ),
                    connection_type="dns",
                    sources = netevent["sources"],
                )
            )

        elif netevent["connection_type"] == "smtp":
            process_res.add_network_connection(
                SandboxNetflowItem(
                    destination_ip = netevent["destination_ip"],
                    destination_port = netevent["destination_port"],
                    source_ip = netevent["source_ip"],
                    source_port = netevent["source_port"],
                    time_observed = netevent["time_observed"],
                    process = netevent["process"],
                    direction = netevent["direction"],
                    transport_layer_protocol = netevent["transport_layer_protocol"],
                    smtp_details=SandboxNetworkSMTP(
                        mail_from = netevent["smtp_details"]["mail_from"],
                        mail_to = netevent["smtp_details"]["mail_to"],
                        attachments = netevent["smtp_details"]["attachments"],
                    ),
                    connection_type="smtp",
                    sources = netevent["sources"],
                )
            )
        else:
            process_res.add_network_connection(
                SandboxNetflowItem(
                    destination_ip = netevent["destination_ip"],
                    destination_port = netevent["destination_port"],
                    source_ip = netevent["source_ip"],
                    source_port = netevent["source_port"],
                    time_observed = netevent["time_observed"],
                    process = netevent["process"],
                    direction = netevent["direction"],
                    transport_layer_protocol = netevent["transport_layer_protocol"],
                    connection_type = netevent["connection_type"],
                    sources = netevent["sources"],
                )
            )
    for sig in process_events["signatures"]:
        attacks = []
        for attack in sig["attacks"]:
            attacks.append(
                SandboxAttackItem(
                    attack_id = attack["attack_id"],
                    pattern = attack["pattern"],
                    categories = attack["categories"],
                )
            )
        process_res.add_signature(
            SandboxSignatureItem(
                name = sig["name"],
                type = sig["type"],
                classification = sig["classification"],
                description = sig["description"],
                score = sig["score"],
                pid = sig["pid"],
                attacks = attacks,
                actors = sig["actors"],
                malware_families = sig["malware_families"],
                sources = sig["sources"]
            ))
    al_result.add_subsection(process_res)
    if len(network_res.subsections) > 0:
        al_result.add_subsection(network_res)
    if len(sigs_res.subsections) > 0:
        al_result.add_subsection(sigs_res)
    return process_events
    
def process_info(info: Dict[str, Any], parent_result_section: ResultSection, ontres: OntologyResults) -> None:
    """
    This method processes the info section of the CAPE report, adding anything noteworthy to the Assemblyline report
    :param info: The JSON of the info section from the report generated by CAPE
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param ontres: The Ontology Results class object
    :return: None
    """
    start_time = local_to_local_with_ms(info["started"])
    end_time = local_to_local_with_ms(info["ended"])
    duration = info["duration"]
    analysis_time = -1  # Default error time
    try:
        duration_str = format_time(datetime.fromtimestamp(int(duration)), "%Hh %Mm %Ss")
        analysis_time = duration_str + "\t(" + start_time + " to " + end_time + ")"
    except Exception:
        pass

    sandbox_version = info["version"]
    task_id = info["id"]
    routing = info["route"]

    # AL ResultSection Stuff
    body = {
        "CAPE Task ID": task_id,
        "Duration": analysis_time,
        "Routing": routing,
        "CAPE Version": sandbox_version,
    }
    info_res = ResultKeyValueSection(INFO_SECTION_TITLE)
    info_res.update_items(body)
    parent_result_section.add_subsection(info_res)

    # AL Ontology Stuff
    oid = SandboxModel.get_oid(
        {
            "sandbox_name": ontres.service_name,
            "sandbox_version": sandbox_version,
            "analysis_metadata": {
                "start_time": start_time,
                "end_time": end_time,
                "task_id": task_id,
            },
        }
    )
    sandbox = ontres.create_sandbox(
        objectid=ontres.create_objectid(
            ontology_id=oid,
            tag=ontres.service_name,
            session=OntologyResults.create_session(),
        ),
        analysis_metadata=Sandbox.AnalysisMetadata(
            start_time=start_time,
            task_id=task_id,
            end_time=end_time,
            routing=routing,
            # To be updated later
            machine_metadata=None,
        ),
        sandbox_name=ontres.service_name,
        sandbox_version=sandbox_version,
    )

    ontres.add_sandbox(sandbox)

def process_machine_info(machine_info: Dict[str, Any], ontres: OntologyResults):
    if len(ontres.sandboxes) == 0:
        return
    sandbox = ontres.sandboxes[-1]
    machine_name = machine_info["Name"]
    sandbox.update_machine_metadata(
        hostname=machine_name,
        platform=machine_info["Platform"].capitalize(),
        ip=machine_info["IP"],
        hypervisor=machine_info["Manager"],
    )

    if x86_IMAGE_SUFFIX in machine_name:
        sandbox.update_machine_metadata(architecture=x86_IMAGE_SUFFIX)
    elif x64_IMAGE_SUFFIX in machine_name:
        sandbox.update_machine_metadata(architecture=x64_IMAGE_SUFFIX)

    # The assumption here is that a machine's name will contain somewhere in it the
    # pattern: <platform prefix><version><processor>
    m = re_compile(MACHINE_NAME_REGEX).search(machine_name)
    if m and len(m.groups()) == 1:
        version = m.group(1)
        sandbox.update_machine_metadata(version=version)

def process_debug(debug: Dict[str, Any], parent_result_section: ResultSection) -> None:
    """
    This method processes the debug section of the CAPE report, adding anything noteworthy to the Assemblyline report
    :param debug: The JSON of the debug section from the report generated by CAPE
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :return: None
    """
    error_res = ResultTextSection(ANALYSIS_ERRORS)
    # Logs from the monitor that do not need to be logged at the AL service level
    errors_to_ignore = [
        "Failed to open terminate event for pid",
        "Could not open file",
        "Not enough memory",
    ]
    for error in debug["errors"]:
        err_str = str(error)
        # TODO: what is the point of lower-casing it?
        err_str = err_str.lower()
        if err_str is not None and len(err_str) > 0:
            error_res.add_line(error)

    # Including error that is not reported conveniently by CAPE for whatever reason
    debug_log = debug["log"].split("\n")
    unique_errors: set[str] = set()
    for analyzer_log in debug_log:
        if "error:" in analyzer_log.lower():  # Hoping that CAPE logs as ERROR
            split_log = analyzer_log.lower().split("error:", 1)[1].strip()
            if any(item.lower() in split_log for item in errors_to_ignore):
                continue
            if split_log in unique_errors:
                continue
            elif len(split_log) < 15:
                continue
            else:
                unique_errors.add(split_log)
            error_res.add_line(split_log.capitalize())

    if error_res.body and len(error_res.body) > 0:
        parent_result_section.add_subsection(error_res)

def process_signatures(
    sigs: List[Dict[str, Any]],
):
    """
    This method processes the signatures section of the CAPE report, adding anything noteworthy to the
    Assemblyline report
    :param sigs: The JSON of the signatures section from the report generated by CAPE
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param ontres: The Ontology Results class object
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param uses_https_proxy_in_sandbox: A boolean indicating if a proxy is used in the sandbox architecture that
    decrypts and forwards HTTPS traffic
    :param signature_map: A map of all YARA signatures processed by Assemblyline and their current properties
    :return: A boolean flag that indicates if the is_process_martian signature was raised
    """
    if len(sigs) <= 0:
        return False
    signatures = []
    sigs = _remove_network_http_noise(sigs)

    for sig in sigs:
        sig_name = sig["name"]

        if sig_name in CAPE_DROPPED_SIGNATURES:
            continue

        translated_score = SCORE_TRANSLATION[sig["severity"]]
        # Get the evidence that supports why the signature was raised
        mark_count = 0
        call_count = 0
        fp_mark_count = 0

        for mark in sig["data"]:
        # Check if the mark is a call
            if _is_mark_call(mark.keys()):
                call_count += 1
            else:
                for k, v in mark.items():
                    if not v or k in MARK_KEYS_TO_NOT_DISPLAY:
                        if isinstance(k, str):
                            try:
                                k = int(k)
                            except Exception as e:
                                pass
                        try:
                            sig["data"].pop(k)
                        except Exception as e:
                            pass
                        fp_mark_count += 1
                    else:
                        mark_count +=1

        # If there are more true positive marks than false positive marks, return signature 
        if not fp_mark_count or fp_mark_count != len(sig["data"]) - call_count:
            signatures.append({
            "name": sig_name,
            "description": sig["description"],
            "categories": sig["categories"],
            "families": sig["families"],
            "references": sig["references"],
            "type": "CUCKOO",
            "classification": Classification.UNRESTRICTED,
            "score": translated_score,
            "data": sig["data"],
        })
        else:
            log.debug(f"The signature {sig_name} was marked as a false positive, ignoring...")
        
    return signatures

def get_network_map(
    network: Dict[str, Any],
    inetsim_network: IPv4Network,
    routing: str,
    process_map: Dict[int, Dict[str, Any]],
    safelist: Dict[str, Dict[str, List[str]]],
    inetsim_dns_servers: List[str],
    uses_https_proxy_in_sandbox: bool,
    suspicious_accepted_languages: List[str],
    parsed_sysmon: Dict = {},
    parsed_etw: Dict[str, Any] = {},
):
    """
    This method processes the network section of the CAPE report, adding anything noteworthy to the
    Assemblyline report
    :param network: The JSON of the network section from the report generated by CAPE
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param inetsim_network: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param routing: The method of routing used in the CAPE environment
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param task_id: The ID of the CAPE Task
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param ontres: The Ontology Results class object
    :param inetsim_dns_servers: A list of IPs that represent the locations where INetSim is serving DNS services
    :param uses_https_proxy_in_sandbox: A boolean indicating if a proxy is used in the sandbox architecture that
    decrypts and forwards HTTPS traffic
    :param suspicious_accepted_languages: A list of suspicious accepted languages in HTTP headers
    :return: None
    """

    # DNS
    dns_servers: List[str] = _determine_dns_servers(network, inetsim_dns_servers)
    dns_requests: Dict[str, List[Dict[str, Any]]] = _get_dns_map(
        network.get("dns", []), process_map, parsed_sysmon, routing, dns_servers, parsed_etw
    )
    #dns_res_sec: Optional[ResultTableSection] = _get_dns_sec(dns_requests, safelist)

    # UDP/TCP
    low_level_flows = {"udp": network.get("udp", []), "tcp": network.get("tcp", [])}
    network_flows_table = _get_low_level_flows(process_map, parsed_sysmon, low_level_flows)
    low_level_flow = []
    for network_flow in network_flows_table:
        if not _remove_network_call(network_flow["domain"], network_flow["dest_ip"], dns_servers, dns_requests, inetsim_network, safelist):
            low_level_flow.append(network_flow)
            
    # HTTP/HTTPS section
    http_level_flows = {
        "http": network.get("http", []),
        "https": network.get("https", []),
        "http_ex": network.get("http_ex", []),
        "https_ex": network.get("https_ex", []),
    }
    http_calls = _process_http_calls(http_level_flows, process_map, parsed_sysmon, dns_servers, dns_requests, safelist, uses_https_proxy_in_sandbox, suspicious_accepted_languages)

    return dns_servers, dns_requests, low_level_flow, http_calls

def _get_dns_map(
    dns_calls: List[Dict[str, Any]],
    process_map: Dict[int, Dict[str, Any]],
    parsed_sysmon: Dict,
    routing: str,
    dns_servers: List[str],
    parsed_etw: Dict[str, Any] = {}
) -> Dict[str, List[Dict[str, Any]]]:
    """
    This method creates a map between domain calls and IPs returned
    :param dns_calls: DNS details that were captured by CAPE
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param routing: The method of routing used in the CAPE environment
    :param dns_servers: A list of DNS servers
    :return: the mapping of resolved IPs and their corresponding domains
    """
    dns_requests: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    if dns_calls is not None:
        for dns_call in dns_calls:
            if len(dns_call["answers"]) > 0:
                answers = [{"answer": i["data"], "Type": i["type"]} for i in dns_call["answers"]]
            else:
                answers = []
            request = dns_call.get("request")
            if not request:
                continue

            dns_type = dns_call["type"]

            # If the method of routing is INetSim or a variation of INetSim, then we will not use PTR records.
            # The reason being that there is always a chance for collision between IPs and hostnames due to the
            # DNS cache, and that chance increases the smaller the size of the random network space
            if routing.lower() in [INETSIM.lower(), "none"] and dns_type == "PTR":
                continue
            # Some Windows nonsense
            for answer in answers:
                if answer is Dict:
                    if set(answer.values()).intersection(set(dns_servers)):
                        continue

            first_seen = dns_call.get("first_seen")
            if first_seen and (isinstance(first_seen, float) or isinstance(first_seen, int)):
                first_seen = epoch_to_local_with_ms(first_seen, trunc=3)
            dns_requests[request].append(
                {
                    "answers": answers,
                    "process_id": dns_call.get("pid"),
                    "process_name": dns_call.get("image"),
                    "time": first_seen,
                    "guid": dns_call.get("guid"),
                    "type": dns_type,
                    "sources": ["PCAP"]
                }
            )

        # Attempt mapping process_name to the dns_call using the API calls
        if process_map is not None:
            for process, process_details in process_map.items():
                for network_call in process_details["network_calls"]:
                    if network_call["event"] == "DNS":
                        dns = network_call["arguments"]
                        if dns != {} and (dns.get("HostName")):
                            for request, attempts in dns_requests.items():
                                for index, attempt in enumerate(attempts):
                                    answers = attempt["answers"]
                                    if answers == None:
                                        continue
                                    for answer in answers:
                                        if answer is not Dict:
                                            continue
                                        #Currently API calls do not track the response so this first condition will never trigger and might be a list in the future
                                        if answer["answer"] == dns.get("Response") or request == dns.get("HostName"):
                                            if not dns_requests[request][index].get("process_name"):
                                                dns_requests[request][index]["process_name"] = process_details["name"]
                                            if not dns_requests[request][index].get("process_id"):
                                                dns_requests[request][index]["process_id"] = process
                                            dns_requests[request][index]["sources"].append("API")
                                        else:
                                            continue
        # Attempt mapping process_name to the dns_call using sysmon
        if parsed_sysmon is not None:
            for process, process_details in parsed_sysmon.items():
                for event in process_details:
                    if event["event_id"] == 22:
                        for request, attempts in dns_requests.items():
                            for index, attempt in enumerate(attempts):
                                answers = attempt["answers"]
                                if answers == None:
                                    continue
                                for answer in answers:
                                    if answer is not Dict:
                                        continue
                                    if (answer["answer"], answer["Type"]) in [(resp["data"], resp["type"]) for resp in event["answers"]]  or request == event["request"]:
                                        if not dns_requests[request][index].get("process_name"):
                                            dns_requests[request][index]["process_name"] = event["image"]

                                        if not dns_requests[request][index].get("process_id"):
                                            dns_requests[request][index]["process_id"] = process
                                        dns_requests[request][index]["sources"].append("sysmon")
                                    else:
                                        continue
        #Attempt mapping process_name to the dns_call using ETW
        if parsed_etw is not None and parsed_etw:
            for etw_request, etw_request_informations in parsed_etw["dns"].items():
                for request, attempts in dns_requests.items():
                    for index, attempt in enumerate(attempts):
                        answers = attempt["answers"]
                        if answers == None:
                            continue
                        for answer in answers:
                            if answer is not Dict:
                                continue
                            if answer["answer"] in etw_request_informations["responses"] or request == etw_request:
                                if not dns_requests[request][index].get("process_id"):
                                    dns_requests[request][index]["process_id"] = etw_request_informations["pids"][0] #Best effort to attribute the dns call to a process
                                dns_requests[request][index]["sources"].append("etw")
                            else:
                                continue
    return dict(dns_requests)

def _get_low_level_flows(
    process_map: Dict[int, Dict[str, Any]],
    parsed_sysmon: Dict,
    flows: Dict[str, List[Dict[str, Any]]],
    parsed_etw: Dict[str, Any] = {}
) -> List[Dict[str, Any]]:
    """
    This method converts low level network calls to a general format
    :param dns_requests: A map of process IDs to process names, network calls, and decrypted buffers
    :param flows: UDP and TCP flows from CAPE's analysis
    :return: Returns a table of low level network calls, and a result section for the table
    """
    # TCP and UDP section
    network_flows_table: List[Dict[str, Any]] = []
    if flows is not None:
        for protocol, network_calls in flows.items():
            for network_call in network_calls:
                dst = network_call["dst"]
                src = network_call["src"]
                src_port: Optional[str] = None
                if src:
                    src_port = network_call.get("sport")
                network_flow = {
                    "timestamp": network_call["time"],
                    "protocol": protocol,
                    "src_ip": src,
                    "src_port": src_port,
                    "domain": None,
                    "dest_ip": dst,
                    "dest_port": network_call["dport"],
                    "image": network_call.get("image"),
                    "pid": network_call.get("pid"),
                    "guid": network_call.get("guid"),
                    "sources": ["PCAP"]
                }
                #TODO check for time similarity as well for associating processes with netflow
                # Attempt mapping process_name to the netflow using the API calls
                if process_map is not None:
                    for process, process_details in process_map.items():
                        for net_call in process_details["network_calls"]:
                            if net_call["event"] in ["Connect", "Request_response", "Proxying"]:
                                call = net_call["arguments"]
                                if call != {} and (call.get("HostName") or call.get("IP") or call.get("URL")):
                                    if network_flow["dest_ip"] in [call.get("HostName"), call.get("IP"), call.get("URL")] or network_flow["domain"] in [call.get("HostName"), call.get("IP"), call.get("URL")]:
                                        if str(network_flow["dest_port"]) == call.get("Port") or call.get("Port") is None:
                                            if not network_flow.get("image"):
                                                network_flow["image"] = process_details["name"]
                                            if not network_flow.get("pid"):
                                                network_flow["pid"] = process
                                            network_flow["sources"].append("API")                       
                 # Attempt mapping process_name to the netflow using sysmon
                if parsed_sysmon is not None:
                    for process, process_details in parsed_sysmon.items():
                        for event in process_details:
                            if event["event_id"] == 3:
                                if (network_flow["dest_ip"] == event["dst"]  or network_flow["domain"] == event["dst"]) and network_flow["src_ip"] == event["src"]:
                                    if network_flow["dest_port"] == event["dport"] and network_flow["src_port"] == event["sport"]:
                                        if not network_flow.get("image"):
                                            network_flow["image"] = event["image"]
                                        if not network_flow.get("pid"):
                                            network_flow["pid"] = process
                                        network_flow["sources"].append("sysmon")
                #Attempt mapping process_name to the netflow using ETW
                if parsed_etw is not None and parsed_etw:
                    for process_id, etw_netcalls in parsed_etw["network"].items():
                        for call in etw_netcalls:
                            if (network_flow["dest_ip"] == call["dst"]  or network_flow["domain"] == call["dst"]) and network_flow["src_ip"] == call["src"]:
                                    if network_flow["dest_port"] == call["dport"] and network_flow["src_port"] == call["sport"]:
                                        if not network_flow.get("pid"):
                                            network_flow["pid"] = process_id
                                        network_flow["sources"].append("etw") 
                network_flows_table.append(network_flow)
    return network_flows_table

def _process_http_calls(
    http_level_flows: Dict[str, List[Dict[str, Any]]],
    process_map: Dict[int, Dict[str, Any]],
    parsed_sysmon: Dict,
    dns_servers: List[str],
    dns_requests: Dict[str, List[Dict[str, Any]]],
    safelist: Dict[str, Dict[str, List[str]]],
    uses_https_proxy_in_sandbox,
    suspicious_accepted_languages,
):
    """
    This method processes HTTP(S) calls and puts them into a nice table
    :param http_level_flows: A list of flows that represent HTTP calls
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param dns_servers: A list of DNS servers
    :param dns_requests: A map of process IDs to process names, network calls, and decrypted buffers
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    """
    # Http level flows consist of http, http_ex, https and https_ex
    http_requests = []
    if http_level_flows is not None:
        for protocol, http_calls in http_level_flows.items():
            for http_call in http_calls:
                download = False
                sus_agent = False
                flagged_language = {}
                host = _massage_host_data(http_call["host"])
                if not host:
                    continue
                if is_valid_ip(host) and "dst" not in http_call:
                    http_call["dst"] = host
                if uses_https_proxy_in_sandbox:
                    http_call["uri"] = convert_url_to_https(method=http_call["method"], url=http_call["uri"])
                #Fields which differ from protocol types that need normalization
                request, port, uri, http_call = _get_important_fields_from_http_call(
                    protocol, host, dns_servers, dns_requests, http_call
                )
                if _is_http_call_safelisted(host, safelist, uri):
                    continue
                
                request_body_path, response_body_path = _massage_body_paths(http_call)
                request_headers = _handle_http_headers(request)
                response_headers = _handle_http_headers(http_call.get("response"))

                for header,header_value in request_headers.items():
                    if header in STANDARD_HTTP_HEADERS:
                        request_headers[header] = header.replace("-", "")
                    elif header == "AcceptLanguage":
                        for sus_language in suspicious_accepted_languages:
                            if sus_language.lower() in header_value.lower():
                                flagged_language = header_value
                    else:
                        http_call["Non_standard_request_headers"] = {}
                        http_call["Non_standard_request_headers"][header] = header_value
                for header,_ in response_headers.items():
                    if header in STANDARD_HTTP_HEADERS:
                        response_headers[header] = header.replace("-", "")
                    else:
                        http_call["Non_standard_request_headers"] = {}
                        http_call["Non_standard_request_headers"][header] = header_value

                destination_ip = _get_destination_ip(http_call, dns_servers)
                if not destination_ip:
                    continue
                first_seen = http_call.get("first_seen")
                if first_seen and (isinstance(first_seen, float) or isinstance(first_seen, int)):
                    first_seen = epoch_to_local_with_ms(first_seen, trunc=3)
                if http_call["method"] == "GET":
                    split_path = http_call["uri"].rsplit("/", 1)
                    if len(split_path) > 1 and search(r"[^\\]*\.(\w+)$", split_path[-1]):
                        download = True
                if http_call.get("user-agent", None) in SUSPICIOUS_USER_AGENTS:
                    sus_agent = True
                http_request = {
                    "protocol": protocol,
                    "host": host,
                    "dst": http_call["dst"],
                    "port": port,
                    "uri": uri,
                    "method": http_call["method"],
                    "path": http_call.get("path", "/"),
                    "user-agent": http_call.get("user-agent", None),
                    "timestamp": first_seen,
                    "version": http_call["version"],
                    "request": request,
                    "request_headers": request_headers,
                    "request_body_path": request_body_path,
                    "response": http_call.get("response"),
                    "response_headers":  response_headers,
                    "response_body_path": response_body_path,
                    "image": None,
                    "pid": None,
                    "guid": None,
                    "download": download,
                    "Suspicious_agent": sus_agent,
                    "Non_standard_request_headers": http_call.get("Non_standard_request_headers"),
                    "Flagged_language": flagged_language,
                    "sources": ["PCAP"]
                }
                 # Attempt mapping process_name to the http_call using the API calls
                if process_map is not None:
                    for process, process_details in process_map.items():
                        for net_call in process_details["network_calls"]:
                            if net_call["event"] in ["Connect", "Request_response"]:
                                call = net_call["arguments"]
                                 # According to https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetconnecta, service = 3 stands for "INTERNET_SERVICE_HTTP"
                                if call.get("Port") in ["80", "443"] or call.get("Service", 0) in ["http", "https", "HTTP", "HTTPS", "3"]:
                                    if call != {} and (call.get("HostName") or call.get("IP") or call.get("URL") or call.get("Buffer")):
                                        if (
                                        http_request["dst"] in [call.get("HostName"), call.get("IP"), call.get("URL")] 
                                        or http_request["host"] in [call.get("HostName"), call.get("IP"), call.get("URL")]
                                        or http_request["request"] == call.get("Buffer")
                                        or any(_uris_are_equal_despite_discrepancies(http_request["host"], call_url) for call_url in [call.get("HostName"), call.get("IP"), call.get("URL")])
                                        ):
                                            if str(http_request["port"]) == call.get("Port") or call.get("Port") is None:
                                                if not http_request.get("image"):
                                                    http_request["image"] = process_details["name"]
                                                if not http_request.get("pid"):
                                                    http_request["pid"] = process
                                                http_request["sources"].append("API")                       
                 # Attempt mapping process_name to the http_call using sysmon
                if parsed_sysmon is not None:
                    for process, process_details in parsed_sysmon.items():
                        for event in process_details:
                            if event["event_id"] == 3:
                                if (
                                    http_request["dst"] == event["dst"]  or http_request["host"] == event["dst"]
                                    or _uris_are_equal_despite_discrepancies(http_request["host"], event["dst"])
                                    ):
                                    if http_request["port"] == event["dport"]:
                                        if not http_request.get("image"):
                                            http_request["image"] = event["image"]
                                        if not http_request.get("pid"):
                                            http_request["pid"] = process
                                        http_request["sources"].append("sysmon")
                http_requests.append(http_request)
    return http_requests    

def process_curtain(
    curtain: Dict[str, Any],
    parent_result_section: ResultSection,
    process_map: Dict[int, Dict[str, Any]],
) -> None:
    """
    This method processes the Curtain section of the CAPE report and adds anything noteworthy to the
    Assemblyline report
    :param curtain: The JSON output from the Curtain module (Powershell commands that were run)
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :return: None
    """
    curtain_body: List[Dict[str, Any]] = []
    curtain_res = ResultTableSection(CURTAIN_SECTION_TITLE)
    curtain_res.set_column_order(["process_name", "original", "reformatted"])
    for pid in curtain.keys():
        process_name = process_map[int(pid)]["name"] if process_map.get(int(pid)) else "powershell.exe"
        for event in curtain[pid]["events"]:
            for command in event.keys():
                curtain_item = {
                    "process_name": process_name,
                    "original": event[command]["original"],
                    "reformatted": None,
                }
                altered = event[command]["altered"]
                if altered != "No alteration of event.":
                    curtain_item["reformatted"] = altered
                curtain_body.append(curtain_item)
        _ = add_tag(
            curtain_res,
            "file.behavior",
            [behaviour for behaviour in curtain[pid]["behaviors"]],
        )
    if len(curtain_body) > 0:
        [curtain_res.add_row(TableRow(**cur)) for cur in curtain_body]
        parent_result_section.add_subsection(curtain_res)

def process_hollowshunter(
    hollowshunter: Dict[str, Any],
    parent_result_section: ResultSection,
    process_map: Dict[int, Dict[str, Any]],
) -> None:
    """
    This method processes the HollowsHunter section of the CAPE report and adds anything noteworthy to the
    Assemblyline report
    :param hollowshunter: The JSON output from the HollowsHunter module
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :return: None
    """
    hollowshunter_body: List[Any] = []
    hollowshunter_res = ResultTableSection("HollowsHunter Analysis")
    hollowshunter_res.set_column_order(["Process", "Indicator", "Description"])
    # We care about implanted PEs
    # Process (PID)       Indicator       Description
    for pid, details in hollowshunter.items():
        implanted_pes = details.get("scanned", {}).get("modified", {}).get("implanted_pe", 0)
        if implanted_pes > 0:
            implanted_pe_count = 0
            modules = []
            for scan in details["scans"]:
                if "workingset_scan" in scan:
                    scan_details = scan["workingset_scan"]
                    # Confirm that Implanted PEs exist
                    if scan_details["has_pe"]:
                        modules.append(scan_details["module"])
                        implanted_pe_count += 1
            if implanted_pes == implanted_pe_count:
                hollowshunter_body.append(
                    {
                        "Process": f"{process_map.get(int(pid), {}).get('name')} ({pid})",
                        "Indicator": "Implanted PE",
                        "Description": f"Modules found: {modules}",
                    }
                )
    if len(hollowshunter_body) > 0:
        [hollowshunter_res.add_row(TableRow(**hh)) for hh in hollowshunter_body]
        parent_result_section.add_subsection(hollowshunter_res)

def process_buffers(
    process_map: Dict[int, Dict[str, Any]],
    safelist: Dict[str, Dict[str, List[str]]],
    parent_result_section: ResultSection,
) -> None:
    """
    This method checks for any buffers found in the process map, and adds them to the Assemblyline report
    :param process_map: A map of process IDs to process names, network calls, and buffers
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :return: None
    """
    buffer_res = ResultTableSection(BUFFERS_SECTION_TITLE, auto_collapse=True)
    buffer_res.set_column_order(["Process", "Source", "Buffer"])
    buffer_ioc_table = ResultTableSection("Buffer IOCs")
    buffer_body = []
    buffers = []
    for process, process_details in process_map.items():
        count_per_source_per_process = 0
        process_name_to_be_displayed = f"{process_details.get('name', 'None')} ({process})"
        for call in process_details.get("crypto_buffers", []):
            buffer = ""
            arguments = call["arguments"]
            buffer = arguments["Buffer"]
            b_buffer = bytes(buffer, "utf-8")
            if all(PE_indicator in b_buffer for PE_indicator in PE_INDICATORS):
                hash = sha256(b_buffer).hexdigest()
                buffers.append((f'{str(process)}-{{arguments["api"]}}-{hash}', b_buffer, buffer))
            if not buffer:
                continue
            extract_iocs_from_text_blob(buffer, buffer_ioc_table, enforce_char_min=True, is_network_static=True)
            table_row = {
                "Process": process_name_to_be_displayed,
                "Source": "Windows API",
                "Buffer": safe_str(buffer),
            }
            if table_row not in buffer_body and count_per_source_per_process < BUFFER_ROW_LIMIT_PER_SOURCE_PER_PROCESS:
                buffer_body.append(table_row)
                count_per_source_per_process += 1

        for call in process_details.get("misc_events"):
            buffer = ""
            arguments = call["arguments"]   
            buffer = arguments["Buffer"]
            b_buffer = bytes(buffer, "utf-8")
            if all(PE_indicator in b_buffer for PE_indicator in PE_INDICATORS):
                hash = sha256(b_buffer).hexdigest()
                buffers.append((f'{str(process)}-{{arguments["api"]}}-{hash}', b_buffer, buffer))
            if not buffer:
                continue
            extract_iocs_from_text_blob(buffer, buffer_ioc_table, enforce_char_min=True, is_network_static=True)
            table_row = {
                "Process": process_name_to_be_displayed,
                "Source": "Windows API",
                "Buffer": safe_str(buffer),
            }
            if table_row not in buffer_body and count_per_source_per_process < BUFFER_ROW_LIMIT_PER_SOURCE_PER_PROCESS:
                buffer_body.append(table_row)
                count_per_source_per_process += 1

        count_per_source_per_process = 0
        network_buffers = []
        for call in process_details.get("network_calls", []):
            buffer = ""
            arguments = call["arguments"]
            if arguments.get("Buffer"):
                buffer = arguments["Buffer"]
                buffer = _remove_bytes_from_buffer(buffer)
                if is_tag_safelisted(
                    buffer, ["network.dynamic.ip", "network.dynamic.uri", "network.dynamic.domain"], safelist
                ):
                    continue
                length_of_ioc_table_pre_extraction = len(buffer_ioc_table.body) if buffer_ioc_table.body else 0
                extract_iocs_from_text_blob(
                    buffer, buffer_ioc_table, enforce_char_min=True, safelist=safelist, is_network_static=True
                )
                # We only want to display network buffers if an IOC is found
                length_of_ioc_table_post_extraction = len(buffer_ioc_table.body) if buffer_ioc_table.body else 0
                if length_of_ioc_table_pre_extraction == length_of_ioc_table_post_extraction:
                    continue
                table_row = {
                    "Process": process_name_to_be_displayed,
                    "Source": "Network",
                    "Buffer": safe_str(buffer),
                }
                if (
                    table_row not in buffer_body
                    and count_per_source_per_process < BUFFER_ROW_LIMIT_PER_SOURCE_PER_PROCESS
                ):
                    buffer_body.append(table_row)
                    count_per_source_per_process += 1
                    b_buffer = bytes(buffer, "utf-8")
                    if all(PE_indicator in b_buffer for PE_indicator in PE_INDICATORS):
                        hash = sha256(b_buffer).hexdigest()
                        network_buffers.append((f'{str(process)}-{{arguments["api"]}}-{hash}', b_buffer, buffer))

    if not os.path.exists(BUFFER_PATH):
        os.mkdir(BUFFER_PATH)

    buffers.extend(network_buffers)
    for filename, b_buffer, buffer in buffers:
        pebuffer = bytearray(b_buffer)
        try:
            PE_from_buffer = pefile.PE(data=pebuffer)
            if is_valid(PE_from_buffer):
                PE_from_buffer.write(f"{BUFFER_PATH}/{filename}")
        except Exception as E:
            try:
                if lief.is_pe(pebuffer):
                    PE_from_buffer = lief.PE.parse(pebuffer)
                    PE_from_buffer.build()
                    PE_from_buffer.write(f"{BUFFER_PATH}/{filename}")
                elif lief.is_pe(buffer):
                    PE_from_buffer = lief.PE.parse(buffer)
                    PE_from_buffer.build()
                    PE_from_buffer.write(f"{BUFFER_PATH}/{filename}")
                else:
                    with open(f"{BUFFER_PATH}/{filename}", "wb+") as f:
                        f.write(pebuffer)
            except Exception as E:
                continue

    # Element in buffer_body should be extracted or scanned for carving PE
    if len(buffer_body) > 0:
        [buffer_res.add_row(TableRow(**buffer)) for buffer in buffer_body]
        if buffer_ioc_table.body:
            buffer_res.add_subsection(buffer_ioc_table)
            buffer_res.set_heuristic(1006)
        parent_result_section.add_subsection(buffer_res)

def process_cape(cape: Dict[str, Any], parent_result_section: ResultSection) -> List[Dict[str, str]]:
    """
    This method creates a map of payloads and the pids that they were hollowed out of
    :param cape: A dictionary containing the CAPE reporting output
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :return: A list of dictionaries with details about the payloads and the pids that they were hollowed out of
    """
    cape_artifacts: List[Dict[str, str]] = list()
    for payload in cape.get("payloads", []):
        cape_artifacts.append(
            {
                "sha256": payload["sha256"],
                "pid": payload["pid"],
                "is_yara_hit": True if len(payload["cape_yara"]) else False,
            }
        )

    if cape.get("configs", []):
        malware_heur = Heuristic(5)
        malware_heur.add_signature_id("config_extracted", 1000)
        configs_sec = ResultSection(CONFIG_EXTRACT_SECTION_TITLE, parent=parent_result_section, heuristic=malware_heur)

        for configuration in cape["configs"]:
            for config_name, config_values in configuration.items():
                if config_name.startswith("_"):
                    continue
                config_sec = ResultTableSection(f"{config_name} Config", parent=configs_sec)
                config_sec.set_column_order(["type", "config_value"])

                for key, value in config_values.items():
                    config_sec.add_row(TableRow(type=key, config_value=value))

    return cape_artifacts

def get_process_map(
    processes: List[Dict[str, Any]], safelist: Dict[str, Dict[str, List[str]]]
) -> Dict[int, Dict[str, Any]]:
    """
    This method creates a process map that maps process IDs with useful details
    :param processes: A list of processes observed by CAPE
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: A map of process IDs to process names, network calls, and decrypted buffers
    """
    process_map: Dict[int, Dict[str, Any]] = {}
    for process in processes:
        network_calls = []
        crypto_buffers = []
        loaded_modules = []
        services_events = []
        drivers_events = []
        registry_events = []
        file_events = []
        misc_events = []
        hooking_events = []
        process_events = []
        interprocess_comm = []
        calls = process["calls"]
        for call in calls:
            category = call.get("category", "does_not_exist")
            api = call["api"]
            for event in API_CALLS:
                if api in event["apis"]:
                    args_of_interest = {}
                    safelisted_values = False
                    args = call["arguments"]
                    for arg in args:
                        if arg["name"].lower() in [arg_tuple[1] for arg_tuple in event["arguments"]]:
                            if category in ["network", "crypto"]:
                                if is_tag_safelisted(arg["value"], ["network.dynamic.ip", "network.dynamic.uri", "network.dynamic.domain"],safelist):
                                    safelisted_values = True
                                    break
                            parsed_arg_name = next((arg_tuple[0] for arg_tuple in event["arguments"] if arg["name"].lower() == arg_tuple[1]), arg["name"])
                            args_of_interest[parsed_arg_name] = arg["value"]
                    if args_of_interest and not safelisted_values:
                        interesting_event = {
                            "event": event["event"],
                            "object": event["object"],
                            "api": api,
                            "arguments": args_of_interest,
                            "source": "API"
                        }
                        if interesting_event["object"] == "Network" and interesting_event not in network_calls:
                            network_calls.append(interesting_event)
                        elif interesting_event["object"] == "Crypt" and interesting_event not in crypto_buffers:
                            crypto_buffers.append(interesting_event)
                        elif interesting_event["object"] in ["DLL", "Function"] and interesting_event not in loaded_modules:
                              loaded_modules.append(interesting_event)
                        elif interesting_event["object"] == "Service" and interesting_event not in services_events:
                            services_events.append(interesting_event)
                        elif interesting_event["object"] == "Driver" and interesting_event not in drivers_events:
                            drivers_events.append(interesting_event)
                        elif interesting_event["object"] == "Registry" and interesting_event not in registry_events:
                            registry_events.append(interesting_event)
                        elif interesting_event["object"] in ["File", "Dir"] and interesting_event not in file_events:
                            file_events.append(interesting_event)
                        elif interesting_event["event"] == "Misc" and interesting_event not in misc_events:
                            misc_events.append(interesting_event)
                        elif interesting_event["event"] in ["Hooking", "Unhooking"] and interesting_event not in hooking_events:
                            hooking_events.append(interesting_event)
                        elif interesting_event["object"] == "Process" and interesting_event not in process_events:
                            process_events.append(interesting_event)
                        elif interesting_event["object"] in ["NamedPipe", "Event"] and interesting_event not in interprocess_comm:
                            interprocess_comm.append(interesting_event)
        first_seen = process.get("first_seen")
        if first_seen and (isinstance(first_seen, float) or isinstance(first_seen, int)):
            first_seen = epoch_to_local_with_ms(first_seen, trunc=3)
        first_seen = first_seen.replace(",", ".")
        pid = process["process_id"]
        process_map[pid] = {
            "name": process["process_name"],
            "image": process["module_path"],
            "ppid": process["parent_id"],
            "start_time": first_seen,
            "command_line": process["environ"]["CommandLine"],
            "network_calls": network_calls,# object-->Network
            "crypto_buffers": crypto_buffers,# object-->Crypt
            "loaded_modules": loaded_modules,# object-->DLL object-->Function
            "services_events": services_events,# object-->Service
            "drivers_events": drivers_events,# object-->Driver
            "registry_events": registry_events,# object-->Registry
            "file_events": file_events,# object-->File object-->dir
            "misc_events": misc_events,# event-->Misc
            "hooking_events": hooking_events,# event-->Hooking event-->Unhooking
            "process_events": process_events,# object-->process
            "interprocess_comm": interprocess_comm,# object-->NamedPipe object-->Event
        }
    return process_map

def build_process_tree(
        processtree: List[Dict[str, Any]], 
        processtree_id_safelist: List[str],
    ):
    root_parent = 0
    result = {
        root_parent: {

        }
    }
    for node in processtree:
        if node.get("parent_id"):
            if node["parent_id"] not in result[root_parent].keys():
                result[root_parent][node["parent_id"]] = {node.get("pid"): {}}
            else:
                result[root_parent][node["parent_id"]][node.get("pid")] = {}
        if node.get("children") and len(node.get("children")) > 0:
            for child in node["children"]:
                result[root_parent][node["parent_id"]][node.get("pid")][child["pid"]] = {}
    return result

def process_sysmon(sysmon: List[Dict[str, Any]], safelist: Dict[str, Dict[str, List[str]]]):
    #Sysmon event id list:
    #Event ID 1: Process creation *
    #Event ID 2: A process changed a file creation time *
    #Event ID 3: Network connection *
    #Event ID 4: Sysmon service state changed
    #Event ID 5: Process terminated *
    #Event ID 6: Driver loaded *
    #Event ID 7: Image loaded *
    #Event ID 8: CreateRemoteThread *
    #Event ID 9: RawAccessRead *
    #Event ID 10: ProcessAccess *
    #Event ID 11: FileCreate *
    #Event ID 12: RegistryEvent (Object create and delete) *
    #Event ID 13: RegistryEvent (Value Set) *
    #Event ID 14: RegistryEvent (Key and Value Rename) *
    #Event ID 15: FileCreateStreamHash *
    #Event ID 16: ServiceConfigurationChange
    #Event ID 17: PipeEvent (Pipe Created) *
    #Event ID 18: PipeEvent (Pipe Connected) *
    #Event ID 19: WmiEvent (WmiEventFilter activity detected) *
    #Event ID 20: WmiEvent (WmiEventConsumer activity detected) *
    #Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected) *
    #Event ID 22: DNSEvent (DNS query) *
    #Event ID 23: FileDelete (File Delete archived)
    #Event ID 24: ClipboardChange (New content in the clipboard)
    #Event ID 25: ProcessTampering (Process image change)
    #Event ID 26: FileDeleteDetected (File Delete logged)
    #Event ID 27: FileBlockExecutable
    #Event ID 28: FileBlockShredding
    #Event ID 29: FileExecutableDetected
    #Event ID 255: Error
    #We care only for processes and network connection atm
    processes = {}
    for event in sysmon:
        event_id = int(event["System"]["EventID"])
        process: Dict[str, str] = {}
        event_data = event["EventData"]["Data"]
        if event_id in [1,2,5,8,9,10]:
            for data in event_data:
                name = data["@Name"].lower()
                text = data.get("#text")
                process["safelisted"] = False
                # Process Create and Terminate
                if name == "utctime" and event_id in [1, 5]:
                    t = ensure_time_format(text, LOCAL_FMT_WITH_MS)
                    if event_id == 1:
                        process["start_time"] = t
                    else:
                        process["start_time"] = MIN_TIME
                        process["end_time"] = t
                elif name == "utctime":
                    t = ensure_time_format(text, LOCAL_FMT_WITH_MS)
                    process["time_observed"] = t
                elif name in ["sourceprocessguid", "parentprocessguid"]:
                    process["pguid"] = text
                elif name in ["processguid", "targetprocessguid"]:
                    process["guid"] = text
                elif name in ["parentprocessid", "sourceprocessid"]:
                    process["ppid"] = int(text)
                elif name in ["processid", "targetprocessid"]:
                    process["pid"] = int(text)
                elif name in ["sourceimage"]:
                    process["pimage"] = text
                elif name in ["image", "targetimage"]:
                    # This is a Linux-specific behaviour in Sysmon
                    if text.endswith(" (deleted)"):
                        text = text[: text.index(" (deleted)")]
                    if not is_tag_safelisted(text, ["dynamic.process.file_name"], safelist):
                        process["image"] = text
                    else:
                        process["safelisted"] = True
                elif name in ["parentcommandline"]:
                    if not is_tag_safelisted(text, ["dynamic.process.command_line"], safelist):
                        process["pcommand_line"] = text
                elif name in ["commandline"]:
                    if not is_tag_safelisted(text, ["dynamic.process.command_line"], safelist):
                        process["command_line"] = text
                    else:
                        process["safelisted"] = True
                elif name == "originalfilename":
                    process["original_file_name"] = text
                elif name == "integritylevel":
                    process["integrity_level"] = text
                elif name == "hashes":
                    split_hash = text.split("=")
                    if len(split_hash) == 2:
                        _, hash_value = split_hash
                        process["image_hash"] = hash_value
            
            if not process.get("pid") or not process.get("guid") or not process.get("image") or not process.get("start_time"):
                continue

            process["event_id"] = event_id

            if process["pid"] not in processes.keys():
                processes[process["pid"]] = []
                processes[process["pid"]].append(process)
            elif f'{process["pid"]}-->{process["guid"]}' in processes.keys():
                processes[f'{process["pid"]}-->{process["guid"]}'].append(process)
            else:
                if process["guid"] in [proc["guid"] for proc in processes[process["pid"]]]:
                    processes[process["pid"]].append(process)
                else:
                    processes[f'{process["pid"]}-->{process["guid"]}'] = []
                    processes[f'{process["pid"]}-->{process["guid"]}'].append(process)
        elif event_id in [3,22]:
             # There are two main EventIDs that describe network events: 3 (Network connection) and 22 (DNS query)
            if event_id == 3:
                protocol = None
                network_conn = {
                    "src": None,
                    "dst": None,
                    "time": None,
                    "dport": None,
                    "sport": None,
                    "guid": None,
                    "pid": None,
                    "image": None,
                }
                for data in event["EventData"]["Data"]:
                    name = data["@Name"]
                    text = data.get("#text")
                    if name == "UtcTime":
                        network_conn["time"] = ensure_time_format(text, LOCAL_FMT_WITH_MS)
                    elif name == "ProcessGuid":
                        network_conn["guid"] = text
                    elif name == "ProcessId":
                        network_conn["pid"] = int(text)
                    elif name == "Image":
                        # Sysmon for Linux adds this to the image if the file is deleted.
                        if text.endswith(" (deleted)"):
                            text = text[: len(text) - len(" (deleted)")]
                        network_conn["image"] = text
                    elif name == "Protocol":
                        protocol = text.lower()
                    elif name == "SourceIp":
                        if re_match(IPV4_REGEX, text):
                            network_conn["src"] = text
                    elif name == "SourcePort":
                        network_conn["sport"] = int(text)
                    elif name == "DestinationIp":
                        if re_match(IPV4_REGEX, text):
                            network_conn["dst"] = text
                    elif name == "DestinationPort":
                        network_conn["dport"] = int(text)
                if any(network_conn[key] is None for key in network_conn.keys()) or not protocol:
                    continue

                network_conn["event_id"] = event_id

                if network_conn["pid"] in processes.keys():
                    processes[network_conn["pid"]].append(network_conn)
                elif f'{network_conn["pid"]}-->{network_conn["guid"]}' in processes.keys():
                    processes[f'{network_conn["pid"]}-->{network_conn["guid"]}'].append(network_conn)
                #if this point is reached, this is an orphan event
            elif event_id == 22:
                dns_query = {
                    "request": None,
                    "answers": [],
                    "first_seen": None,
                    "guid": None,
                    "pid": None,
                    "image": None,
                }
                for data in event["EventData"]["Data"]:
                    name = data["@Name"]
                    text = data.get("#text")
                    if text is None:
                        continue
                    if name == "UtcTime":
                        dns_query["first_seen"] = ensure_time_format(text, LOCAL_FMT_WITH_MS)
                    elif name == "ProcessGuid":
                        dns_query["guid"] = text
                    elif name == "ProcessId":
                        dns_query["pid"] = int(text)
                    elif name == "QueryName":
                        if not is_tag_safelisted(text, ["network.dynamic.domain"], safelist):
                            dns_query["request"] = text
                    elif name == "QueryResults":
                        records = text.split(';')
                        for record in records:
                            try:
                                dns_type_value = int(search(DNS_TYPE_REGEX, record).group(1))
                                dns_type = DNS_TYPE[dns_type_value] 
                            except IndexError:
                                dns_type = "A"
                            except AttributeError:
                                dns_type = "A"
                            ip = findall(IP_REGEX, record)
                            for item in ip:
                                if re_match(r"::ffff:\d{1,2}", item):
                                    continue
                                if {"data": item, "type": dns_type} not in dns_query["answers"]:
                                    dns_query["answers"].append({"data": item, "type": dns_type})
                            domain = findall(DOMAIN_REGEX, record)
                            for item in domain:
                                if {"data": item, "type": dns_type} not in dns_query["answers"]:
                                    dns_query["answers"].append({"data": item, "type": dns_type})
                    elif name == "Image":
                        # Sysmon for Linux adds this to the image if the file is deleted.
                        if text.endswith(" (deleted)"):
                            text = text[: len(text) - len(" (deleted)")]
                        dns_query["image"] = text

                if any(dns_query[key] is None for key in dns_query.keys()):
                    continue

                dns_query["event_id"] = event_id
                
                if dns_query["pid"] in processes.keys():
                    processes[dns_query["pid"]].append(dns_query)
                elif f'{dns_query["pid"]}-->{dns_query["guid"]}' in processes.keys():
                    processes[f'{dns_query["pid"]}-->{dns_query["guid"]}'].append(dns_query)
                #if this point is reached, this is an orphan event
    return processes

def process_ETW(artifacts: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(artifacts, Dict):
        return {}
    ETW_result = {}
    for artifact, path in artifacts.items():
        ETW_result[artifact] = {}
        with open(path, "rb") as etw_file:
            for entry in etw_file:
                try:
                    content = json.loads(entry.decode("utf-8").replace("\'", "\"").replace("None", "\"Null\""))
                except json.JSONDecodeError as e:
                    content = None
                    log.debug(f"Failed to decode {artifact} ETW json: {str(e)}")
                except Exception as e:
                    content = None
                    log.debug(f"General failure to read {artifact} ETW json: {str(e)}")
                if not isinstance(content, Dict) or not content:
                    continue
                if artifact == "dns":
                    if content["QueryType"] == "Query":
                        if content["QueryName"] not in ETW_result[artifact].keys():
                            ETW_result[artifact][content["QueryName"]] = {"pids": [content["ProcessId"]], "dns_server": content["DNS Server"], "responses": []}
                        elif content["ProcessId"] not in ETW_result[artifact][content["QueryName"]]["pids"]:
                            ETW_result[artifact][content["QueryName"]]["pids"].append(content["ProcessId"])
                    elif content["QueryType"] == "Response":
                        if content["QueryName"] not in ETW_result[artifact].keys():
                            continue
                        if content.get("QueryResults", None):
                            ETW_result[artifact][content["QueryName"]]["responses"].append(content["QueryResults"])
                elif artifact == "network":
                    if content["EventHeader"]["EventDescriptor"]["Id"] in [1002, 1033]: #TCPREQUESTCONNECT and TCPCONNECTTCBCOMPLETE
                        if content["EventHeader"]["ProcessId"] not in ETW_result[artifact].keys():
                            ETW_result[artifact][content["EventHeader"]["ProcessId"]] = []
                        src = None
                        src_port = -1
                        dst = None
                        dst_port = -1
                        src_match = re_match(ETW_ADDR_REGEX, content["LocalAddress"])
                        dst_match = re_match(ETW_ADDR_REGEX, content["RemoteAddress"])
                        if not src_match or not dst_match:
                            continue
                        try:
                            src = src_match.group(1)
                            src_port = src_match.group(2)
                            dst = dst_match.group(1)
                            dst_port = dst_match.group(2)
                        except Exception as e:
                            continue
                        timestamp = datetime(1601, 1, 1) + timedelta(seconds=content["EventHeader"]["TimeStamp"]/10000000)
                        event = {
                            "timestamp": format_time(timestamp, LOCAL_FMT_WITH_MS),
                            "type": content["Task Name"],
                            "src": src,
                            "src_port": src_port,
                            "dst": dst,
                            "dst_port": dst_port
                        }
                        ETW_result[artifact][content["EventHeader"]["ProcessId"]].append(event) 

                    if content["EventHeader"]["EventDescriptor"]["Id"] in [1169, 1170]: #UDPENDPOINTSENDMESSAGES and UdpEndpointReceiveMessages
                        if content["EventHeader"]["ProcessId"] not in ETW_result[artifact].keys():
                            ETW_result[artifact][content["EventHeader"]["ProcessId"]] = []
                        src = None
                        src_port = -1
                        dst = None
                        dst_port = -1
                        src_match = re_match(ETW_SOCK_ADDR_REGEX, content["LocalSockAddr"])
                        dst_match = re_match(ETW_SOCK_ADDR_REGEX, content["RemoteSockAddr"])
                        if not src_match or not dst_match:
                            continue
                        try:
                            src = src_match.group(1) if src_match.group(1) != "0:0" else "127.0.0.1"
                            src_port = src_match.group(2)
                            dst = dst_match.group(1) if dst_match.group(1) != "0:0" else "127.0.0.1"
                            dst_port = dst_match.group(2)
                        except Exception as e:
                            continue
                        timestamp = datetime(1601, 1, 1) + timedelta(seconds=content["EventHeader"]["TimeStamp"]/10000000)
                        event = {
                            "timestamp": format_time(timestamp, LOCAL_FMT_WITH_MS),
                            "type": content["Task Name"],
                            "src": src,
                            "src_port": src_port,
                            "dst": dst,
                            "dst_port": dst_port
                        }
                        ETW_result[artifact][content["EventHeader"]["ProcessId"]].append(event)

                   
                    if content["EventHeader"]["EventDescriptor"]["Id"] == 1422: #ICMPSENDRECV
                        if content["EventHeader"]["ProcessId"] not in ETW_result[artifact].keys():
                            ETW_result[artifact][content["EventHeader"]["ProcessId"]] = []
                        src = None
                        dst = None
                        src_match = re_match(IP_REGEX, content["SourceAddress"])
                        dst_match = re_match(IP_REGEX, content["DestAddress"])
                        if not src_match or not dst_match:
                            continue
                        try:
                            src = src_match.group(1)
                            src_port = src_match.group(2)
                            dst = dst_match.group(1)
                            dst_port = dst_match.group(2)
                        except Exception as e:
                            continue
                        timestamp = datetime(1601, 1, 1) + timedelta(seconds=content["EventHeader"]["TimeStamp"]/10000000)
                        event = {
                            "timestamp": format_time(timestamp, LOCAL_FMT_WITH_MS),
                            "type": content["Task Name"],
                            "src": src,
                            "dst": dst,
                            "transport_protocol" : content["IPTransportProtocol"],
                            "direction": content["PathDirection"],
                            "icmp_type": content["IcmpType"],
                            "icmp_code": content["IcmpCode"], 
                        }
                        ETW_result[artifact][content["EventHeader"]["ProcessId"]].append(event)

                elif artifact == "processes":
                    if content["EventHeader"]["EventDescriptor"]["Id"] == 1: #PROCESSSTART
                        if content["ProcessID"] not in ETW_result[artifact].keys():
                            try:
                                timestamp = epoch_to_local_with_ms(iso_to_epoch(content["CreateTime"].replace("\u200e", "")), 3)
                            except Exception as e:
                                timestamp = "-"
                            ETW_result[artifact][content["ProcessID"]] = {"claimed_ppid": content["ParentProcessID"], "real_ppid": content["EventHeader"]["ProcessId"], "image": content["ImageName"], "creation_time": timestamp}
                
                else:
                    log.debug(f"Invalid ETW content type {artifact}")
    return ETW_result    
    
def process_behavior(behaviour):
    processes = behaviour["processes"]
    if len(processes) < 1:
        return []
    else:
        parent_pid = processes[0]["parent_id"]
        initial_process = processes[0]["process_name"]
        initial_process_pid = processes[0]["process_id"]

        # Adding special case for iexplore, since HH creates two dumps for the main process and it's child
        if initial_process == "iexplore.exe":
            return [
                (process["process_id"], process["process_name"])
                for process in processes
                if process["parent_id"] == parent_pid
                or process["process_name"] == initial_process
                and process["parent_id"] == initial_process_pid
            ]
        else:
            return [
                (process["process_id"], process["process_name"])
                for process in processes
                if process["parent_id"] == parent_pid
            ]

def _remove_bytes_from_buffer(buffer: str) -> str:
    """
    This method removes byte characters from a buffer string
    """
    non_byte_chars = []
    for item in buffer.split("\\"):
        if not item:
            continue
        res = sub(BYTE_CHAR, "", item)
        if res and len(res) >= MIN_DOMAIN_CHARS:
            if res in ["http/1.1"]:
                continue
            non_byte_chars.append(res)
    return ",".join(non_byte_chars)

def convert_processtree_id_to_tree_id(processtree_id: str) -> str:
    possible_sha256 = ""
    for proc in processtree_id.split("|"):
        value_to_create_hash_from = (possible_sha256 + proc).encode()
        tree_id = sha256(value_to_create_hash_from).hexdigest()
        possible_sha256 = tree_id

    return tree_id

def _remove_network_http_noise(sigs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    This method removes the network_http signature if the network_cnc_http signature has been raised.
    This is because if the network_cnc_http signature has been raised, it is guaranteed that the network_http signature
    will also be raised and this signature will only create noise.
    :param sigs: The JSON of the signatures section from the report generated by CAPE
    :return: The modified (if applicable) JSON of the signatures section from the report generated by CAPE
    """
    if any(sig["name"] == "network_cnc_http" for sig in sigs):
        return [sig for sig in sigs if sig["name"] != "network_http"]
    else:
        return sigs
    
def _determine_dns_servers(network: Dict[str, Any], inetsim_dns_servers: List[str]) -> List[str]:
    # An assumption is being made here that the first UDP flow to port 53 is
    # for DNS.
    if len(network.get("udp", [])) > 0:
        dst = next(
            (udp_flow["dst"] for udp_flow in network["udp"] if udp_flow["dport"] == 53),
            None,
        )
        if dst:
            dns_servers = [dst]
        else:
            dns_servers = []
    else:
        dns_servers = []
    
    for item in inetsim_dns_servers:
        if item not in dns_servers:
            dns_servers.append(item)

    return dns_servers

def _remove_network_call(
    dom: str,
    dest_ip: str,
    dns_servers: List[str],
    dns_requests: Dict[str, List[Dict[str, Any]]],
    inetsim_network: IPv4Network,
    safelist: Dict[str, Dict[str, List[str]]],
) -> bool:
    list_of_all_answers = []
    for _, attempts in dns_requests.items():
        for attempt in attempts:
            if isinstance(attempt["answers"], List):
                list_of_all_answers.extend(attempt["answers"])
            elif attempt["answers"] == None:
                continue
            else:
                list_of_all_answers.append(attempt["answers"])
    # if domain is safe-listed
    if is_tag_safelisted(dom, ["network.dynamic.domain"], safelist):
        return True
    # if no domain and destination ip is safe-listed or is the dns server
    elif (not dom and is_tag_safelisted(dest_ip, ["network.dynamic.ip"], safelist)) or dest_ip in dns_servers:
        return True
    # if dest ip is noise
    elif dest_ip not in list_of_all_answers and ip_address(dest_ip) in inetsim_network:
        return True

    return False

def _massage_host_data(host: str) -> str:
    """
    This method tries to get the actual host out of the parsed "host" value
    :param host: The parsed "host" value
    :return: The actual host
    """
    if ":" in host:  # split on port if port exists
        host = host.split(":")[0]
    return host

def _massage_http_ex_data(
    host: str, dns_servers: List[str], dns_requests: Dict[str, List[Dict[str, Any]]], http_call: Dict[str, Any]
) -> Tuple[str, str, str, Dict[str, Any]]:
    """
    This method extracts key details from the parsed <http(s)>_ex protocol data
    :param host: The actual host
    :param dns_servers: A list of DNS servers
    :param dns_requests: A map of process IDs to process names, network calls, and decrypted buffers
    :param http_call: The parsed HTTP call data
    :return: A tuple of the URI reached out to, and the potentially modified parsed HTTP call data
    """
    path = http_call["uri"]
    if host in path:
        path = path.split(host)[1]

    uri = f"{http_call['protocol']}://{host}{path}"

    # The dst could be the nest IP, so we want to replace this
    if http_call["dst"] in dns_servers and any(host == item for item in dns_requests.keys()):
        for request, attempts in dns_requests.items():
            for attempt in attempts:
                if isinstance(attempt["answers"], List):
                    answers = attempt["answers"]
                elif attempt["answers"] == None:
                    continue
                else:
                    answers = [attempt["answers"]]
                    for answer in answers:
                        if isinstance(answer, Dict):
                            if answer["answer"].isdigit():
                                continue
                        elif isinstance(answer, str):
                            if answer.isdigit():
                                continue
                        if request == host:
                            http_call["dst"] = answer["answer"]
                            break

    return uri, http_call

def _get_important_fields_from_http_call(
    protocol: str,
    host: str,
    dns_servers: List[str],
    dns_requests: Dict[str, List[Dict[str, Any]]],
    http_call: Dict[str, Any],
) -> Tuple[str, int, str, Dict[str, Any]]:
    """
    This method extracts key details from the parsed <http(s)(_ex)> protocol data
    :param
    :param host: The actual host
    :param dns_servers: A list of DNS servers
    :param dns_requests: A map of process IDs to process names, network calls, and decrypted buffers
    :param http_call: The parsed HTTP call data
    :return: A tuple of the request data, destination port, URI reached out to, and the potentially modified parsed HTTP call data
    """
    # <protocol>_ex data is weird and requires special parsing
    if "ex" in protocol:
        uri, http_call = _massage_http_ex_data(host, dns_servers, dns_requests, http_call)
        request = http_call["request"]
        port = http_call["dport"]
    else:
        request = http_call["data"]
        port = http_call["port"]
        uri = http_call["uri"]
    return request, port, uri, http_call

def _is_http_call_safelisted(host: str, safelist: Dict[str, Dict[str, List[str]]], uri: str) -> bool:
    """
    This method checks to see if the host or uri is safelisted
    :param host: The actual host
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param uri: URI reached out to
    :return: A boolean representing if the parsed HTTP call data contains safelisted values
    """
    return (
        is_tag_safelisted(host, ["network.dynamic.ip", "network.dynamic.domain"], safelist)
        or is_tag_safelisted(uri, ["network.dynamic.uri"], safelist)
        or "/wpad.dat" in uri
        or not re_match(FULL_URI, uri)
    )

def _massage_body_paths(http_call: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """
    This method tries to get the body paths for the request and response objects out of the parsed "path" values
    :param http_call: The parsed HTTP call data
    :return: A tuple containing the path to the request/reponse body dumps
    """
    request_body_path = http_call.get("req", {}).get("path")
    response_body_path = http_call.get("resp", {}).get("path")

    if request_body_path:
        request_body_path = request_body_path[request_body_path.index("network/") :]
    if response_body_path:
        response_body_path = response_body_path[response_body_path.index("network/") :]

    return request_body_path, response_body_path

def _get_destination_ip(
    http_call: Dict[str, Any], dns_servers: List[str]
) -> Optional[str]:
    """
    This method returns the destination IP used for the HTTP call
    :param http_call: The parsed HTTP call data
    :param dns_servers: A list of DNS servers
    :param host: The actual host
    :param ontres: The Ontology Results class object
    :return: The destination IP reached out to, if it exists
    """
    destination_ip = None
    if http_call.get("dst") and http_call["dst"] not in dns_servers:
        destination_ip = http_call["dst"]
    return destination_ip

def _uris_are_equal_despite_discrepancies(api_uri: Optional[str], pcap_uri: str) -> bool:
    """
    Sometimes there are discrepancies between the URIs associated with an HTTP request between PCAP parsing and API call parsing
    Ex. http://<domain>:443 and https://<domain>:443/
    :param api_uri: The URI parsed from an API call
    :param pcap_uri: The URI parsed from PCAP traffic
    :return: A boolean indicating whether the two URIs are equal*
    """
    if api_uri and pcap_uri:
        # Okay so far so good
        if api_uri.startswith("https://") and pcap_uri.startswith("http://"):
            return _handle_similar_netloc_and_path(api_uri, pcap_uri)

    return False

def _handle_similar_netloc_and_path(api_uri: str, pcap_uri: str) -> bool:
    """
    This method handles the same netloc and path between API URLs and PCAP URLs
    :param api_uri: The URI parsed from an API call
    :param pcap_uri: The URI parsed from PCAP traffic
    :return: A boolean indicating whether the two netlocs and paths are equal*
    """
    # Getting warmer...
    api_domain_and_path = api_uri.split("://", 1)[1]
    pcap_domain_and_path = pcap_uri.split("://", 1)[1]

    if api_domain_and_path == pcap_domain_and_path:
        # Jackpot!
        return True

    # If no jackpot yet, here is another discrepancy
    elif (
        api_domain_and_path.endswith("/")
        and not pcap_domain_and_path.endswith("/")
        and api_domain_and_path.rstrip("/") == pcap_domain_and_path
    ):
        # Bingo bongo!
        return True

    return False

def _handle_http_headers(header_string: str) -> Dict[str, str]:
    """
    This method parses an HTTP header string and returns the parsed string in a nice dictionary
    :param header_string: The HTTP header string to be parsed
    :return: A dictionary that represents the HTTP headers
    """
    request_headers = {}
    if not header_string or "\r\n" not in header_string:
        return request_headers
    headers = header_string.split("\r\n")[1:]
    for header_pair in headers:
        if not header_pair:
            continue
        values = header_pair.split(": ")
        if len(values) == 2:
            header, value = values
            request_headers[header.replace("-", "")] = value
    return request_headers

def _create_signature_result_section(
    name: str,
    signature: Dict[str, Any],
    translated_score: int,
    ontres_sig: Signature,
    ontres: OntologyResults,
    process_map: Dict[int, Dict[str, Any]],
    safelist: Dict[str, Dict[str, List[str]]],
    uses_https_proxy_in_sandbox: bool,
    signature_map: Dict[str, Dict[str, Any]] = {},
) -> tuple[Optional[ResultMultiSection], List]:
    """
    This method creates a ResultMultiSection for the given signature
    :param name: The name of the signature
    :param signature: The details of the signature
    :param translated_score: The Assemblyline-adapted score of the signature
    :param ontres_sig: The signature for the Ontology Results
    :param ontres: The Ontology Results class object
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param uses_https_proxy_in_sandbox: A boolean indicating if a proxy is used in the sandbox architecture that
    decrypts and forwards HTTPS traffic
    :param signature_map: A map of all YARA signatures processed by Assemblyline and their current properties
    :return: A ResultMultiSection containing details about the signature,
             unless the signature is deemed a False Positive
    """
    sig_res = ResultMultiSection(f"Signature: {name}")
    description = signature.get("description", "No description for signature.")
    sig_res.add_section_part(TextSectionBody(body=description))
    _set_heuristic_signature(name, signature, sig_res, translated_score)
    _set_attack_ids(signature.get("ttp", {}), sig_res, ontres_sig)
    _set_families(signature.get("families", []), sig_res, ontres_sig)

    # Get the evidence that supports why the signature was raised
    mark_count = 0
    call_count = 0
    message_added = False
    attributes: List[Attribute] = list()
    action = SIGNATURE_TO_ATTRIBUTE_ACTION_MAP.get(name)
    fp_mark_count = 0
    iocs_found_in_data_res_sec: Optional[ResultTableSection] = None
    pids = []
    for mark in signature["data"]:
        if mark_count >= 10 and not message_added:
            sig_res.add_section_part(
                TextSectionBody(
                    body=f"There were {len(signature['data']) - mark_count - call_count} "
                    "more marks that were not displayed."
                )
            )
            message_added = True
        mark_body = KVSectionBody()

        # Check if the mark is a call
        if _is_mark_call(mark.keys()):
            call_count += 1
            _handle_mark_call(mark.get("pid"), action, attributes, ontres)
            if mark.get("pid") and mark.get("pid") not in pids:
                pids.append(mark.get("pid"))
        else:
            iocs_found_in_data_res_sec = _handle_mark_data(
                mark.items(),
                sig_res,
                mark_count,
                mark_body,
                attributes,
                process_map,
                safelist,
                ontres,
                iocs_found_in_data_res_sec,
                uses_https_proxy_in_sandbox,
                signature_map,
            )
            if mark_body.body:
                sig_res.add_section_part(mark_body)
                mark_count += 1
            else:
                fp_mark_count += 1

    if iocs_found_in_data_res_sec and iocs_found_in_data_res_sec.body:
        sig_res.add_subsection(iocs_found_in_data_res_sec)

    if attributes:
        [ontres_sig.add_attribute(attribute) for attribute in attributes]
    ontres_sig.update(name=name, score=translated_score)

    return (sig_res, pids)

def _is_mark_call(mark_keys: List[str]) -> bool:
    """
    This method determines if a mark is a "call" rather than "data"
    :param mark_keys: A list of mark keys
    :return: A boolean representing if the mark is a "call"
    """
    return all(k in ["type", "pid", "cid", "call"] for k in mark_keys)

def _handle_mark_call(
    pid: Optional[int], action: Optional[str], attributes: List[Attribute], ontres: OntologyResults
) -> None:
    """
    This method handles a mark that is a "call"
    :param pid: The process ID, if given, of the call
    :param action: The action representing the signature, as per the OntologyResults model for Signature
    :param attributes: A list of attribute objects
    :param ontres: The Ontology Results class object
    :return: None
    """
    # The way that this would work is that the marks of the signature contain a call followed by a non-call
    source = ontres.get_process_by_pid(pid)
    # If the source is the same as a previous attribute for the same signature, skip
    if source and all(
        attribute.action != action and attribute.source.as_primitives() != source.as_primitives()
        for attribute in attributes
    ):
        attribute = ontres.create_attribute(
            source=source.objectid,
            action=action,
        )
        attributes.append(attribute)

def _handle_mark_data(
    mark_items: List[Tuple[str, Any]],
    sig_res: ResultMultiSection,
    mark_count: int,
    mark_body: KVSectionBody,
    attributes: List[Attribute],
    process_map: Dict[int, Dict[str, Any]],
    safelist: Dict[str, Dict[str, List[str]]],
    ontres: OntologyResults,
    iocs_found_in_data_res_sec: Optional[ResultTableSection] = None,
    uses_https_proxy_in_sandbox: bool = False,
    signature_map: Dict[str, Dict[str, Any]] = {},
) -> None:
    """
    This method handles a mark that is "data"
    :param mark_items: A list of tuples representing the mark
    :param sig_res: The signature result section
    :param mark_count: The count representing the number of marks that have been added to the mark_body
    :param mark_body: The ResultSection body object
    :param attributes: A list of attribute objects
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param ontres: The Ontology Results class object
    :param iocs_found_in_data_res_sec: The result section containing any IOCs found in signature data
    :param uses_https_proxy_in_sandbox: A boolean indicating if a proxy is used in the sandbox architecture that
    decrypts and forwards HTTPS traffic
    :param signature_map: A map of all YARA signatures processed by Assemblyline and their current properties
    :return: None
    """
    for k, v in mark_items:
        if not v or k in MARK_KEYS_TO_NOT_DISPLAY or json.dumps({k: v}) in sig_res.section_body.body:
            continue

        # The mark_count limit only exists for display purposes
        if mark_count < 10:
            if isinstance(v, str) and len(v) > 512:
                v = truncate(v, 512)
            if isinstance(v, str) and is_tag_safelisted(
                v, ["network.dynamic.ip", "network.dynamic.uri", "network.dynamic.domain"], safelist
            ):
                continue

            mark_body.set_item(k, v)

        # Regardless of the mark_count limit, attempt to tag items. This type-casting is required in _tag_mark_values
        if isinstance(v, list):
            v = ",".join([item if isinstance(item, str) else str(item) for item in v])
        elif not isinstance(v, str):
            v = str(v)
        iocs_found_in_data_res_sec = _tag_mark_values(
            sig_res,
            k,
            v,
            attributes,
            process_map,
            ontres,
            iocs_found_in_data_res_sec,
            uses_https_proxy_in_sandbox,
            signature_map,
        )

    return iocs_found_in_data_res_sec

def _tag_mark_values(
    sig_res: ResultMultiSection,
    key: str,
    value: str,
    attributes: List[Attribute],
    process_map: Dict[int, Dict[str, Any]],
    ontres: OntologyResults,
    iocs_found_in_data_res_sec: Optional[ResultTableSection] = None,
    uses_https_proxy_in_sandbox: bool = False,
    signature_map: Dict[str, Dict[str, Any]] = {},
) -> Optional[ResultTableSection]:
    """
    This method tags a given value accordingly by the key
    :param sig_res: The signature result section
    :param key: The mark's key
    :param value: The mark's value for the given key
    :param attributes: A list of Attribute objects from the OntologyResults model
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param ontres: The Ontology Results class object
    :param iocs_found_in_data_res_sec: The result section containing any IOCs found in signature data
    :param uses_https_proxy_in_sandbox: A boolean indicating if a proxy is used in the sandbox architecture that
    decrypts and forwards HTTPS traffic
    :param signature_map: A map of all YARA signatures processed by Assemblyline and their current properties
    :return: None
    """
    delimiters = [":", "->", ",", " ", "("]
    if key.lower() in [
        "cookie",
        "process",
        "binary",
        "copy",
        "office_martian",
        "file",
        "service",
        "getasynckeystate",
        "setwindowshookexw",
    ]:
        if "process: " in value.lower():
            value = value.lower().replace("process: ", "")
        if any(delimiter in value for delimiter in delimiters):
            for delimiter in delimiters:
                if delimiter in value:
                    # Special case to not split if : is present but it's a file path with a drive
                    if delimiter == ":" and ":\\" in value:
                        continue
                    split_values = value.split(delimiter)
                    value = split_values[0].strip()
                    break
        _ = add_tag(sig_res, "dynamic.process.file_name", value)
    elif key.lower() in ["command", "service_path"]:
        _ = add_tag(sig_res, "dynamic.process.command_line", value)
    elif key.lower() in ["ip"]:
        if ":" in value and not search(IPV6_REGEX, value):
            split_values = value.split(":")
            _ = add_tag(sig_res, "network.dynamic.ip", split_values[0].strip())
            if "(" in split_values[1]:
                further_split = split_values[1].split("(")
                _ = add_tag(sig_res, "network.port", further_split[0].strip())
            else:
                _ = add_tag(sig_res, "network.port", split_values[1].strip())
        else:
            _ = add_tag(sig_res, "network.dynamic.ip", value)
    elif key.lower() in ["regkey"]:
        _ = add_tag(sig_res, "dynamic.registry_key", value)
    elif key.lower() in [
        "http_request",
        "url",
        "suspicious_request",
        "ioc",
        "request",
        "http_downloadurl",
    ]:
        if uses_https_proxy_in_sandbox:
            # Let's try to avoid misparsed data in the signatures
            value = convert_url_to_https(method="CONNECT", url=value)
        if key.lower() in ["request","suspicious_request","http_request"]:
            try:
                value = search(HTTP_REQUEST_REGEX, value).group(1)
            except IndexError:
                return
            except AttributeError:
                pass
        if add_tag(sig_res, "network.dynamic.uri", value) and attributes:
            # Determine which attribute is to be assigned the uri
            for attribute in attributes:
                process = ontres.get_process_by_guid(attribute.source.guid)
                if not process:
                    continue
                for network_call in process_map[process.pid]["network_calls"]:
                    if network_call["event"] in ["Connect", "Request_response"]:
                        args = network_call["arguments"]
                        if args.get("Service", 0) in ["http", "https", "HTTP", "HTTPS", "3"] or value in args.get("Buffer", "") or value in args.get("URL", ""):
                            attribute.update(uri=value)
                            break
    elif key.lower() in ["dynamicloader"]:
        _ = add_tag(sig_res, "file.pe.exports.function_name", value)
    elif key.endswith("_exe"):
        _ = add_tag(sig_res, "dynamic.process.file_name", key.replace("_", "."))
    elif key.lower() in ["hit"]:
        reg_match = search(YARA_RULE_EXTRACTOR, value)
        if reg_match and len(reg_match.regs) == 3:
            if reg_match.group(1):
                pid = int(reg_match.group(1))
                process_with_pid = ontres.get_process_by_pid(pid)
                if process_with_pid:
                    attribute = ontres.create_attribute(
                        source=process_with_pid.objectid,
                    )
                    attributes.append(attribute)
            rule_name = reg_match.group(2)
            # Find the appropriate source name for signature linking in the UI
            source_name = "CAPE"
            if signature_map:
                for sig_info in signature_map.values():
                    if sig_info["name"] == rule_name:
                        source_name = sig_info["source"]
                        break
            _ = add_tag(sig_res, "file.rule.cape", f"{source_name}.{rule_name}")
            if sig_res.heuristic:
                sig_res.heuristic.add_signature_id(rule_name.lower(), 500)
    elif key.lower() in ["domain"]:
        _ = add_tag(sig_res, "network.dynamic.domain", value)

    # Hunt for IOCs in the value
    else:
        if not iocs_found_in_data_res_sec:
            iocs_found_in_data_res_sec = ResultTableSection("IOCs found in Signature data")
        extract_iocs_from_text_blob(truncate(value, 5000), iocs_found_in_data_res_sec, is_network_static=True)
        if iocs_found_in_data_res_sec.body:
            return iocs_found_in_data_res_sec

def _set_heuristic_signature(
    name: str, signature: Dict[str, Any], sig_res: ResultMultiSection, translated_score: int
) -> None:
    """
    This method sets up the heuristic for each signature
    :param name: The name of the signature
    :param signature: The details of the signature
    :param sig_res: The signature result section
    :param translated_score: The Assemblyline-adapted score of the signature
    :return: None
    """
    sig_category = get_category(name)
    heuristic_id = 1
    if sig_category == "unknown":
        heuristic_id = 9999
        log.warning(f"Unknown signature detected: {signature}")
    if sig_category == "Capemon Yara Hit":
        heuristic_id = 2
    # Creating heuristic
    sig_res.set_heuristic(heuristic_id)

    # Adding signature and score
    if sig_category != "unknown":
        name = sig_category + ":" + name 
    sig_res.heuristic.add_signature_id(name, score=translated_score)

def _set_attack_ids(attack_ids: Dict[str, Dict[str, str]], sig_res: ResultMultiSection, ontres_sig: Signature) -> None:
    """
    This method sets the Mitre ATT&CK ID for the heuristic and the Ontology Results Signature
    :param attack_ids: A dictionary of ATT&CK IDs
    :param sig_res: The signature result section
    :param ontres_sig: The signature for the Ontology Results
    :return: None
    """
    for attack_id in attack_ids:
        if attack_id in revoke_map:
            attack_id = revoke_map[attack_id]
        sig_res.heuristic.add_attack_id(attack_id)
        ontres_sig.add_attack_id(attack_id)
    for attack_id in sig_res.heuristic.attack_ids:
        ontres_sig.add_attack_id(attack_id)

def _set_families(families: List[str], sig_res: ResultMultiSection, ontres_sig: Signature) -> None:
    """
    This method gets the signature family and tags it
    :param families: A list of families
    :param sig_res: The signature result section
    :param ontres_sig: The signature for the Ontology Results
    :return: None
    """
    sig_families = [family for family in families if family not in SKIPPED_FAMILIES]
    if len(sig_families) > 0:
        sig_res.add_section_part(TextSectionBody(body="\tFamilies: " + ",".join([safe_str(x) for x in sig_families])))
        _ = add_tag(sig_res, "dynamic.signature.family", sig_families)
        ontres_sig.set_malware_families(sig_families)

def _get_dns_sec(
    dns_requests: Dict[str, List[Dict[str, Any]]], safelist: Dict[str, Dict[str, List[str]]]
) -> ResultTableSection:
    """
    This method creates the result section for DNS traffic
    :param dns_requests: the mapping of resolved IPs and their corresponding domains
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: the result section containing details that we care about
    """
    answer_exists = False
    non_standard_dns_query_types: Set[str] = set()
    if dns_requests is None or len(dns_requests) == 0:
        return None
    dns_res_sec = ResultTableSection("Protocol: DNS")
    dns_res_sec.set_column_order(["domain", "answer", "type"])
    dns_res_sec.set_heuristic(1000)
    dns_body: List[Dict[str, str]] = []
    _ = add_tag(dns_res_sec, "network.protocol", "dns")

    for request, attempts in dns_requests.items():
        for attempt in attempts:
            request_type = attempt.get("type")
            if isinstance(attempt["answers"], List):
                answers = attempt["answers"]
            elif attempt["answers"] == None:
                continue
            else:
                answers = [attempt["answers"]]
            for answer in answers:
                _ = add_tag(dns_res_sec, "network.dynamic.ip", answer["answer"], safelist)
                if add_tag(dns_res_sec, "network.dynamic.domain", request, safelist):
                    if answer["answer"].isdigit():
                        dns_request = {
                            "domain": request,
                            "type": request_type,
                        }
                    else:
                        # If there is only UDP and no TCP traffic, then we need to tag the domains here:
                        dns_request = {
                            "domain": request,
                            "answer": answer["answer"],
                            "type": request_type,
                        }
                    dns_body.append(dns_request)
                answer_exists = True
            if request_type and request_type not in ["PTR", "A", "AAAA"]:
                non_standard_dns_query_types.add(request_type)
    [dns_res_sec.add_row(TableRow(**dns)) for dns in dns_body]

    if not answer_exists:
        # This is not worth failing the entire analysis over, but worth reporting.
        _ = ResultTextSection(
            title_text="DNS services are down!", body="Contact the CAPE administrator for details.", parent=dns_res_sec
        )

    if non_standard_dns_query_types:
        dns_query_heur = Heuristic(1009)
        dns_query_res = ResultTextSection(
            dns_query_heur.name, heuristic=dns_query_heur, body=dns_query_heur.description, parent=dns_res_sec
        )
        for dns_query_type in sorted(non_standard_dns_query_types):
            dns_query_res.add_line(f"\t-\t{dns_query_type}")

    return dns_res_sec

def _create_network_connection_for_network_flow(
    network_flow: Dict[str, Any], session: str, ontres: OntologyResults
):
    if network_flow["dest_port"] in [80, 443]:
        connection_type = NetworkConnection.HTTP
    elif network_flow["dest_port"] in [53]:
        connection_type = NetworkConnection.DNS
    else:
        connection_type = None
    nc_oid = NetworkConnectionModel.get_oid(
        {
            "source_ip": network_flow["src_ip"],
            "source_port": network_flow["src_port"],
            "destination_ip": network_flow["dest_ip"],
            "destination_port": network_flow["dest_port"],
            "transport_layer_protocol": network_flow["protocol"],
            "connection_type": connection_type,
        }
    )
    objectid = ontres.create_objectid(
        tag=NetworkConnectionModel.get_tag(
            {
                "destination_ip": network_flow["dest_ip"],
                "destination_port": network_flow["dest_port"],
            }
        ),
        ontology_id=nc_oid,
        session=session,
        time_observed=(
            epoch_to_local_with_ms(network_flow["timestamp"], trunc=3)
            if not isinstance(network_flow["timestamp"], str)
            else network_flow["timestamp"]
        ),
    )
    objectid.assign_guid()
    try:
        nc = ontres.create_network_connection(
            objectid=objectid,
            source_ip=network_flow["src_ip"],
            source_port=network_flow["src_port"],
            destination_ip=network_flow["dest_ip"],
            destination_port=network_flow["dest_port"],
            transport_layer_protocol=network_flow["protocol"],
            direction=NetworkConnection.OUTBOUND,
        )
    except ValueError as e:
        log.warning(
            f"{e}. The required values passed were:\n"
            f"objectid={objectid}\n"
            f"destination_ip={network_flow['dest_ip']}\n"
            f"destination_port={network_flow['dest_port']}\n"
            f"transport_layer_protocol={network_flow['protocol']}"
        )
        return None
    p_oid = ProcessModel.get_oid(
        {
            "pid": network_flow["pid"],
            "image": network_flow.get("image"),
        }
    )
    if network_flow.get("image"):
        nc.update_process(
            objectid=ontres.create_objectid(
                tag=Process.create_objectid_tag(network_flow.get("image")),
                ontology_id=p_oid,
                guid=network_flow.get("guid"),
                session=session,
            ),
            pid=network_flow["pid"],
            image=network_flow.get("image"),
            start_time=(
                epoch_to_local_with_ms(network_flow["timestamp"])
                if not isinstance(network_flow["timestamp"], str)
                else network_flow["timestamp"]
            ),
        )
    ontres.add_network_connection(nc)
    return nc

def _setup_network_connection_with_network_http(
    uri: str,
    http_call: Dict[str, Any],
    request_headers: Dict[str, str],
    response_headers: Dict[str, str],
    request_body_path: str,
    response_body_path: str,
    port: int,
    destination_ip: str,
    ontres: OntologyResults,
) -> Tuple[NetworkConnection, NetworkHTTP]:
    """
    This method sets up the linking of a NetworkConnection object with a new NetworkHTTP object
    :param uri: URI reached out to
    :param http_call: The parsed HTTP call data
    :param request_headers: A dictionary that represents the HTTP request headers
    :param response_headers: A dictionary that represents the HTTP response headers
    :param request_body_path: The path to the request body dump
    :param response_body_path:The path to the response body dump
    :param port: The destination port accessed
    :param destination_ip: The destination IP reached out to
    :param ontres: The Ontology Results class object
    :return: A tuple of the linked NetworkConnection object and the new NetworkHTTP object
    """
    # We can now create a NetworkHTTP object
    nh = _create_network_http(
        uri, http_call, request_headers, response_headers, request_body_path, response_body_path, ontres
    )

    destination_port = port
    nc = _get_network_connection_by_details(destination_ip, destination_port, ontres)

    # Check if a NetworkConnection object exists
    # A NetworkConnection already exists?!
    if nc:
        # Update!
        nc.update(http_details=nh, connection_type=NetworkConnection.HTTP)
    # A NetworkConnection does not??
    else:
        # Create a NetworkConnection object with a reference to the NetworkHTTP object we just created
        nc = _create_network_connection_for_http_call(http_call, destination_ip, destination_port, nh, ontres)

    return nc, nh

def _create_network_http(
    uri: str,
    http_call: Dict[str, Any],
    request_headers: Dict[str, str],
    response_headers: Dict[str, str],
    request_body_path: Optional[str],
    response_body_path: Optional[str],
    ontres: OntologyResults,
) -> NetworkHTTP:
    """
    This method is basically a wrapper for the OntologyResults create_network_http method
    :param uri: URI reached out to
    :param http_call: The parsed HTTP call data
    :param request_headers: A dictionary that represents the HTTP request headers
    :param response_headers: A dictionary that represents the HTTP response headers
    :param request_body_path: The path to the request body dump
    :param response_body_path:The path to the response body dump
    :param ontres: The Ontology Results class object
    :return: The NetworkHTTP object
    """
    return ontres.create_network_http(
        request_uri=uri,
        response_status_code=http_call.get("status"),
        request_method=http_call["method"],
        request_headers=request_headers,
        response_headers=response_headers,
        request_body_path=request_body_path,
        response_body_path=response_body_path,
    )

def _get_network_connection_by_details(
    destination_ip: str, destination_port: int, ontres: OntologyResults
) -> NetworkConnection:
    """
    This method is basically a wrapper for the OntologyResults get_network_connection_by_details method
    :param destination_ip: The destination IP reached out to
    :param destination_port: The destination port accessed
    :param ontres: The Ontology Results class object
    :return: The NetworkConnection object
    """
    return ontres.get_network_connection_by_details(
        destination_ip=destination_ip,
        destination_port=destination_port,
        direction=NetworkConnection.OUTBOUND,
        transport_layer_protocol=NetworkConnection.TCP,
    )

def _create_network_connection_for_http_call(
    http_call: Dict[str, Any], destination_ip: str, destination_port: int, nh: NetworkHTTP, ontres: OntologyResults
) -> NetworkConnection:
    """
    This method creates a NetworkConnection
    :param http_call: The parsed HTTP call data
    :param destination_ip: The destination IP reached out to
    :param destination_port: The destination port accessed
    :param nh: The NetworkHTTP object
    :param ontres: The Ontology Results class object
    :return: The new NetworkConnection object
    """
    if len(ontres.sandboxes) == 0:
        return
    session = ontres.sandboxes[-1].objectid.session
    source_ip = http_call.get("src")
    source_port = http_call.get("sport")
    nc_oid = NetworkConnectionModel.get_oid(
        {
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "transport_layer_protocol": NetworkConnection.TCP,
            "connection_type": NetworkConnection.HTTP,
            "http_details.request_uri": http_call.get("request_uri"),
        }
    )
    objectid = ontres.create_objectid(
        tag=NetworkConnectionModel.get_tag(
            {
                "destination_ip": destination_ip,
                "destination_port": destination_port,
            }
        ),
        ontology_id=nc_oid,
        session=session,
    )
    nc = ontres.create_network_connection(
        objectid=objectid,
        destination_ip=destination_ip,
        destination_port=destination_port,
        transport_layer_protocol=NetworkConnection.TCP,
        direction=NetworkConnection.OUTBOUND,
        source_ip=source_ip,
        source_port=source_port,
        http_details=nh,
        connection_type=NetworkConnection.HTTP,
    )
    ontres.add_network_connection(nc)
    return nc

def _process_non_http_traffic_over_http(network_res: ResultSection, unique_netflows: List[Dict[str, Any]]) -> None:
    """
    This method adds a result section detailing non-HTTP network traffic over ports commonly used for HTTP
    :param network_res: The result section that will contain the result section detailing this traffic, if any
    :param unique_netflows: Network flows observed during CAPE analysis
    :return: None
    """
    non_http_traffic_result_section = ResultTableSection("Non-HTTP Traffic Over HTTP Ports")
    non_http_traffic_result_section.set_column_order(
        ["timestamp", "protocol", "src_ip", "src_port", "domain", "dest_ip", "dest_port", "image", "pid"]
    )
    non_http_list: List[Dict[str, Any]] = []
    # If there was no HTTP/HTTPS calls made, then confirm that there was no suspicious
    for netflow in unique_netflows:
        if netflow["dest_port"] in [443, 80]:
            non_http_list.append(netflow)
            _ = add_tag(
                non_http_traffic_result_section,
                "network.dynamic.ip",
                netflow["dest_ip"],
            )
            _ = add_tag(
                non_http_traffic_result_section,
                "network.dynamic.domain",
                netflow["domain"],
            )
            _ = add_tag(non_http_traffic_result_section, "network.port", netflow["dest_port"])
    if len(non_http_list) > 0:
        non_http_traffic_result_section.set_heuristic(1005)
        [non_http_traffic_result_section.add_row(TableRow(**non_http)) for non_http in non_http_list]
        network_res.add_subsection(non_http_traffic_result_section)

def _process_unseen_iocs(
    network_res: ResultSection,
    process_map: Dict[int, Dict[str, Any]],
    ontres: OntologyResults,
    safelist: Dict[str, Dict[str, List[str]]],
) -> None:
    """
    This method adds a result section detailing unseen IOCs found in API calls but not network traffic
    :param network_res: The result section that will contain the result section detailing this traffic, if any
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param ontres: The Ontology Results class object
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    unseen_iocs_heur = Heuristic(1013)
    possibly_unseen_iocs_res = ResultTableSection(unseen_iocs_heur.name, heuristic=unseen_iocs_heur)
    seen_domains = [dns_netflow.domain for dns_netflow in ontres.dns_netflows]
    seen_ips = [netflow.destination_ip for netflow in ontres.netflows]
    seen_uris = [http_netflow.request_uri for http_netflow in ontres.http_netflows]

    for _, process_details in process_map.items():
        for network_call in process_details["network_calls"]:
            iocs = [ioc for arg_name, ioc in network_call["arguments"].items() if arg_name in ["HostName", "IP", "URL", "Proxy"]]
            for ioc in iocs:
                if not _api_ioc_in_network_traffic(ioc, seen_domains + seen_ips + seen_uris):
                    extract_iocs_from_text_blob(
                        ioc,
                        possibly_unseen_iocs_res,
                        enforce_char_min=True,
                        safelist=safelist,
                        is_network_static=True,
                    )

    if possibly_unseen_iocs_res.body:
        possibly_seen_body = json.loads(possibly_unseen_iocs_res.section_body.body)
        unseen_iocs_res = ResultTableSection(unseen_iocs_heur.name, heuristic=unseen_iocs_heur)
        for item in possibly_seen_body:
            # We don't care about uri paths in this scenario
            if item["ioc_type"] == "uri_path":
                continue
            if _api_ioc_in_network_traffic(item["ioc"], seen_domains + seen_ips + seen_uris):
                continue
            if re_match(FULL_URI, item["ioc"]):
                ioc = _massage_api_urls(item["ioc"])
            else:
                ioc = item["ioc"]
            unseen_iocs_res.add_row(TableRow({"ioc_type": item["ioc_type"], "ioc": ioc}))
            _ = add_tag(unseen_iocs_res, "network.dynamic.uri", ioc, safelist)

        if unseen_iocs_res.body:
            network_res.add_subsection(unseen_iocs_res)

def _api_ioc_in_network_traffic(ioc: str, ioc_list: List[str]) -> bool:
    """
    This method checks if an IOC found in an API call is seen in network traffic
    :param ioc: The IOC found in an API call to check for
    :param ioc_list: The list of IOCs found in the network traffic
    :return: A boolean indicating that the API call IOC was present in
    the network traffic
    """
    if ioc in ioc_list:
        return True

    if re_match(FULL_URI, ioc):
        altered_ioc = _massage_api_urls(ioc)
        if altered_ioc in ioc_list:
            return True

    for seen_ioc in ioc_list:
        if re_match(FULL_URI, ioc) and re_match(FULL_URI, seen_ioc):
            if _handle_similar_netloc_and_path(ioc, seen_ioc):
                return True
            if _uris_are_equal_despite_discrepancies(ioc, seen_ioc):
                return True

    return False

def _massage_api_urls(api_url: str) -> str:
    """
    This method massages a URL found in an API call
    :param api_url: A URL found in an API call
    :return: A potentially massaged URL found in an
    """
    altered_api_url: Optional[str] = None
    # API call data requires some massaging. For instance, unnecessary ports in URIs
    if api_url.startswith("http://") and ":80" in api_url:
        altered_api_url = api_url.replace(":80", "")
    elif api_url.startswith("https://") and ":443" in api_url:
        altered_api_url = api_url.replace(":443", "")

    if altered_api_url:
        return altered_api_url
    return api_url

def same_dictionaries(d1, d2):
    if not isinstance(d1, dict) or not isinstance(d2, dict):
        if isinstance(d1, List) and isinstance(d2, List):
            if len(d1) == 0 and len(d2) == 0:
                 return True
            elif len(d1) != len(d2):
                return False
            for index in range(0, len(d1)):
                if d1[index] not in d2 and not (isinstance(d1[index], dict) and isinstance(d2[index], dict)):
                    return False
                elif isinstance(d1[index], dict) and isinstance(d2[index], dict):
                    return any([same_dictionaries(d1[index], d2[i]) for i in range(0, len(d1))])
            return d1.__hash__ == d2.__hash__
        elif d1 == d2:
            return True
        else:
            return False
    if len(d1) != len(d2):
        return False
    for key in d1:
        if key not in d2 or not same_dictionaries(d1[key], d2[key]):
            return False
    return True

class Sandbox_Validator(Validator):
    def _check_with_is_time_format_valid(self, field, value):
        valid_format = False
        try:
            if isinstance(value, str):
                if value == "-":
                    valid_format = True
                else:
                    strptime(value, LOCAL_FMT_WITH_MS)
                    valid_format = True
        except Exception as e:
            pass
        if not valid_format:
            self._error(field, "The time format is invalid")

def validate_sandbox_event(event_dict, type):
    if not isinstance(event_dict, Dict):
        return False
    needed_normalization = False
    process_schema = {
            "image": {"type": 'string', "required": True}, 
            "start_time": {"type": 'string', "required": True, "check_with": "is_time_format_valid"},
            "end_time": {"type": 'string', "nullable": True, "check_with": "is_time_format_valid"},
            "pid": {"type": "integer", "required": True, 'coerce': int, "min": 0, "max": DWORD_MAX},
            "ppid": {"type": "integer", "required": True, 'coerce': int, "min": 0, "max": DWORD_MAX},
            "command_line": {"type": 'string', "nullable": True, "maxlength": 1024},
            "safelisted": {"type": 'boolean', "required": True},
            "integrity_level": {"type": "string", "nullable": True, "allowed": ["low", "medium", "high", "system", "appcontainer"]},
            "image_hash": {"type": "string", "nullable": True, "regex": r'^[A-Fa-f0-9]{64}$'},
            "original_file_name": {"type": "string", "nullable": True},
            "file_count": {"type": "integer", 'coerce': int, "min": 0},
            "registry_count": {"type": "integer", 'coerce': int, "min":0},
            "sources": {"type": "list", "nullable": True, "empty": True, "schema": {"type": "string"}}
    }
    attack_schema = {
        "attack_id" : {"type": "string", "required": True},
        "pattern": {"type": "string", "required": True},
        "categories": {"type": "list", "required": True, "nullable": True, "empty": True, "schema": {"type": "string"}}
    }
    signature_schema = {
            "name": {"type": 'string', "required": True, "maxlength": 256},
            "type": {"type": 'string', "required": True, "allowed": ["CUCKOO", "CAPE"]},
            "classification": {"type": "string", "required": True},
            "attacks": {"type": "list", "required": True, "empty": True, "schema": {"type": "dict", "schema": attack_schema}},
            "actors": {"type": "list", "required": True, "empty": True, "schema": {"type": "string"}},
            "malware_families": {"type": "list", "required": True, "empty": True, "schema": {"type": "string"}},
            "data": {"type": "list", "required": True, "empty": True, "schema": {"type": "dict", "empty": False}},
            "score": {"type": "integer", "required": True, 'coerce': int, "min": 0, "max": DWORD_MAX},
            "pid": {"type": "list", "required": True, "nullable": True, "empty": True, "schema": {"type": "integer", "required": True, 'coerce': int, "min": 0, "max": DWORD_MAX}},
            "description": {"type": "string", "required": True, "empty": True, "maxlength": 256},
            "sources": {"type": "list", "nullable": True, "empty": True, "schema": {"type": "string"}}
    }
    DOMAIN_REGEX, IP_REGEX
    dns_connection_schema = {
        "domain": {"type": "string", "required": True, 'anyof_regex': [DOMAIN_REGEX, IP_REGEX, REVERSE_DNS_REGEX]},
        "resolved_ips": {"type": "list", "nullable": True, "empty": True, "schema": {}},
        "resolved_domains": {"type": "list", "nullable": True, "empty": True, "schema": {}},
        "lookup_type": {"type": "string", "required": True, "allowed": list(DNS_TYPE.values())},

    }
    http_connection_schema = {
        "request_uri": {"type": "string", "required": True, "regex": FULL_URI},
        "request_method": {"type": "string", "required": True},
        "request_headers": {"type": "dict", "nullable": True, "empty": True, "schema": {"type": "string"}},
        "response_headers": {"type": "dict", "nullable": True, "empty": True, "schema": {"type": "string"}},
        "request_body": {"type": "string", "nullable": True, "empty": True},
        "response_status_code": {"type": "integer", "nullable": True, 'coerce': int, "min": 0},
        "response_body": {"type": "string", "nullable": True, "empty": True},
        "request_body_path": {"type": "string", "regex": URI_PATH},
        "response_body_path": {"type": "string", "regex": URI_PATH},
        "response_content_fileinfo": {"type": "dict",  "nullable": True, "empty": True, "schema": {"type": "dict"}},
        "response_content_mimetype": {"type": "string", "nullable": True, "empty": True}
    }
    smtp_connection_schema = {
        "type": "dict"
    }
    network_connection_schema = {
            "destination_ip": {"type": "string", "required": True, "regex": IP_REGEX},
            "destination_port": {"type": "integer", "required": True, 'coerce': int, "min": 0, "max": MAX_PORT_NUMBER},
            "transport_layer_protocol": {"type": "string", "required": True, "allowed": [NetworkConnection.TCP, NetworkConnection.UDP]},
            "direction": {"type": "string", "required": True, "allowed": [NetworkConnection.OUTBOUND, NetworkConnection.INBOUND, NetworkConnection.UNKNOWN]},
            "process": {"type": "integer", "nullable": True, 'coerce': int, "min": 0, "max": DWORD_MAX},
            "source_ip": {"type": "string", "nullable": True, "empty": True, "regex": IP_REGEX},
            "source_port": {"type": "integer", "nullable": True, "empty": True, 'coerce': int, "min": 0, "max": MAX_PORT_NUMBER},
            "http_details": {"type": "dict", "nullable": True, "empty": True, "schema": http_connection_schema},
            "dns_details": {"type": "dict", "nullable": True, "empty": True, "schema": dns_connection_schema},
            "smtp_details": {"type": "dict", "nullable": True, "empty": True, "schema": smtp_connection_schema},
            "connection_type": {"type": "string", "required": True, "nullable": True, "allowed": [NetworkConnection.HTTP, NetworkConnection.DNS]},
            "time_observed": {"type": 'string', "nullable": True, "empty": True, "check_with": "is_time_format_valid"},
            "sources": {"type": "list", "nullable": True, "empty": True, "schema": {"type": "string"}}
    }
    machine_metadata_schema = {
        "ip": {"type": "string", "required": True, "regex": IP_REGEX},
        "hypervisor": {"type": "string", "required": True, "empty": True, "nullable": True, "maxlength": 256},
        "hostname": {"type": "string", "required": True, 'anyof_regex': [DOMAIN_REGEX, IP_REGEX]},
        "platform": {"type": "string", "required": True, "empty": True, "nullable": True, "maxlength": 256},
        "version": {"type": "string", "required": True, "empty": True, "nullable": True, "maxlength": 256},
        "architecture": {"type": "string", "required": True, "empty": True, "nullable": True, "maxlength": 256}
    }
    analysis_metadata_schema = {
        "start_time": {"type": 'string', "required": True, "check_with": "is_time_format_valid"},
        "task_id": {"type": "integer", "required": True, 'coerce': int, "min": 0, "max": DWORD_MAX},
        "end_time": {"type": 'string', "required": True, "check_with": "is_time_format_valid"},
        "routing": {"type": "string", "required": True, "allowed": ROUTING_LIST},
        "machine_metadata": {"type": "dict", "nullable": True, "empty": True, "schema": machine_metadata_schema},
        "window_size": {"type": "string", "nullable": True, "empty": True}
    }
    analysis_info_schema = {
        "analysis_metadata": {"type": "dict", "required": True, "schema": analysis_metadata_schema},
        "sandbox_name": {"type": "string", "required": True, "allowed": ["CAPE"]},
        "sandbox_version": {"type": "string", "required": True, "maxlength": 64}
    }
    complete_schema = {
            "signatures": {"type": "list", "required": True, "nullable": True, "empty": True, "schema": { "type": "dict", "schema": signature_schema}},
            "network_connections": {"type": "list", "required": True, "nullable": True, "empty": True, "schema": { "type": "dict", "schema": network_connection_schema}},
            "processes": {"type": "list", "required": True, "schema": { "type": "dict", "schema": process_schema}},
            "analysis_information": {"type": "dict", "required": True, "schema": analysis_info_schema},
        }
    used_schema = {}
    if type == "process":
        used_schema = process_schema
        identifier = event_dict.get("pid", -1)
    elif type == "signature":
        used_schema = signature_schema
        identifier = event_dict.get("name", "")
    elif type == "network_connection":
        used_schema = network_connection_schema
        dest = event_dict.get("destination_ip", " ")
        dest_port = event_dict.get("destination_port", 0)
        src = event_dict.get("source_ip", " ")
        src_port = event_dict.get("source_port", 0)
        identifier = f"{src}:{src_port}-->{dest}:{dest_port}"
    elif type == "complete":
        used_schema = complete_schema
        identifier = "Sandbox_full_schema"
    else:
        log.debug(f"Invalid format. Skipping {identifier}")
        return False
    v = Sandbox_Validator(used_schema, purge_unknown=True)
    initial_event_dict = event_dict
    event_dict = v.normalized(event_dict, always_return_document = True)
    if not same_dictionaries(initial_event_dict, event_dict):
        needed_normalization = True
    return_value = v.validate(event_dict)
    if not return_value:
        log.debug(f"Invalid data format for event : {identifier} --> {v.errors}")
        return False
    else:
        if needed_normalization:
            return event_dict
        else:
            return True

def main(argv):

    # pip install PyYAML
    import yaml
    from assemblyline.common.heuristics import HeuristicHandler, InvalidHeuristicException
    from assemblyline_v4_service.common.base import ServiceBase
    from assemblyline_v4_service.common.helper import get_heuristics
    from assemblyline_v4_service.common.result import Result
    from cape.safe_process_tree_leaf_hashes import SAFE_PROCESS_TREE_LEAF_HASHES
    log.setLevel(DEBUG)
    report_path = argv[1]
    file_ext = argv[2]
    random_ip_range = argv[3]
    routing = argv[4]
    safelist_path = argv[5]
    custom_processtree_id_safelist = json.loads(argv[6])
    inetsim_dns_servers = json.loads(argv[7])
    uses_https_proxy_in_sandbox = True if argv[8] == "True" else False
    suspicious_accepted_languages = json.loads(argv[9])

    with open(safelist_path, "r") as f:
        safelist = yaml.safe_load(f)
    safelist["regex"]["network.dynamic.ip"].append(random_ip_range.replace(".", "\\.").replace("0/24", ".*"))

    ontres = OntologyResults(service_name="CAPE")

    with open(report_path, "r") as f:
        api_report = json.loads(f.read())

    result = Result()
    al_result = ResultSection("Parent")
    result.add_section(al_result)
    machine_info = {
        "Name": "blahblahwin10x86",
        "Manager": "blah",
        "Platform": "Windows",
        "IP": "1.1.1.1",
        "Tags": [],
    }

    custom_tree_id_safelist = list(SAFE_PROCESS_TREE_LEAF_HASHES.values())
    custom_tree_id_safelist.extend(
        [
            convert_processtree_id_to_tree_id(item)
            for item in custom_processtree_id_safelist
            if item not in custom_tree_id_safelist
        ]
    )
    task_dir = report_path.replace("reports/lite.json", "") if "reports/lite.json" in report_path else None
    cape_artifact_pids, main_process_tuples, process_events = generate_al_result(
        api_report,
        al_result,
        file_ext,
        random_ip_range,
        routing,
        safelist,
        machine_info,
        ontres,
        custom_tree_id_safelist,
        inetsim_dns_servers,
        uses_https_proxy_in_sandbox,
        suspicious_accepted_languages,
        None,
        task_dir
    )

    service = ServiceBase()

    ontres.preprocess_ontology(custom_tree_id_safelist)
    # Print the ontres
    print(json.dumps(ontres.as_primitives(), indent=4))
    with open("result_ontology.json", "w") as output:
        json.dump(ontres.as_primitives(), output, indent=4)
    attach_dynamic_ontology(service, ontres)

    # Convert Result object to dict
    output = dict(
        result=result.finalize(),
    )

    # Load heuristics
    heuristics = get_heuristics()

    # Transform heuristics and calculate score
    total_score = 0
    for section in output["result"]["sections"]:
        if section["heuristic"]:
            heur_id = section["heuristic"]["heur_id"]

            try:
                section["heuristic"], new_tags = HeuristicHandler().service_heuristic_to_result_heuristic(
                    section["heuristic"], heuristics
                )
                for tag in new_tags:
                    section["tags"].setdefault(tag[0], [])
                    if tag[1] not in section["tags"][tag[0]]:
                        section["tags"][tag[0]].append(tag[1])
                total_score += section["heuristic"]["score"]
            except InvalidHeuristicException:
                section["heuristic"] = None
            section["heuristic"]["name"] = heuristics[heur_id]["name"]
    output["result"]["score"] = total_score

    # Print the result
    print(json.dumps(output, indent=4))
    with open("result.json", "w") as result:
        json.dump(output, result, indent=4)
    
    with open("Section.json", "w") as f:
        json.dump(process_events ,f)

if __name__ == "__main__":
    from sys import argv
    main(argv)
