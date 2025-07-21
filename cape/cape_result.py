import json
import os
from collections import defaultdict
from datetime import datetime
from hashlib import sha256
from ipaddress import IPv4Network, ip_address, ip_network
from logging import getLogger
from re import compile as re_compile
from re import match as re_match
from re import search, sub
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import pefile
import lief
from peutils import is_valid

from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline.common.attack_map import revoke_map
from assemblyline.common.identify import CUSTOM_BATCH_ID, CUSTOM_PS1_ID
from assemblyline.common.isotime import epoch_to_local_with_ms, format_time, local_to_local_with_ms
from assemblyline.common.net import is_valid_ip
from assemblyline.common.str_utils import safe_str, truncate
from assemblyline.odm.base import FULL_URI
from assemblyline.odm.models.ontology.results import Process as ProcessModel
from assemblyline.odm.models.ontology.results import Sandbox as SandboxModel
from assemblyline.odm.models.ontology.results import Signature as SignatureModel
from assemblyline.odm.models.ontology.results.network import NetworkConnection as NetworkConnectionModel
from assemblyline_service_utilities.common.dynamic_service_helper import (
    MAX_TIME,
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
from assemblyline_service_utilities.common.sysmon_helper import (
    UNKNOWN_PROCESS,
    convert_sysmon_network,
    convert_sysmon_processes,
)
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
)
from cape.signatures import CAPE_DROPPED_SIGNATURES, SIGNATURE_TO_ATTRIBUTE_ACTION_MAP, get_category_id
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
# Custom regex for finding uris in a text blob
UNIQUE_IP_LIMIT = 100
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
# Signature Processing Constants
SKIPPED_FAMILIES = ["generic"]

INETSIM = "INetSim"
CONNECT_API_CALLS = [
    "connect",
    "InternetConnectW",
    "InternetConnectA",
    "WSAConnect",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "WinHttpConnect",
    "WSAConnectByNameW",
]
DNS_API_CALLS = [
    "getaddrinfo",
    "InternetConnectW",
    "InternetConnectA",
    "GetAddrInfoW",
    "gethostbyname",
    "DnsQuery_A",
    "DnsQuery_UTF8",
    "DnsQuery_W",
]
HTTP_API_CALLS = [
    "send",
    "InternetConnectW",
    "InternetConnectA",
    "URLDownloadToFileW",
    "InternetCrackUrlA",
    "InternetCrackUrlW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "WinHttpConnect",
    "WSASend",
    "URLDownloadToCacheFileW",
]
BUFFER_API_CALLS = [
    "send",
    "sendto",
    "recv",
    "recvfrom",
    "WSARecv",
    "WSARecvFrom",
    "WSASend",
    "WSASendTo",
    "WSASendMsg",
    "SslEncryptPacket",
    "SslDecryptPacket",
    "InternetReadFile",
    "InternetWriteFile",
]
CRYPT_BUFFER_CALLS = [
    "CryptDecrypt",
    "CryptEncrypt",
    "BCryptDecrypt",
    "BCryptEncrypt",
    "NCryptDecrypt",
    "NCryptEncrypt",
]
MISC_BUFFER_CALLS = ["OutputDebugStringA", "OutputDebugStringW"]
SUSPICIOUS_USER_AGENTS = ["Microsoft BITS", "Excel Service"]
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
ANALYSIS_ERRORS = "Analysis Errors"
# Substring of Warning Message from
# https://github.com/cuckoosandbox/cuckoo/blob/50452a39ff7c3e0c4c94d114bc6317101633b958/cuckoo/core/guest.py#L561
GUEST_LOSING_CONNNECTIVITY = "Virtual Machine /status failed. This can indicate the guest losing network connectivity"
# Substring of Error Message from
# https://github.com/cuckoosandbox/cuckoo/blob/50452a39ff7c3e0c4c94d114bc6317101633b958/cuckoo/core/scheduler.py#L572
GUEST_CANNOT_REACH_HOST = (
    "it appears that this Virtual Machine hasn't been configured properly "
    "as the CAPE Host wasn't able to connect to the Guest."
)
GUEST_LOST_CONNECTIVITY = 5
SIGNATURES_SECTION_TITLE = "Signatures"
ENCRYPTED_BUFFER_LIMIT = 25
SYSTEM_PROCESS_ID = 4
MARK_KEYS_TO_NOT_DISPLAY = ["data_being_encrypted"]
BUFFER_ROW_LIMIT_PER_SOURCE_PER_PROCESS = 10
YARA_RULE_EXTRACTOR = r"(?:(?:PID )?([0-9]{2,4}))?.*'(.\w+)'"
BYTE_CHAR = "x[a-z0-9]{2}"

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
BAT_COMMANDS_PATH = os.path.join("/tmp", "commands.bat")
PS1_COMMANDS_PATH = os.path.join("/tmp", "commands.ps1")
BUFFER_PATH = os.path.join("/tmp", "buffers")

PE_INDICATORS = [b"MZ", b"This program cannot be run in DOS mode"]


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

    if info:
        process_info(info, al_result, ontres)

    if machine_info:
        process_machine_info(machine_info, ontres)

    if debug:
        # Ransomware tends to cause issues with CAPE's analysis modules, and including the associated analysis errors
        # creates unnecessary noise to include this
        if not any("ransomware" in sig["name"] for sig in sigs):
            process_debug(debug, al_result)

    process_map = get_process_map(behaviour.get("processes", {}), safelist)

    if sysmon:
        convert_sysmon_processes(sysmon, safelist, ontres)
        convert_sysmon_network(sysmon, network, safelist)

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
        else:
            # Otherwise, moving on!
            main_process_tuples = process_behaviour(behaviour, process_map, safelist, ontres)

    if ontres.get_processes():
        _update_process_map(process_map, ontres.get_processes())

    is_process_martian = False

    if network:
        process_network(
            network,
            al_result,
            validated_random_ip_range,
            routing,
            process_map,
            safelist,
            ontres,
            inetsim_dns_servers,
            uses_https_proxy_in_sandbox,
            suspicious_accepted_languages,
        )

    if sigs:
        is_process_martian = process_signatures(
            sigs, process_map, al_result, ontres, safelist, uses_https_proxy_in_sandbox, signature_map
        )

    build_process_tree(al_result, is_process_martian, ontres, processtree_id_safelist)

    process_all_events(al_result, ontres, processtree_id_safelist)

    if curtain:
        process_curtain(curtain, al_result, process_map)

    if hollowshunter:
        process_hollowshunter(hollowshunter, al_result, process_map)

    if process_map:
        process_buffers(process_map, safelist, al_result)

    cape_artifact_pids: Dict[str, int] = {}
    if cape:
        cape_artifact_pids = process_cape(cape, al_result)

    return cape_artifact_pids, main_process_tuples


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
    info_res = ResultKeyValueSection("Analysis Information")
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


def process_behaviour(
    behaviour: Dict[str, Any],
    process_map: Dict[int, Dict[str, Any]],
    safelist: Dict[str, Dict[str, List[str]]],
    ontres: OntologyResults,
) -> List[Tuple[int, str]]:
    """
    This method processes the behaviour section of the CAPE report, adding anything noteworthy to the
    Assemblyline report
    :param behaviour: The JSON of the behaviour section from the report generated by CAPE
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param ontres: The Ontology Results class object
    :return: A list of tuples representing both the PID of the initial process and the process name
    """
    # Preparing CAPE processes to match the OntologyResults format
    processes = behaviour["processes"]
    if processes:
        convert_cape_processes(processes, process_map, safelist, ontres)

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


def get_process_api_sums(apistats: Dict[str, Dict[str, int]]) -> Dict[str, int]:
    """
    This method calculates the sum of unique process calls per process
    :param apistats: A map of the number of process calls made by processes
    :return: A map of process calls and how many times those process calls were made
    """
    # Get the total number of api calls per pid
    api_sums: Dict[str, int] = {}
    for pid in apistats:
        api_sums[pid] = 0
        process_apistats = apistats[pid]
        for api_call in process_apistats:
            api_sums[pid] += process_apistats[api_call]
    return api_sums


def convert_cape_processes(
    cape_processes: List[Dict[str, Any]],
    process_map: Dict[int, Dict[str, Any]],
    safelist: Dict[str, Dict[str, List[str]]],
    ontres: OntologyResults,
) -> None:
    """
    This method converts processes observed in CAPE to the format supported by the OntologyResults helper class
    :param cape_processes: A list of processes observed during the analysis of the task
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param ontres: The Ontology Results class object
    :return: None
    """
    session = ontres.sandboxes[-1].objectid.session
    for item in cape_processes:
        process_path = item.get("module_path")
        command_line = item["environ"].get("CommandLine")
        if (
            not process_path
            or not command_line
            or is_tag_safelisted(command_line, ["dynamic.process.command_line"], safelist)
        ):
            continue

        first_seen = item["first_seen"].replace(",", ".")

        if not item.get("guid"):
            guid = ontres.get_guid_by_pid_and_time(item["process_id"], first_seen)
        else:
            guid = item.get("guid")

        if not item.get("pguid"):
            pguid = ontres.get_pguid_by_pid_and_time(item["process_id"], first_seen)
        else:
            pguid = item.get("pguid")

        p_oid = ProcessModel.get_oid(
            {
                "pid": item["process_id"],
                "ppid": item["parent_id"],
                "image": process_path,
                "command_line": command_line,
            }
        )
        ontres.update_process(
            objectid=ontres.create_objectid(
                tag=Process.create_objectid_tag(process_path),
                ontology_id=p_oid,
                guid=guid,
                session=session,
                time_observed=first_seen,
            ),
            pid=item["process_id"],
            ppid=item["parent_id"],
            image=process_path,
            command_line=command_line,
            start_time=first_seen,
            pguid=pguid,
            loaded_modules = process_map[item["process_id"]]["loaded_modules"],
            services_involved = process_map[item["process_id"]]["services_involved"],
        )


def build_process_tree(
    parent_result_section: ResultSection,
    is_process_martian: bool,
    ontres: OntologyResults,
    processtree_id_safelist: List[str],
) -> None:
    """
    This method builds a process tree ResultSection
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param is_process_martian: A boolean flag that indicates if the is_process_martian signature was raised
    :param ontres: The Ontology Results class object
    :param processtree_id_safelist: A list of hashes used for safelisting process tree IDs
    :return: None
    """
    if not ontres.get_processes():
        return
    process_tree_section = ontres.get_process_tree_result_section(processtree_id_safelist, 56) #tying to heuristic 56
    if is_process_martian:
        sig_name = "process_martian"
        heur_id = get_category_id(sig_name)
        process_tree_section.set_heuristic(heur_id)
        # Let's keep this heuristic as informational
        process_tree_section.heuristic.add_signature_id(sig_name, score=10)
    if process_tree_section.body:
        parent_result_section.add_subsection(process_tree_section)


def process_signatures(
    sigs: List[Dict[str, Any]],
    process_map: Dict[int, Dict[str, Any]],
    parent_result_section: ResultSection,
    ontres: OntologyResults,
    safelist: Dict[str, Dict[str, List[str]]],
    uses_https_proxy_in_sandbox: bool,
    signature_map: Dict[str, Dict[str, Any]] = {},
) -> bool:
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

    session = ontres.sandboxes[-1].objectid.session
    # Flag used to indicate if process_martian signature should be used in process_behaviour
    is_process_martian = False
    sigs_res = ResultSection(SIGNATURES_SECTION_TITLE)

    sigs = _remove_network_http_noise(sigs)

    for sig in sigs:
        sig_name = sig["name"]

        if sig_name in CAPE_DROPPED_SIGNATURES:
            continue

        if not is_process_martian and sig_name == "process_martian":
            is_process_martian = True

        translated_score = SCORE_TRANSLATION[sig["severity"]]
        data = {
            "name": sig_name,
            "type": "CUCKOO",
            "classification": Classification.UNRESTRICTED,
        }
        s_tag = SignatureModel.get_tag(data)
        s_oid = SignatureModel.get_oid(data)
        ontres_sig = ontres.create_signature(
            objectid=ontres.create_objectid(
                tag=s_tag,
                ontology_id=s_oid,
                session=session,
            ),
            name=sig_name,
            type="CUCKOO",
            score=translated_score,
            classification = Classification.UNRESTRICTED,
        )
        sig_res = _create_signature_result_section(
            sig_name,
            sig,
            translated_score,
            ontres_sig,
            ontres,
            process_map,
            safelist,
            uses_https_proxy_in_sandbox,
            signature_map,
        )

        if sig_res:
            ontres.add_signature(ontres_sig)
            _add_process_context(ontres_sig, sig_res, ontres)
            sigs_res.add_subsection(sig_res)

    if len(sigs_res.subsections) > 0:
        parent_result_section.add_subsection(sigs_res)
    return is_process_martian


def _add_process_context(ontres_sig: Signature, sig_res: ResultMultiSection, ontres: OntologyResults) -> None:
    """
    This method adds process context to a signature
    :param ontres_sig: The Signature object
    :param sig_res: The result section for the signature
    :param ontres: The Ontology Results class object
    :return: None
    """
    if ontres_sig.attributes:
        process_sources = []
        for attribute in ontres_sig.attributes:
            if attribute.source:
                p = ontres.get_process_by_objectid(attribute.source)
                if p and p.image not in process_sources:
                    process_sources.append(f"{safe_str(p.image)} ({p.pid})")
        if process_sources:
            sig_res.add_section_part(TextSectionBody(body=f"Processes involved: {','.join(process_sources)}"))


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


def _is_network_flow_a_connect_match(network_flow: Dict[str, Any], connect: Dict[str, Any]) -> bool:
    # We either have an IP+port match
    ip_match = any(network_flow["dest_ip"] == connect.get(item, "") for item in ["ip_address", "hostname"])
    ip_and_port_match = ip_match and connect["port"] == network_flow["dest_port"]

    # Or we have a domain match, either directly or via URL
    if network_flow.get("domain"):
        domain_match = network_flow["domain"] == connect.get("servername", "") or network_flow[
            "domain"
        ] == _massage_host_data(urlparse(connect.get("url", "")).netloc)
    else:
        domain_match = False

    return ip_and_port_match or domain_match


def _link_flow_with_process(
    network_flow: Dict[str, Any], process_map: Dict[int, Dict[str, Any]], ontres: OntologyResults
) -> Dict[str, Any]:
    # if process name does not exist from DNS, then find processes that made connection calls
    if network_flow["image"] is None:
        for process, process_details in process_map.items():
            for network_call in process_details["network_calls"]:
                # If the network_call is a known CONNECT call hook, set and break
                connect = {}
                for api_call in CONNECT_API_CALLS:
                    if api_call in network_call:
                        connect = network_call[api_call]
                        break

                # We are connect or bust
                if not connect:
                    continue

                if _is_network_flow_a_connect_match(network_flow, connect):
                    network_flow["image"] = process_details["name"]
                    network_flow["pid"] = process
                    break
            if network_flow["image"]:
                break

    # Special handling for when Sysmon gives us process-related details but cannot get the image name
    elif network_flow["image"] == UNKNOWN_PROCESS:
        p = ontres.get_process_by_guid(network_flow.get("guid"))
        if isinstance(network_flow.get("timestamp"), float):
            timestamp = epoch_to_local_with_ms(network_flow["timestamp"])
        else:
            timestamp = network_flow.get("timestamp")
        if not p:
            p = ontres.get_process_by_pid_and_time(network_flow.get("pid"), timestamp)

        if p:
            network_flow["image"] = p.image

    return network_flow


def _tag_network_flow(
    netflows_sec: ResultTableSection,
    dom: str,
    network_flow: Dict[str, Any],
    dest_ip: str,
    safelist: Dict[str, Dict[str, List[str]]],
) -> None:
    # If the record has not been removed then it should be tagged for protocol, domain, ip, and port
    _ = add_tag(netflows_sec, "network.dynamic.domain", dom)
    _ = add_tag(netflows_sec, "network.protocol", network_flow["protocol"])
    _ = add_tag(netflows_sec, "network.dynamic.ip", dest_ip, safelist)
    _ = add_tag(netflows_sec, "network.dynamic.ip", network_flow["src_ip"], safelist)
    _ = add_tag(netflows_sec, "network.port", network_flow["dest_port"])
    _ = add_tag(netflows_sec, "network.port", network_flow["src_port"])


def _create_network_connection_for_network_flow(
    network_flow: Dict[str, Any], session: str, ontres: OntologyResults
) -> bool:
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
        return False
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

    # We want all key values for all network flows except for timestamps and event_type
    del network_flow["timestamp"]
    return True


# TODO: break this up into methods
def process_network(
    network: Dict[str, Any],
    parent_result_section: ResultSection,
    inetsim_network: IPv4Network,
    routing: str,
    process_map: Dict[int, Dict[str, Any]],
    safelist: Dict[str, Dict[str, List[str]]],
    ontres: OntologyResults,
    inetsim_dns_servers: List[str],
    uses_https_proxy_in_sandbox: bool,
    suspicious_accepted_languages: List[str],
) -> None:
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
    session = ontres.sandboxes[-1].objectid.session
    network_res = ResultSection("Network Activity")

    # DNS
    dns_servers: List[str] = _determine_dns_servers(network, inetsim_dns_servers)
    dns_server_heur = Heuristic(1008)
    dns_server_sec = ResultTextSection(
        dns_server_heur.name, heuristic=dns_server_heur, body=dns_server_heur.description
    )
    dns_server_hit = False
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

    dns_requests: Dict[str, List[Dict[str, Any]]] = _get_dns_map(
        network.get("dns", []), process_map, routing, dns_servers
    )
    dns_res_sec: Optional[ResultTableSection] = _get_dns_sec(dns_requests, safelist)

    # UDP/TCP
    low_level_flows = {"udp": network.get("udp", []), "tcp": network.get("tcp", [])}
    network_flows_table, netflows_sec = _get_low_level_flows(dns_requests, low_level_flows)

    # We have to copy the network table so that we can iterate through the copy
    # and remove items from the real one at the same time
    for network_flow in network_flows_table[:]:
        dom = network_flow["domain"]
        dest_ip = network_flow["dest_ip"]

        if _remove_network_call(dom, dest_ip, dns_servers, dns_requests, inetsim_network, safelist):
            network_flows_table.remove(network_flow)
        else:
            network_flow = _link_flow_with_process(network_flow, process_map, ontres)
            _tag_network_flow(netflows_sec, dom, network_flow, dest_ip, safelist)

            if not _create_network_connection_for_network_flow(network_flow, session, ontres):
                continue
    for request, attempts in dns_requests.items():
        if (request, safelist):
            continue
        for attempt in attempts:
            relevant_answer = []
            if isinstance(attempt["answers"], List):
                answers = attempt["answers"]
            elif attempt["answers"] == None:
                continue
            else:
                answers = [attempt["answers"]]
            for answer in answers:
                if answer and answer.isdigit():
                    continue
                relevant_answer.append(answer)
                if not request or not attempt.get("type"):
                    continue
                if len(relevant_answer) == 0:
                    relevant_answer.append("")
                domain_answer = []
                ip_answer = []
                for dns_answer in relevant_answer:
                    if not any(c.isalpha() for c in dns_answer) :
                        ip_answer.append(dns_answer)    
                    elif any(c.isalpha() for c in dns_answer):
                        domain_answer.append(dns_answer)
                if len(domain_answer) > 0 and len(ip_answer) > 0:
                    nd = ontres.create_network_dns(
                        domain=request, resolved_ips=ip_answer, resolved_domains=domain_answer, lookup_type=attempt.get("type")
                    )
                elif len(domain_answer) > 0:
                    nd = ontres.create_network_dns(
                        domain=request, resolved_ips=None, resolved_domains=domain_answer, lookup_type=attempt.get("type")
                    )
                elif len(ip_answer) > 0:
                    nd = ontres.create_network_dns(
                        domain=request, resolved_ips=ip_answer, resolved_domains=None, lookup_type=attempt.get("type")
                    )
                else:
                    nd = ontres.create_network_dns(
                        domain=request, resolved_ips=relevant_answer, resolved_domains=None, lookup_type=attempt.get("type")
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
                        "dns_details": {"domain": request},
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
                p = ontres.get_process_by_guid(attempt["guid"])
                if not p:
                    p = ontres.get_process_by_pid_and_time(attempt["process_id"], nc.objectid.time_observed)
                if p:
                    nc.set_process(p)
                ontres.add_network_connection(nc)
                ontres.add_network_dns(nd)

    if dns_res_sec and len(dns_res_sec.tags.get("network.dynamic.domain", [])) > 0:
        network_res.add_subsection(dns_res_sec)
    unique_netflows: List[Dict[str, Any]] = []
    if len(network_flows_table) > 0:
        tcp_seen = False
        udp_seen = False
        # Need to convert each dictionary to a string in order to get the set of network_flows_table, since
        # dictionaries are not hashable
        for item in network_flows_table:
            if item not in unique_netflows:  # Remove duplicates
                unique_netflows.append(item)
                netflows_sec.add_row(TableRow(**item))
                if item["protocol"] == "tcp":
                    tcp_seen = True
                elif item["protocol"] == "udp":
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
    http_level_flows = {
        "http": network.get("http", []),
        "https": network.get("https", []),
        "http_ex": network.get("http_ex", []),
        "https_ex": network.get("https_ex", []),
    }
    _process_http_calls(http_level_flows, process_map, dns_servers, dns_requests, safelist, ontres)
    http_calls = ontres.get_network_http()
    if len(http_calls) > 0:
        normalized_headers = [header.replace("-", "") for header in STANDARD_HTTP_HEADERS]

        http_sec = ResultTableSection("Protocol: HTTP/HTTPS")
        http_header_sec = ResultTableSection("IOCs found in HTTP/HTTPS Headers")
        remote_file_access_sec = ResultTextSection("Access Remote File")
        remote_file_access_sec.add_line("The sample attempted to download the following files:")
        suspicious_user_agent_sec = ResultTextSection("Suspicious User Agent(s)")
        suspicious_user_agent_sec.add_line("The sample made HTTP calls via the following user agents:")
        http_header_anomaly_sec = ResultTableSection("Non-Standard HTTP Headers")
        http_header_anomaly_sec.set_heuristic(1012)

        sus_user_agents_used = []
        http_sec.set_heuristic(1002)
        _ = add_tag(http_sec, "network.protocol", "http")

        for http_call in http_calls:
            request_uri: str
            if uses_https_proxy_in_sandbox:
                request_uri = convert_url_to_https(method=http_call.request_method, url=http_call.request_uri)
            else:
                request_uri = http_call.request_uri
            _ = add_tag(http_sec, "network.dynamic.uri", request_uri, safelist)

            for _, value in http_call.request_headers.items():
                extract_iocs_from_text_blob(value, http_header_sec, is_network_static=True)

            # Now we're going to try to detect if a remote file is attempted to be downloaded over HTTP
            if http_call.request_method == "GET":
                split_path = request_uri.rsplit("/", 1)
                if len(split_path) > 1 and search(r"[^\\]*\.(\w+)$", split_path[-1]):
                    if not remote_file_access_sec.body:
                        remote_file_access_sec.add_line(f"\t{request_uri}")
                    elif f"\t{request_uri}" not in remote_file_access_sec.body:
                        remote_file_access_sec.add_line(f"\t{request_uri}")
                    if not remote_file_access_sec.heuristic:
                        remote_file_access_sec.set_heuristic(1003)
                    _ = add_tag(
                        remote_file_access_sec,
                        "network.dynamic.uri",
                        request_uri,
                        safelist,
                    )

            user_agent = http_call.request_headers.get("UserAgent")
            if user_agent:
                if any(sus_user_agent in user_agent for sus_user_agent in SUSPICIOUS_USER_AGENTS):
                    if suspicious_user_agent_sec.heuristic is None:
                        suspicious_user_agent_sec.set_heuristic(1007)
                    sus_user_agent_used = next(
                        (sus_user_agent for sus_user_agent in SUSPICIOUS_USER_AGENTS if (sus_user_agent in user_agent)),
                        None,
                    )
                    if sus_user_agent_used not in sus_user_agents_used:
                        _ = add_tag(
                            suspicious_user_agent_sec,
                            "network.user_agent",
                            sus_user_agent_used,
                            safelist,
                        )
                        suspicious_user_agent_sec.add_line(f"\t{sus_user_agent_used}")
                        sus_user_agents_used.append(sus_user_agent_used)

            accept_language = http_call.request_headers.get("AcceptLanguage")
            if accept_language:
                for sus_language in suspicious_accepted_languages:
                    if sus_language.lower() in accept_language.lower():
                        http_header_anomaly_sec.heuristic.add_signature_id(
                            f"suspicious_language_accepted_{sus_language.split('-')[1].lower()}", 750
                        )

            nc = ontres.get_network_connection_by_network_http(http_call)
            if nc:
                process = nc.process

            # If no network connection exists, it could be due to a network connection being associated
            # with another http call already that uses the same connection specs, so
            # let's make an educated guess. If there is only one process that has network calls, then
            # odds are the process is the one that made this call.
            elif len([proc for proc, details in process_map.items() if len(details["network_calls"]) > 0]) == 1:
                pid = [proc for proc, details in process_map.items() if len(details["network_calls"]) > 0][0]
                process = ontres.get_process_by_pid(pid)
            else:
                process = None
            http_sec.add_row(
                TableRow(
                    process_name=f"{process.image} ({process.pid})" if process else "None (None)",
                    method=http_call.request_method,
                    request=http_call.request_headers,
                    uri=request_uri,
                )
            )

            # Flag non-standard request headers
            for header, header_value in http_call.request_headers.items():
                if header.upper() not in normalized_headers:
                    http_header_anomaly_sec.add_row(TableRow(header=header, header_value=header_value))

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
    else:
        _process_non_http_traffic_over_http(network_res, unique_netflows)

    # Let's add a section here that covers URLs seen in API calls that the
    # monitor picked up but the signatures / PCAP did not
    _process_unseen_iocs(network_res, process_map, ontres, safelist)

    if len(network_res.subsections) > 0:
        parent_result_section.add_subsection(network_res)


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
            for _, network_details in network_call.items():
                for _, v in network_details.items():
                    if not _api_ioc_in_network_traffic(v, seen_domains + seen_ips + seen_uris):
                        extract_iocs_from_text_blob(
                            v,
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
    if len(dns_requests.keys()) == 0:
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
                _ = add_tag(dns_res_sec, "network.dynamic.ip", answer, safelist)
                if add_tag(dns_res_sec, "network.dynamic.domain", request, safelist):
                    if answer.isdigit():
                        dns_request = {
                            "domain": request,
                            "type": request_type,
                        }
                    else:
                        # If there is only UDP and no TCP traffic, then we need to tag the domains here:
                        dns_request = {
                            "domain": request,
                            "answer": answer,
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


def _get_dns_map(
    dns_calls: List[Dict[str, Any]],
    process_map: Dict[int, Dict[str, Any]],
    routing: str,
    dns_servers: List[str],
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
    no_answer_count = 0
    for dns_call in dns_calls:
        if len(dns_call["answers"]) > 0:
            answers = [i["data"] for i in dns_call["answers"]]
        else:
            # We still want these DNS calls in the dns_requests map, so use int as unique ID
            answers = [str(no_answer_count)]
            no_answer_count += 1

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
        if set(answers).intersection(set(dns_servers)):
            continue

        # A DNS pointer record (PTR for short) provides the domain name associated with an IP address.
        if dns_type == "PTR":
            continue

        # An 'A' record provides the IP address associated with a domain name.
        else:
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
                }
            )

    # now map process_name to the dns_call
    for process, process_details in process_map.items():
        for network_call in process_details["network_calls"]:
            dns = next(
                (network_call[api_call] for api_call in DNS_API_CALLS if api_call in network_call),
                {},
            )
            if dns != {} and (dns.get("hostname") or dns.get("servername") or dns.get("nodename")):
                for request, attempts in dns_requests.items():
                    for index, attempt in enumerate(attempts):
                        answers = attempt["answers"]
                        if answers == None:
                            continue
                        for answer in answers:
                            if not answer.isdigit() in [
                                dns.get("hostname"),
                                dns.get("servername", dns.get("nodename")),
                            ]:
                                if not dns_requests[request][index].get("process_name"):
                                    dns_requests[request][index]["process_name"] = process_details["name"]

                            if not dns_requests[request][index].get("process_id"):
                                dns_requests[request][index]["process_id"] = process
                        else:
                            continue
    return dict(dns_requests)


def _get_low_level_flows(
    dns_requests: Dict[str, List[Dict[str, Any]]],
    flows: Dict[str, List[Dict[str, Any]]],
) -> Tuple[List[Dict[str, Any]], ResultTableSection]:
    """
    This method converts low level network calls to a general format
    :param dns_requests: A map of process IDs to process names, network calls, and decrypted buffers
    :param flows: UDP and TCP flows from CAPE's analysis
    :return: Returns a table of low level network calls, and a result section for the table
    """
    # TCP and UDP section
    network_flows_table: List[Dict[str, Any]] = []

    # This result section will contain all of the "flows" from src ip to dest ip
    netflows_sec = ResultTableSection("TCP/UDP Network Traffic")
    netflows_sec.set_column_order(
        ["timestamp", "protocol", "src_ip", "src_port", "domain", "dest_ip", "dest_port", "image", "pid"]
    )
    for protocol, network_calls in flows.items():
        if len(network_calls) <= 0:
            continue
        elif len(network_calls) > UNIQUE_IP_LIMIT / 2:
            network_calls_made_to_unique_ips: List[Dict[str, Any]] = []
            # Collapsing network calls into calls made to unique IP+port combos
            for network_call in network_calls:
                if len(network_calls_made_to_unique_ips) >= UNIQUE_IP_LIMIT:
                    # BAIL! Too many to put in a table
                    too_many_unique_ips_sec = ResultTextSection("Too Many Unique IPs")
                    too_many_unique_ips_sec.add_line(
                        "The number of TCP calls displayed has been capped "
                        f"at {UNIQUE_IP_LIMIT}. The full results can be found "
                        "in the supplementary PCAP file included with the analysis."
                    )
                    netflows_sec.add_subsection(too_many_unique_ips_sec)
                    break
                dst_port_pair = json.dumps({network_call["dst"]: network_call["dport"]})
                if dst_port_pair not in [json.dumps({x["dst"]: x["dport"]}) for x in network_calls_made_to_unique_ips]:
                    network_calls_made_to_unique_ips.append(network_call)
            network_calls = network_calls_made_to_unique_ips
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
            }
            for request, attempts in dns_requests.items():
                for attempt in attempts:
                    if isinstance(attempt["answers"], List):
                        answers = attempt["answers"]
                    elif attempt["answers"] == None:
                        continue
                    else:
                        answers = [attempt["answers"]]
                    if dst in answers:
                        if dst.isdigit():
                            continue
                        # We have no way of knowing which domain the underlying connection was made to, so just go with the first one
                        network_flow["domain"] = request
                        if not network_flow["image"]:
                            network_flow["image"] = attempt.get("process_name")
                        if network_flow["image"] and not network_flow["pid"]:
                            network_flow["pid"] = attempt["process_id"]
            network_flows_table.append(network_flow)
    return network_flows_table, netflows_sec


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
                    if answer.isdigit():
                        continue
                    if request == host:
                        http_call["dst"] = answer
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
    http_call: Dict[str, Any], dns_servers: List[str], host: str, ontres: OntologyResults
) -> Optional[str]:
    """
    This method returns the destination IP used for the HTTP call
    :param http_call: The parsed HTTP call data
    :param dns_servers: A list of DNS servers
    :param host: The actual host
    :param ontres: The Ontology Results class object
    :return: The destination IP reached out to, if it exists
    """
    if http_call.get("dst") and http_call["dst"] not in dns_servers:
        destination_ip = http_call["dst"]
    else:
        destination_ip = ontres.get_destination_ip_by_domain(host)
    return destination_ip


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


def _link_process_to_http_call(
    process_map: Dict[int, Dict[str, Any]], request: str, uri: str, nc: NetworkConnection, ontres: OntologyResults
) -> None:
    """
    This method links a process to an HTTP call
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param request: The HTTP call data
    :param uri: URI reached out to
    :param nc: The NetworkConnection object
    :param ontres: The Ontology Results class object
    :return: None
    """
    # We should always have a NetworkConnection object with http_details at this point
    if not nc or not nc.http_details:
        return

    # We are going to use this domain for validation
    uri_pieces = urlparse(uri)
    domain = _massage_host_data(uri_pieces.netloc)

    # We need to confirm whether any network call in the process map
    # can be REASONABLY linked to the NetworkConnection object

    match = False
    for pid, process_details in process_map.items():
        for network_call in process_details["network_calls"]:
            # If the network_call is a known HTTP call hook, set and break
            http_call = {}
            for api_call in HTTP_API_CALLS:
                if api_call in network_call:
                    http_call = network_call[api_call]
                    break

            if http_call == {}:
                continue

            # Reasons why we should reject this network call

            # The fact that a network call only contains the "service" key is not enough to link anything
            if len(http_call.keys()) == 1 and "service" in http_call:
                continue
            # According to https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetconnecta, service = 3 stands for "INTERNET_SERVICE_HTTP"
            elif http_call.get("service") and int(http_call["service"]) != 3:
                continue

            # Reasons why we should keep processing this network call
            if (
                _uris_are_equal_despite_discrepancies(http_call.get("url"), uri)
                or http_call.get("servername") == domain
                or http_call.get("buffer", "") == request
            ):
                if not nc.process:
                    # A OntologyResults process should exist for every pid in the process map
                    p = ontres.get_process_by_pid(pid)
                    nc.set_process(p)
                else:
                    nc.update_process(image=process_details["name"], pid=pid)
                match = True
                break
        if match:
            break


def _process_http_calls(
    http_level_flows: Dict[str, List[Dict[str, Any]]],
    process_map: Dict[int, Dict[str, Any]],
    dns_servers: List[str],
    dns_requests: Dict[str, List[Dict[str, Any]]],
    safelist: Dict[str, Dict[str, List[str]]],
    ontres: OntologyResults,
) -> None:
    """
    This method processes HTTP(S) calls and puts them into a nice table
    :param http_level_flows: A list of flows that represent HTTP calls
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param dns_servers: A list of DNS servers
    :param dns_requests: A map of process IDs to process names, network calls, and decrypted buffers
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param ontres: The Ontology Results class object
    :return: None
    """
    # Http level flows consist of http, http_ex, https and https_ex
    for protocol, http_calls in http_level_flows.items():
        # Let's go
        for http_call in http_calls:
            # First thing's first, is there a host?
            host = _massage_host_data(http_call["host"])
            if not host:
                continue

            # Assign a previosuly non-existent dst field if the host is an IP
            if is_valid_ip(host) and "dst" not in http_call:
                http_call["dst"] = host

            # request, port and uri are the main fields that we want to have as separate variables
            request, port, uri, http_call = _get_important_fields_from_http_call(
                protocol, host, dns_servers, dns_requests, http_call
            )

            # Now that we've massaged the data, let's confirm that this uri is not safelisted
            # We don't mess with safe uris
            if _is_http_call_safelisted(host, safelist, uri):
                continue

            request_body_path, response_body_path = _massage_body_paths(http_call)
            request_headers = _handle_http_headers(request)
            response_headers = _handle_http_headers(http_call.get("response"))

            # This flag will be used to determine if we should add the NetworkHTTP
            # object to the OntologyResults
            nh_to_add = False

            # Check if a NetworkHTTP object exists in the OntologyResults yet
            nh = ontres.get_network_http_by_details(
                request_uri=uri,
                request_method=http_call["method"],
                request_headers=request_headers,
            )

            if not nh:
                # When creating a new NetworkHTTP object, we are destination_ip or bust!
                destination_ip = _get_destination_ip(http_call, dns_servers, host, ontres)
                if not destination_ip:
                    continue

                nc, nh = _setup_network_connection_with_network_http(
                    uri,
                    http_call,
                    request_headers,
                    response_headers,
                    request_body_path,
                    response_body_path,
                    port,
                    destination_ip,
                    ontres,
                )

                nh_to_add = True
            else:
                nc = ontres.get_network_connection_by_network_http(nh)

            _link_process_to_http_call(process_map, request, uri, nc, ontres)

            if nh_to_add:
                ontres.add_network_http(nh)


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


def process_all_events(
    parent_result_section: ResultSection,
    ontres: OntologyResults,
    processtree_id_safelist: List[str],
) -> None:
    """
    This method converts all events to a table that is sorted by timestamp
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param ontres: The Ontology Results class object
    :param processtree_id_safelist: A list of hashes used for safelisting process tree IDs
    :return: None
    """
    # Each item in the events table will follow the structure below:
    # {
    #   "timestamp": timestamp,
    #   "process_name": process_name,
    #   "details": {}
    # }
    if not ontres.get_processes() and not ontres.get_network_connections():
        return
    events_section = ResultTableSection("Event Log")
    event_ioc_table = ResultTableSection("Event Log IOCs")

    ps1_commands: List[str] = []
    bat_commands: List[str] = []

    process_seen = False

    for event in ontres.get_events(safelist=processtree_id_safelist):
        if isinstance(event, NetworkConnection):
            if event.objectid.time_observed in [MIN_TIME, MAX_TIME]:
                continue
            # We need to see a process first, otherwise this network event is most likely a false positive
            if not process_seen:
                continue
            if event.dns_details:
                events_section.add_row(
                    TableRow(
                        time_observed=event.objectid.time_observed,
                        process_name=f"{getattr(event.process, 'image', None)} ({getattr(event.process, 'pid', None)})",
                        details={
                            "protocol": event.connection_type,
                            "domain": event.dns_details.domain,
                            "lookup_type": event.dns_details.lookup_type,
                            "dns_requests": event.dns_details.resolved_ips,
                        },
                    )
                )
            elif event.http_details:
                events_section.add_row(
                    TableRow(
                        time_observed=event.objectid.time_observed,
                        process_name=f"{getattr(event.process, 'image', None)} ({getattr(event.process, 'pid', None)})",
                        details={
                            "protocol": event.connection_type,
                            "method": event.http_details.request_method,
                            "uri": event.http_details.request_uri,
                            "status_code": event.http_details.response_status_code,
                        },
                    )
                )
            else:
                events_section.add_row(
                    TableRow(
                        time_observed=event.objectid.time_observed,
                        process_name=f"{getattr(event.process, 'image', None)} ({getattr(event.process, 'pid', None)})",
                        details={
                            "protocol": event.transport_layer_protocol,
                            "domain": ontres.get_domain_by_destination_ip(event.destination_ip),
                            "dest_ip": event.destination_ip,
                            "dest_port": event.destination_port,
                        },
                    )
                )
        elif isinstance(event, Process):
            # We want ALL command lines, even the ones that we failed to get times for
            if event.command_line:
                ps1_matches = find_powershell_strings(event.command_line.encode())
                for match in ps1_matches:
                    command = get_powershell_command(match.value)
                    if command and command + b"\n" not in ps1_commands:
                        ps1_commands.append(command + b"\n")

                cmd_matches = find_cmd_strings(event.command_line.encode())
                for match in cmd_matches:
                    command = get_cmd_command(match.value)
                    if command and command + b"\n" not in bat_commands:
                        bat_commands.append(command + b"\n")

            if event.objectid.time_observed in [MIN_TIME, MAX_TIME]:
                continue

            # Our dreams have come true. We have seen a process. Now we can start displaying network calls
            process_seen = True

            _ = add_tag(events_section, "dynamic.process.command_line", event.command_line)
            extract_iocs_from_text_blob(event.command_line, event_ioc_table, is_network_static=True)
            _ = add_tag(events_section, "dynamic.process.file_name", event.image)
            if isinstance(event.objectid.time_observed, float) or isinstance(event.objectid.time_observed, int):
                time_observed = epoch_to_local_with_ms(event.objectid.time_observed)
            else:
                time_observed = event.objectid.time_observed
            events_section.add_row(
                TableRow(
                    time_observed=time_observed,
                    process_name=f"{event.image} ({event.pid})",
                    details={
                        "command_line": event.command_line,
                    },
                )
            )
        else:
            raise ValueError(f"{event.as_primitives()} is not of type NetworkConnection or Process.")

    if ps1_commands:
        with open(PS1_COMMANDS_PATH, "wb") as f:
            ps1_commands.insert(0, CUSTOM_PS1_ID)
            f.writelines(ps1_commands)

    if bat_commands:
        with open(BAT_COMMANDS_PATH, "wb") as f:
            bat_commands.insert(0, CUSTOM_BATCH_ID)
            f.writelines(bat_commands)

    if event_ioc_table.body:
        events_section.add_subsection(event_ioc_table)
    if events_section.body:
        parent_result_section.add_subsection(events_section)


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
    curtain_res = ResultTableSection("PowerShell Activity")
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
    buffer_res = ResultTableSection("Buffers", auto_collapse=True)
    buffer_res.set_column_order(["Process", "Source", "Buffer"])
    buffer_ioc_table = ResultTableSection("Buffer IOCs")
    buffer_body = []
    buffers = []
    for process, process_details in process_map.items():
        count_per_source_per_process = 0
        process_name_to_be_displayed = f"{process_details.get('name', 'None')} ({process})"
        for call in process_details.get("decrypted_buffers", []):
            buffer = ""

            crypt_api = next((item for item in CRYPT_BUFFER_CALLS if call.get(item)), None)
            if crypt_api:
                buffer = call[crypt_api]["buffer"]
                b_buffer = bytes(buffer, "utf-8")
                if all(PE_indicator in b_buffer for PE_indicator in PE_INDICATORS):
                    hash = sha256(b_buffer).hexdigest()
                    buffers.append((f"{str(process)}-{crypt_api}-{hash}", b_buffer, buffer))

            else:
                misc_api = next((item for item in MISC_BUFFER_CALLS if call.get(item)), None)
                if misc_api:
                    buffer = call[misc_api]["string"]
                    b_buffer = bytes(buffer, "utf-8")
                    if all(PE_indicator in b_buffer for PE_indicator in PE_INDICATORS):
                        hash = sha256(b_buffer).hexdigest()
                        buffers.append((f"{str(process)}-{misc_api}-{hash}", b_buffer, buffer))
            # Note not all calls have the key name consistent with their capemon api output
            # "CryptDecrypt" --> "buffer " Depricated but still used
            # "CryptEncrypt" --> "buffer" Depricated but still used
            # "BCryptDecrypt" --> "buffer" Key in memory
            # "BCryptEncrypt" --> "buffer" Key in memory
            # "NCryptDecrypt" --> "buffer"  #key in a KSP
            # "NCryptEncrypt" --> "buffer" key in a KSP
            # Commented out since in most cases the encryption and decryption must be done on the same computer
            # "CryptProtectData" --> ?
            # "CryptUnProtectData" --> ?
            # Commented out since no proof of requirement is there
            # "CryptDecryptMessage" --> ?
            # "CryptEncryptMessage" --> ?
            # "CryptDecodeMessage" --> ?
            # Do we want hashing as well ?
            # "CryptHashMessage" --> ?

            # "OutputDebugStringA" --> "string"
            # "OutputDebugStringW" --> "string"

            # do we want those since it's in memory and probably going to be picked up elsewhere in dumps?
            # "CryptProtectMemory" --> ?
            # "CryptUnprotectMemory" --> ?
            # The need for compression/decompression buffer is probably not needed
            # "RtlDecompressBuffer" --> ?
            # "RtlCompressBuffer" --> ?

            # Do we want hashing as well ?
            # "CryptHashData" --> ?

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
        for network_call in process_details.get("network_calls", []):
            for api_call in BUFFER_API_CALLS:
                if api_call in network_call:
                    buffer = network_call[api_call]["buffer"]
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
                            network_buffers.append((f"{str(process)}-{api_call}-{hash}", b_buffer, buffer))

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
        malware_heur = Heuristic(38)
        malware_heur.add_signature_id("config_extracted", 1000)
        configs_sec = ResultSection("Configs Extracted By CAPE", parent=parent_result_section, heuristic=malware_heur)

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
    api_calls_of_interest = {
        "LdrLoadDll": ["filename"],
        "LoadLibraryExW": ["lplibfilename"],
        "LdrGetDllHandle": ["filename"],
        "CreateServiceA": ["servicename", "displayname", "starttype", "binarypathname"],
        "CreateServiceW": ["servicename", "displayname", "starttype", "binarypathname"],
        "StartServiceA": ["servicename", "arguments"],
        "StartServiceW": ["servicename", "arguments"],
        "getaddrinfo": ["hostname", "nodename"],  # DNS
        "GetAddrInfoW": ["hostname", "nodename"],  # DNS
        "gethostbyname": ["hostname"],  # DNS
        "connect": ["ip_address", "port"],  # Connecting to IP
        "InternetConnectW": [
            "username",
            "service",
            "password",
            "hostname",
            "port",
            "servername",
            "serverport",
        ],
        "InternetConnectA": [
            "username",
            "service",
            "password",
            "hostname",
            "port",
            "servername",
            "serverport",
        ],
        # DNS and Connecting to IP, if service = 3 then HTTP
        "send": ["buffer"],  # HTTP Request
        "WSASend": ["buffer"],  # Socket connection
        "WSAConnect": ["ip_address", "port"],  # Connecting to IP
        # "HttpOpenRequestW": ["http_method", "path"],  # HTTP Request TODO not sure what to do with this yet
        # "HttpOpenRequestA": ["http_method", "path"],  # HTTP Request TODO not sure what to do with this yet
        # "InternetOpenW": ["user-agent"],  # HTTP Request TODO not sure what to do with this yet
        # "recv": ["buffer"],  # HTTP Response, TODO not sure what to do with this yet
        # "InternetReadFile": ["buffer"]  # HTTP Response, TODO not sure what to do with this yet
        "CryptDecrypt": ["buffer"],  # Used for certain malware files that use configuration files
        "OutputDebugStringA": ["string"],  # Used for certain malware files that use configuration files
        "URLDownloadToFileW": ["url"],
        "InternetCrackUrlA": ["url"],
        "InternetCrackUrlW": ["url"],
        "InternetOpenUrlA": ["url"],
        "WinHttpGetProxyForUrl": ["url"],
        "WinHttpConnect": ["servername", "serverport"],
    }
    for process in processes:
        process_name = process["module_path"] if process.get("module_path") else process["process_name"]
        network_calls = []
        loaded_dlls = []
        services_involved = []
        decrypted_buffers = []
        calls = process["calls"]
        for call in calls:
            category = call.get("category", "does_not_exist")
            api = call["api"]
            if category in ["network", "crypto", "system"] and api in api_calls_of_interest.keys():
                args = call["arguments"]
                args_of_interest: Dict[str, str] = {}
                for arg in api_calls_of_interest.get(api, []):
                    # Call arguments are split into dictionaries, each containing a name and value kv pair
                    for kv in args:
                        if arg == kv["name"].lower() and kv["value"]:
                            if category == "system" and "cfg:" in kv["value"]:
                                args_of_interest[arg] = kv["value"]
                                break
                            elif category in ["network", "crypto"]:
                                if is_tag_safelisted(
                                    kv["value"],
                                    ["network.dynamic.ip", "network.dynamic.uri", "network.dynamic.domain"],
                                    safelist,
                                ):
                                    continue
                                args_of_interest[arg] = kv["value"]
                                break
                            elif category == "system" and "api" not in kv["value"]:
                                args_of_interest[arg] = kv["value"].lower().replace(".dll", "")
                                break
                if args_of_interest:
                    item_to_add = {api: args_of_interest}
                    if category == "network" and item_to_add not in network_calls:
                        network_calls.append(item_to_add)
                    elif next(iter(item_to_add)) in ["LdrLoadDll", "LoadLibraryExW", "LdrGetDllHandle"] and next(iter(next(iter(item_to_add.values())).values())) not in loaded_dlls:
                        dll_name = next(iter(next(iter(item_to_add.values())).values())) 
                        adding_dll = True
                        for loaded_dll in loaded_dlls:
                            dll_chunck = loaded_dll.split("\\")
                            if dll_name in dll_chunck:
                                adding_dll = False
                            elif dll_chunck[-1] in dll_name.split("\\"):
                                adding_dll = False
                        if adding_dll:    
                            loaded_dlls.append(next(iter(next(iter(item_to_add.values())).values())))
                    elif next(iter(item_to_add)) in ["CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"] and item_to_add not in services_involved:
                        services_involved.append(item_to_add)
                    elif category in ["crypto", "system"] and next(iter(item_to_add)) not in ["LdrLoadDll", "LoadLibraryExW", "LdrGetDllHandle", "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"] and item_to_add not in decrypted_buffers:
                        decrypted_buffers.append(item_to_add)
        pid = process["process_id"]
        process_map[pid] = {
            "name": process_name,
            "network_calls": network_calls,
            "decrypted_buffers": decrypted_buffers,
            "loaded_modules": loaded_dlls,
            "services_involved": services_involved,
        }
    return process_map


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
) -> Optional[ResultMultiSection]:
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

    # If there are more true positive marks than false positive marks, return signature result section
    if not fp_mark_count or fp_mark_count != len(signature["data"]) - call_count:
        return sig_res
    else:
        log.debug(f"The signature {name} was marked as a false positive, ignoring...")
        return None


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
    sig_id = get_category_id(name)
    if sig_id == 9999:
        log.warning(f"Unknown signature detected: {signature}")

    # Creating heuristic
    sig_res.set_heuristic(sig_id)

    # Adding signature and score
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

        # The mark_count limit only exists for diaply purposes
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
        if ":" in value:
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
        if add_tag(sig_res, "network.dynamic.uri", value) and attributes:
            # Determine which attribute is to be assigned the uri
            for attribute in attributes:
                process = ontres.get_process_by_guid(attribute.source.guid)
                if not process:
                    continue
                for network_call in process_map[process.pid]["network_calls"]:
                    send = next(
                        (network_call[api_call] for api_call in HTTP_API_CALLS if api_call in network_call),
                        {},
                    )
                    if (
                        send != {}
                        and (send.get("service", 0) == 3 or value in send.get("buffer", ""))
                        or value in send.get("url", "")
                    ):
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


def _update_process_map(process_map: Dict[int, Dict[str, Any]], processes: List[Process]) -> None:
    """
    This method updates the process map with the processes added to the Ontology Results
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param processes: A list of processes
    :return: None
    """
    for process in processes:
        if process.pid in process_map or process.pid == SYSTEM_PROCESS_ID:
            continue

        process_map[process.pid] = {
            "name": process.image,
            "network_calls": [],
            "decrypted_buffers": [],
        }


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


if __name__ == "__main__":
    from sys import argv

    # pip install PyYAML
    import yaml
    from assemblyline.common.heuristics import HeuristicHandler, InvalidHeuristicException
    from assemblyline_v4_service.common.base import ServiceBase
    from assemblyline_v4_service.common.helper import get_heuristics
    from assemblyline_v4_service.common.result import Result
    from cape.safe_process_tree_leaf_hashes import SAFE_PROCESS_TREE_LEAF_HASHES

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

    cape_artifact_pids, main_process_tuples = generate_al_result(
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
    )

    service = ServiceBase()

    ontres.preprocess_ontology(custom_tree_id_safelist)
    # Print the ontres
    print(json.dumps(ontres.as_primitives(), indent=4))
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
