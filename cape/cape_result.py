from datetime import datetime
from ipaddress import ip_address, ip_network, IPv4Network
from json import dumps
from logging import getLogger
from re import match as re_match, search, sub
from typing import Any, Dict, List, Optional, Tuple

from assemblyline.common.str_utils import safe_str, truncate
from assemblyline.common import log as al_log
from assemblyline.common.attack_map import revoke_map
from assemblyline.common.net import is_valid_ip
from assemblyline.odm.base import IP_REGEX, FULL_URI
from assemblyline_v4_service.common.result import (
    ResultSection,
    ResultKeyValueSection,
    ResultTextSection,
    ResultTableSection,
    TableRow,
    ResultMultiSection,
    TextSectionBody,
    KVSectionBody,
)
from assemblyline_v4_service.common.safelist_helper import is_tag_safelisted
from assemblyline_v4_service.common.tag_helper import add_tag

from cape.signatures import get_category_id, CAPE_DROPPED_SIGNATURES
from cape.safe_process_tree_leaf_hashes import SAFE_PROCESS_TREE_LEAF_HASHES
from assemblyline_v4_service.common.dynamic_service_helper import (
    extract_iocs_from_text_blob,
    SandboxOntology,
    Process,
    NetworkConnection,
    MIN_DOMAIN_CHARS
)

al_log.init_logging("service.cape.cape_result")
log = getLogger("assemblyline.service.cape.cape_result")
# Global variable used for containing the system safelist
global_safelist: Optional[Dict[str, Dict[str, List[str]]]] = None
# Custom regex for finding uris in a text blob
UNIQUE_IP_LIMIT = 100
SCORE_TRANSLATION = {1: 10, 2: 100, 3: 250, 4: 500, 5: 750, 6: 1000, 7: 1000, 8: 1000}  # dead_host signature

# Signature Processing Constants
SKIPPED_MARK_ITEMS = ["type", "suspicious_features", "entropy", "process", "useragent"]
SKIPPED_CATEGORY_IOCS = ["section", "Data received", "Data sent"]
SKIPPED_FAMILIES = ["generic"]
SKIPPED_PATHS = ["/"]
SILENT_IOCS = ["ransomware_mass_file_delete", "injection_ntsetcontextthread", "injection_resumethread"]
SILENT_PROCESS_NAMES = ["injection_write_memory_exe", "injection_write_memory", "injection_modifies_memory"]

INETSIM = "INetSim"
DNS_API_CALLS = ["getaddrinfo", "InternetConnectW", "InternetConnectA", "GetAddrInfoW", "gethostbyname"]
HTTP_API_CALLS = ["send", "InternetConnectW", "InternetConnectA", "URLDownloadToFileW", "InternetCrackUrlW", "InternetOpenUrlA"]
BUFFER_API_CALLS = ["send", "WSASend"]
SUSPICIOUS_USER_AGENTS = ["Microsoft BITS", "Excel Service"]
SUPPORTED_EXTENSIONS = [
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
    "vbs",
    "wsf",
    "xls",
    "xlsm",
    "xlsx",
]
ANALYSIS_ERRORS = "Analysis Errors"
# Substring of Warning Message frm https://github.com/cuckoosandbox/cuckoo/blob/50452a39ff7c3e0c4c94d114bc6317101633b958/cuckoo/core/guest.py#L561
GUEST_LOSING_CONNNECTIVITY = "Virtual Machine /status failed. This can indicate the guest losing network connectivity"
# Substring of Error Message from https://github.com/cuckoosandbox/cuckoo/blob/50452a39ff7c3e0c4c94d114bc6317101633b958/cuckoo/core/scheduler.py#L572
GUEST_CANNOT_REACH_HOST = (
    "it appears that this Virtual Machine hasn't been configured properly as the CAPE Host wasn't able to connect to the Guest."
)
GUEST_LOST_CONNECTIVITY = 5
SIGNATURES_SECTION_TITLE = "Signatures"
ENCRYPTED_BUFFER_LIMIT = 25
SYSTEM_PROCESS_ID = 4
MARK_KEYS_TO_NOT_DISPLAY = ["data_being_encrypted"]
BUFFER_ROW_LIMIT_PER_SOURCE_PER_PROCESS = 10
YARA_RULE_EXTRACTOR = r"'(.\w+)'"
BYTE_CHAR = "x[a-z0-9]{2}"


# noinspection PyBroadException
# TODO: break this into smaller methods
def generate_al_result(
    api_report: Dict[str, Any],
    al_result: ResultSection,
    file_ext: str,
    random_ip_range: str,
    routing: str,
    safelist: Dict[str, Dict[str, List[str]]],
    so: SandboxOntology,
) -> Dict[str, int]:
    """
    This method is the main logic that generates the Assemblyline report from the CAPE analysis report
    :param api_report: The JSON report for the CAPE analysis
    :param al_result: The overarching result section detailing what image this task is being sent to
    :param file_ext: The file extension of the file to be submitted
    :param random_ip_range: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param routing: What method of routing is being used in the CAPE environment
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology class object
    :return: A map of payloads and the pids that they were hollowed out of
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
        process_info(info, al_result, so)

    if debug:
        # Ransomware tends to cause issues with CAPE's analysis modules, and including the associated analysis errors
        # creates unnecessary noise to include this
        if not any("ransomware" in sig["name"] for sig in sigs):
            process_debug(debug, al_result)

    process_map = get_process_map(behaviour.get("processes", {}), safelist)

    if sysmon:
        convert_sysmon_processes(sysmon, safelist, so)
        convert_sysmon_network(sysmon, network, safelist)

    if behaviour:
        sample_executed = [
            len(behaviour.get("processtree", [])),
            len(behaviour.get("processes", [])),
        ]
        if not any(item > 0 for item in sample_executed):
            noexec_res = ResultTextSection("Sample Did Not Execute")
            noexec_res.add_line(f"No program available to execute a file with the following extension: {safe_str(file_ext)}")
            al_result.add_subsection(noexec_res)
        else:
            # Otherwise, moving on!
            process_behaviour(behaviour, safelist, so)

    if so.get_processes():
        _update_process_map(process_map, so.get_processes())

    is_process_martian = False

    if network:
        process_network(network, al_result, validated_random_ip_range, routing, process_map, safelist, so)

    if sigs:
        is_process_martian = process_signatures(
            sigs, al_result, so
        )

    build_process_tree(al_result, is_process_martian, so)

    process_all_events(al_result, so)

    if curtain:
        process_curtain(curtain, al_result, process_map)

    if hollowshunter:
        process_hollowshunter(hollowshunter, al_result, process_map)

    if process_map:
        process_buffers(process_map, al_result)

    cape_artifact_pids: Dict[str, int] = {}
    if cape:
        cape_artifact_pids = process_cape(cape)

    return cape_artifact_pids


def process_info(info: Dict[str, Any], parent_result_section: ResultSection, so: SandboxOntology) -> None:
    """
    This method processes the info section of the CAPE report, adding anything noteworthy to the Assemblyline report
    :param info: The JSON of the info section from the report generated by CAPE
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param so: An instance of the sandbox ontology class
    :return: None
    """
    start_time = info["started"]
    end_time = info["ended"]
    duration = info["duration"]
    analysis_time = -1  # Default error time
    try:
        duration_str = datetime.fromtimestamp(int(duration)).strftime("%Hh %Mm %Ss")
        analysis_time = duration_str + "\t(" + start_time + " to " + end_time + ")"
    except Exception:
        pass
    body = {"CAPE Task ID": info["id"], "Duration": analysis_time, "Routing": info["route"], "CAPE Version": info["version"]}
    info_res = ResultKeyValueSection("Analysis Information")
    info_res.update_items(body)
    parent_result_section.add_subsection(info_res)
    so.update_analysis_metadata(task_id=info["id"], start_time=start_time, end_time=end_time, routing=info["route"])
    so.set_sandbox_version(info["version"])


def process_debug(debug: Dict[str, Any], parent_result_section: ResultSection) -> None:
    """
    This method processes the debug section of the CAPE report, adding anything noteworthy to the Assemblyline report
    :param debug: The JSON of the debug section from the report generated by CAPE
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :return: None
    """
    error_res = ResultTextSection(ANALYSIS_ERRORS)
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
            split_log = analyzer_log.lower().split("error:")[1].strip()
            if split_log in unique_errors:
                continue
            else:
                unique_errors.add(split_log)
            error_res.add_line(split_log.capitalize())

    if error_res.body and len(error_res.body) > 0:
        parent_result_section.add_subsection(error_res)


def process_behaviour(behaviour: Dict[str, Any], safelist: Dict[str, Dict[str, List[str]]], so: SandboxOntology) -> None:
    """
    This method processes the behaviour section of the CAPE report, adding anything noteworthy to the
    Assemblyline report
    :param behaviour: The JSON of the behaviour section from the report generated by CAPE
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology class object
    :return: None
    """
    # Preparing CAPE processes to match the SandboxOntology format
    processes = behaviour["processes"]
    if processes:
        convert_cape_processes(processes, safelist, so)


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
    cape_processes: List[Dict[str, Any]], safelist: Dict[str, Dict[str, List[str]]], so: SandboxOntology
) -> None:
    """
    This method converts processes observed in CAPE to the format supported by the SandboxOntology helper class
    :param cape_processes: A list of processes observed during the analysis of the task
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology class object
    :return: None
    """
    existing_pids = [proc.pid for proc in so.get_processes()]
    for item in cape_processes:
        # If process pid doesn't match any processes that Sysmon already picked up
        if item["process_id"] not in existing_pids:
            process_path = item.get("module_path")
            command_line = item["environ"].get("CommandLine")
            if (
                not process_path
                or not command_line
                or is_tag_safelisted(process_path, ["dynamic.process.file_name"], safelist)
                or is_tag_safelisted(command_line, ["dynamic.process.command_line"], safelist)
            ):
                continue
            so.update_process(
                pid=item["process_id"],
                ppid=item["parent_id"],
                image=process_path,
                command_line=command_line,
                start_time=datetime.strptime(item["first_seen"], "%Y-%m-%d %H:%M:%S,%f").timestamp(),
                guid=so.get_guid_by_pid_and_time(item["process_id"], item["first_seen"])
                if not item.get("guid")
                else item.get("guid"),
                pguid=so.get_pguid_by_pid_and_time(item["process_id"], item["first_seen"])
                if not item.get("pguid")
                else item.get("pguid"),
            )


def build_process_tree(parent_result_section: ResultSection, is_process_martian: bool, so: SandboxOntology) -> None:
    """
    This method builds a process tree ResultSection
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param is_process_martian: A boolean flag that indicates if the is_process_martian signature was raised
    :param so: The sandbox ontology class object
    :return: None
    """
    if not so.get_processes():
        return
    process_tree_section = so.get_process_tree_result_section(SAFE_PROCESS_TREE_LEAF_HASHES.keys())
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
    parent_result_section: ResultSection,
    so: SandboxOntology,
) -> bool:
    """
    This method processes the signatures section of the CAPE report, adding anything noteworthy to the
    Assemblyline report
    :param sigs: The JSON of the signatures section from the report generated by CAPE
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param so: The sandbox ontology class object
    :return: A boolean flag that indicates if the is_process_martian signature was raised
    """
    if len(sigs) <= 0:
        return False

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
        so_sig = so.create_signature()
        sig_res = _create_signature_result_section(sig_name, sig, translated_score, so_sig)

        sigs_res.add_subsection(sig_res)
        so.add_signature(so_sig)
    if len(sigs_res.subsections) > 0:
        parent_result_section.add_subsection(sigs_res)
    return is_process_martian


# TODO: break this up into methods
def process_network(
    network: Dict[str, Any],
    parent_result_section: ResultSection,
    inetsim_network: IPv4Network,
    routing: str,
    process_map: Dict[int, Dict[str, Any]],
    safelist: Dict[str, Dict[str, List[str]]],
    so: SandboxOntology,
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
    :param so: The sandbox ontology class object
    :return: None
    """
    network_res = ResultSection("Network Activity")

    # DNS
    # An assumption is being made here that the first UDP flow to port 53 is
    # for DNS.
    if len(network.get("udp", [])) > 0:
        dst = next((udp_flow["dst"] for udp_flow in network["udp"] if udp_flow["dport"] == 53), None)
        if dst:
            dns_servers = [dst]
        else:
            dns_servers = []
    else:
        dns_servers = []

    dns_calls: List[Dict[str, Any]] = network.get("dns", [])
    resolved_ips: Dict[str, Dict[str, Any]] = _get_dns_map(dns_calls, process_map, routing, dns_servers)
    dns_res_sec: Optional[ResultTableSection] = _get_dns_sec(resolved_ips, safelist)

    low_level_flows = {"udp": network.get("udp", []), "tcp": network.get("tcp", [])}
    network_flows_table, netflows_sec = _get_low_level_flows(resolved_ips, low_level_flows, safelist)

    # We have to copy the network table so that we can iterate through the copy
    # and remove items from the real one at the same time
    copy_of_network_table = network_flows_table[:]
    for network_flow in copy_of_network_table:
        dom = network_flow["domain"]
        dest_ip = network_flow["dest_ip"]
        # if domain is safe-listed
        if is_tag_safelisted(dom, ["network.dynamic.domain"], safelist):
            network_flows_table.remove(network_flow)
        # if no domain and destination ip is safe-listed or is the dns server
        elif (not dom and is_tag_safelisted(dest_ip, ["network.dynamic.ip"], safelist)) or dest_ip in dns_servers:
            network_flows_table.remove(network_flow)
        # if dest ip is noise
        elif dest_ip not in resolved_ips and ip_address(dest_ip) in inetsim_network:
            network_flows_table.remove(network_flow)
        else:
            # if process name does not exist from DNS, then find processes that made connection calls
            process_details = {}
            if network_flow["image"] is None:
                for process in process_map:
                    process_details = process_map[process]
                    for network_call in process_details["network_calls"]:
                        connect = (
                            network_call.get("connect", {})
                            or network_call.get("InternetConnectW", {})
                            or network_call.get("InternetConnectA", {})
                            or network_call.get("WSAConnect", {})
                            or network_call.get("InternetOpenUrlA", {})
                        )
                        if (
                            connect != {}
                            and (
                                connect.get("ip_address", "") == network_flow["dest_ip"]
                                or connect.get("hostname", "") == network_flow["dest_ip"]
                            )
                            and connect["port"] == network_flow["dest_port"]
                            or (network_flow["domain"] and network_flow["domain"] in connect.get("url", ""))
                        ):
                            network_flow["image"] = process_details["name"] + " (" + str(process) + ")"
                            network_flow["pid"] = process
                            break
                    if network_flow["image"]:
                        break

            # If the record has not been removed then it should be tagged for protocol, domain, ip, and port
            _ = add_tag(netflows_sec, "network.dynamic.domain", dom)
            _ = add_tag(netflows_sec, "network.protocol", network_flow["protocol"])
            _ = add_tag(netflows_sec, "network.dynamic.ip", dest_ip, safelist)
            _ = add_tag(netflows_sec, "network.dynamic.ip", network_flow["src_ip"], safelist)
            _ = add_tag(netflows_sec, "network.port", network_flow["dest_port"])
            _ = add_tag(netflows_sec, "network.port", network_flow["src_port"])

            nc = so.create_network_connection(
                source_ip=network_flow["src_ip"],
                source_port=network_flow["src_port"],
                destination_ip=network_flow["dest_ip"],
                destination_port=network_flow["dest_port"],
                time_observed=network_flow["timestamp"],
                transport_layer_protocol=network_flow["protocol"],
                direction="outbound",
            )
            nc.update_process(pid=network_flow["pid"], image=process_details.get("name"), start_time=network_flow["timestamp"])
            so.add_network_connection(nc)

            # We want all key values for all network flows except for timestamps and event_type
            del network_flow["timestamp"]

    for answer, request in resolved_ips.items():
        nd = so.create_network_dns(domain=request["domain"], resolved_ips=[answer], lookup_type=request["type"])
        nd.update_connection_details(
            destination_ip=dns_servers[0] if dns_servers else None,
            destination_port=53,
            transport_layer_protocol="udp",
            direction="outbound",
        )
        nd.update_process(pid=request["process_id"], image=request["process_name"], guid=request["guid"])
        so.add_network_dns(nd)

    if dns_res_sec and len(dns_res_sec.tags.get("network.dynamic.domain", [])) > 0:
        network_res.add_subsection(dns_res_sec)
    unique_netflows: List[Dict[str, Any]] = []
    if len(network_flows_table) > 0:
        # Need to convert each dictionary to a string in order to get the set of network_flows_table, since
        # dictionaries are not hashable
        for item in network_flows_table:
            if item not in unique_netflows:  # Remove duplicates
                unique_netflows.append(item)
                netflows_sec.add_row(TableRow(**item))
        network_res.add_subsection(netflows_sec)

    # HTTP/HTTPS section
    http_level_flows = {
        "http": network.get("http", []),
        "https": network.get("https", []),
        "http_ex": network.get("http_ex", []),
        "https_ex": network.get("https_ex", []),
    }
    _process_http_calls(http_level_flows, process_map, dns_servers, resolved_ips, safelist, so)
    http_calls = so.get_network_http()
    if len(http_calls) > 0:
        http_sec = ResultTableSection("Protocol: HTTP/HTTPS")
        remote_file_access_sec = ResultTextSection("Access Remote File")
        remote_file_access_sec.add_line("The sample attempted to download the following files:")
        suspicious_user_agent_sec = ResultTextSection("Suspicious User Agent(s)")
        suspicious_user_agent_sec.add_line("The sample made HTTP calls via the following user agents:")
        sus_user_agents_used = []
        http_sec.set_heuristic(1002)
        _ = add_tag(http_sec, "network.protocol", "http")

        for http_call in http_calls:
            if not add_tag(http_sec, "network.dynamic.ip", http_call.connection_details.destination_ip, safelist) and not so.get_domain_by_destination_ip(http_call.connection_details.destination_ip):
                continue
            elif http_call.connection_details.destination_ip in dns_servers:
                continue
            _ = add_tag(http_sec, "network.port", http_call.connection_details.destination_port)
            _ = add_tag(
                http_sec,
                "network.dynamic.domain",
                so.get_domain_by_destination_ip(http_call.connection_details.destination_ip),
                safelist,
            )
            _ = add_tag(http_sec, "network.dynamic.uri", http_call.request_uri, safelist)

            # Now we're going to try to detect if a remote file is attempted to be downloaded over HTTP
            if http_call.request_method == "GET":
                split_path = http_call.request_uri.rsplit("/", 1)
                if len(split_path) > 1 and search(r"[^\\]*\.(\w+)$", split_path[-1]):
                    if not remote_file_access_sec.body:
                        remote_file_access_sec.add_line(f"\t{http_call.request_uri}")
                    elif f"\t{http_call.request_uri}" not in remote_file_access_sec.body:
                        remote_file_access_sec.add_line(f"\t{http_call.request_uri}")
                    if not remote_file_access_sec.heuristic:
                        remote_file_access_sec.set_heuristic(1003)
                    _ = add_tag(remote_file_access_sec, "network.dynamic.uri", http_call.request_uri, safelist)

            user_agent = http_call.request_headers.get("UserAgent")
            if user_agent:
                if any(sus_user_agent in user_agent for sus_user_agent in SUSPICIOUS_USER_AGENTS):
                    if suspicious_user_agent_sec.heuristic is None:
                        suspicious_user_agent_sec.set_heuristic(1007)
                    sus_user_agent_used = next(
                        (sus_user_agent for sus_user_agent in SUSPICIOUS_USER_AGENTS if (sus_user_agent in user_agent)), None
                    )
                    if sus_user_agent_used not in sus_user_agents_used:
                        _ = add_tag(suspicious_user_agent_sec, "network.user_agent", sus_user_agent_used, safelist)
                        suspicious_user_agent_sec.add_line(f"\t{sus_user_agent_used}")
                        sus_user_agents_used.append(sus_user_agent_used)

            http_sec.add_row(
                TableRow(
                    process_name=f"{http_call.get_process_image()} ({http_call.get_process_pid()})",
                    request=http_call.request_headers,
                    uri=http_call.request_uri,
                )
            )
        if remote_file_access_sec.heuristic:
            http_sec.add_subsection(remote_file_access_sec)
        if suspicious_user_agent_sec.heuristic:
            suspicious_user_agent_sec.add_line(" | ".join(sus_user_agents_used))
            http_sec.add_subsection(suspicious_user_agent_sec)
        if http_sec.body or http_sec.subsections:
            network_res.add_subsection(http_sec)
    else:
        _process_non_http_traffic_over_http(network_res, unique_netflows)

    if len(network_res.subsections) > 0:
        parent_result_section.add_subsection(network_res)


def _get_dns_sec(resolved_ips: Dict[str, Dict[str, Any]], safelist: Dict[str, Dict[str, List[str]]]) -> ResultTableSection:
    """
    This method creates the result section for DNS traffic
    :param resolved_ips: the mapping of resolved IPs and their corresponding domains
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: the result section containing details that we care about
    """
    if len(resolved_ips.keys()) == 0:
        return None
    dns_res_sec = ResultTableSection("Protocol: DNS")
    dns_res_sec.set_heuristic(1000)
    dns_body: List[Dict[str, str]] = []
    _ = add_tag(dns_res_sec, "network.protocol", "dns")
    for answer, request_dict in resolved_ips.items():
        request = request_dict["domain"]
        _ = add_tag(dns_res_sec, "network.dynamic.ip", answer, safelist)
        if add_tag(dns_res_sec, "network.dynamic.domain", request, safelist):
            # If there is only UDP and no TCP traffic, then we need to tag the domains here:
            dns_request = {
                "domain": request,
                "ip": answer,
            }
            dns_body.append(dns_request)
    [dns_res_sec.add_row(TableRow(**dns)) for dns in dns_body]
    return dns_res_sec


def _get_dns_map(
    dns_calls: List[Dict[str, Any]], process_map: Dict[int, Dict[str, Any]], routing: str, dns_servers: List[str]
) -> Dict[str, Dict[str, Any]]:
    """
    This method creates a map between domain calls and IPs returned
    :param dns_calls: DNS details that were captured by CAPE
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param routing: The method of routing used in the CAPE environment
    :param dns_servers: A list of DNS servers
    :return: the mapping of resolved IPs and their corresponding domains
    """
    resolved_ips: Dict[str, Dict[str, Any]] = {}
    for dns_call in dns_calls:
        if len(dns_call["answers"]) > 0:
            answer = dns_call["answers"][0]["data"]
            request = dns_call["request"]
            dns_type = dns_call["type"]

            # If the method of routing is INetSim or a variation of INetSim, then we will not use PTR records. The reason being that there is
            # always a chance for collision between IPs and hostnames due to the DNS cache, and that chance increases
            # the smaller the size of the random network space
            if routing.lower() in [INETSIM.lower(), "none"] and dns_type == "PTR":
                continue

            # A DNS pointer record (PTR for short) provides the domain name associated with an IP address.
            if dns_type == "PTR" and "in-addr.arpa" in request:
                # Determine the ip from the ARPA request by extracting and reversing the IP from the "ip"
                request = request.replace(".in-addr.arpa", "")
                split_ip = request.split(".")
                request = f"{split_ip[3]}.{split_ip[2]}.{split_ip[1]}.{split_ip[0]}"

                # If PTR and A request for the same ip-domain pair, we choose the A
                if request in resolved_ips:
                    continue

                resolved_ips[request] = {"domain": answer}
            elif dns_type == "PTR" and "ip6.arpa" in request:
                # Drop it
                continue
            # Some Windows nonsense
            elif answer in dns_servers:
                continue
            # An 'A' record provides the IP address associated with a domain name.
            else:
                resolved_ips[answer] = {
                    "domain": request,
                    "process_id": dns_call.get("pid"),
                    "process_name": dns_call.get("image"),
                    "time": dns_call.get("time"),
                    "guid": dns_call.get("guid"),
                    "type": dns_type,
                }
    # now map process_name to the dns_call
    for process, process_details in process_map.items():
        for network_call in process_details["network_calls"]:
            dns = next((network_call[api_call] for api_call in DNS_API_CALLS if api_call in network_call), {})
            if dns != {} and (dns.get("hostname") or dns.get("servername")):
                ip_mapped_to_host = next((ip for ip, details in resolved_ips.items() if details["domain"] in [dns.get("hostname"), dns.get("servername")]), None)
                if not ip_mapped_to_host:
                    continue
                if not resolved_ips[ip_mapped_to_host].get("process_name"):
                    resolved_ips[ip_mapped_to_host]["process_name"] = process_details["name"]
                if not resolved_ips[ip_mapped_to_host].get("process_id"):
                    resolved_ips[ip_mapped_to_host]["process_id"] = process
    return resolved_ips


def _get_low_level_flows(
    resolved_ips: Dict[str, Dict[str, Any]], flows: Dict[str, List[Dict[str, Any]]], safelist: Dict[str, Dict[str, List[str]]]
) -> Tuple[List[Dict[str, Any]], ResultTableSection]:
    """
    This method converts low level network calls to a general format
    :param resolved_ips: A map of process IDs to process names, network calls, and decrypted buffers
    :param flows: UDP and TCP flows from CAPE's analysis
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: Returns a table of low level network calls, and a result section for the table
    """
    # TCP and UDP section
    network_flows_table: List[Dict[str, Any]] = []

    # This result section will contain all of the "flows" from src ip to dest ip
    netflows_sec = ResultTableSection("TCP/UDP Network Traffic")

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
                dst_port_pair = dumps({network_call["dst"]: network_call["dport"]})
                if dst_port_pair not in [dumps({x["dst"]: x["dport"]}) for x in network_calls_made_to_unique_ips]:
                    network_calls_made_to_unique_ips.append(network_call)
            network_calls = network_calls_made_to_unique_ips
        for network_call in network_calls:
            dst = network_call["dst"]
            src = network_call["src"]
            src_port: Optional[str] = None
            if is_tag_safelisted(src, ["network.dynamic.ip"], safelist):
                src: Optional[str] = None
            if src:
                src_port = network_call["sport"]
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
            }
            if dst in resolved_ips.keys():
                network_flow["domain"] = resolved_ips[dst]["domain"]
                if not network_flow["image"]:
                    network_flow["image"] = resolved_ips[dst].get("process_name")
                if network_flow["image"] and not network_flow["pid"]:
                    network_flow["pid"] = resolved_ips[dst]["process_id"]
            network_flows_table.append(network_flow)
    return network_flows_table, netflows_sec


def _process_http_calls(
    http_level_flows: Dict[str, List[Dict[str, Any]]],
    process_map: Dict[int, Dict[str, Any]],
    dns_servers: List[str],
    resolved_ips: Dict[str, Dict[str, Any]],
    safelist: Dict[str, Dict[str, List[str]]],
    so: SandboxOntology,
) -> None:
    """
    This method processes HTTP(S) calls and puts them into a nice table
    :param http_level_flows: A list of flows that represent HTTP calls
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param dns_servers: A list of DNS servers
    :param resolved_ips: A map of process IDs to process names, network calls, and decrypted buffers
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology class object
    :return: None
    """
    for protocol, http_calls in http_level_flows.items():
        if len(http_calls) <= 0:
            continue
        for http_call in http_calls:

            host = http_call["host"]
            if ":" in host:  # split on port if port exists
                host = host.split(":")[0]
            if not host:
                continue
            if is_valid_ip(host) and "dst" not in http_call:
                http_call["dst"] = host

            if "ex" in protocol:
                path = http_call["uri"]
                if host in path:
                    path = path.split(host)[1]
                request = http_call["request"]
                port = http_call["dport"]
                uri = f"{http_call['protocol']}://{host}{path}"

                # The dst could be the nest IP, so we want to replace this
                if http_call["dst"] in dns_servers and any(host == item["domain"] for item in resolved_ips.values()):
                    for ip, details in resolved_ips.items():
                        if details["domain"] == host:
                            http_call["dst"] = ip
                            break

            else:
                path = http_call["path"]
                request = http_call["data"]
                port = http_call["port"]
                uri = http_call["uri"]

            if (
                is_tag_safelisted(host, ["network.dynamic.ip", "network.dynamic.domain"], safelist)
                or is_tag_safelisted(uri, ["network.dynamic.uri"], safelist)
                or "/wpad.dat" in uri
                or not re_match(FULL_URI, uri)
            ):
                continue

            request_body_path = http_call.get("req", {}).get("path")
            response_body_path = http_call.get("resp", {}).get("path")

            if request_body_path:
                request_body_path = request_body_path[request_body_path.index("network/") :]
            if response_body_path:
                response_body_path = response_body_path[response_body_path.index("network/") :]

            request_headers = _handle_http_headers(request)
            response_headers = _handle_http_headers(http_call.get("response"))

            nh_to_add = False
            nh = so.get_network_http_by_details(
                request_uri=uri, request_method=http_call["method"], request_headers=request_headers
            )
            if not nh:
                nh = so.create_network_http()
                nh_to_add = True

            nh.update(
                request_uri=uri,
                response_status_code=http_call.get("status"),
                request_method=http_call["method"],
                request_headers=request_headers,
                response_headers=response_headers,
                request_body_path=request_body_path,
                response_body_path=response_body_path,
            )

            nh.update_connection_details(
                source_ip=http_call.get("src"),
                source_port=http_call.get("sport"),
                destination_ip=http_call["dst"]
                if http_call.get("dst") and http_call["dst"] not in dns_servers
                else so.get_destination_ip_by_domain(host),
                destination_port=port,
                direction="outbound",
                transport_layer_protocol="tcp",
            )

            match = False
            for process, process_details in process_map.items():
                for network_call in process_details["network_calls"]:
                    send = next((network_call[api_call] for api_call in HTTP_API_CALLS if api_call in network_call), {})
                    if (
                        send != {}
                        and (send.get("service", 0) == 3 or send.get("buffer", "") == request)
                        or send.get("url", "") == uri
                    ):
                        nh.update_process(image=process_details["name"], pid=process)
                        match = True
                        break
                if match:
                    break

            if nh_to_add:
                so.add_network_http(nh)
            else:
                network_connection_to_point_to = so.get_network_connection_by_details(
                    nh.connection_details.source_ip,
                    nh.connection_details.source_port,
                    nh.connection_details.destination_ip,
                    nh.connection_details.destination_port,
                    nh.connection_details.direction,
                    nh.connection_details.transport_layer_protocol,
                )
                if network_connection_to_point_to:
                    if match:
                        # Do not allow unvalidated process to linger after unlinking
                        nh.connection_details.process = None
                    nh.set_network_connection(network_connection_to_point_to)


def _handle_http_headers(header_string: str) -> Dict[str, str]:
    """
    This method parses an HTTP header string and returns the parsed string in a nice dictionary
    :param header_string: The HTTP header string to be parsed
    :return: The parsed string as a nice dictionary
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


def process_all_events(parent_result_section: ResultSection, so: SandboxOntology) -> None:
    """
    This method converts all events to a table that is sorted by timestamp
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param so: The sandbox ontology class object
    :return: None
    """
    # Each item in the events table will follow the structure below:
    # {
    #   "timestamp": timestamp,
    #   "process_name": process_name,
    #   "details": {}
    # }
    if not so.get_processes() and not so.get_network_connections():
        return
    events_section = ResultTableSection("Event Log")
    event_ioc_table = ResultTableSection("Event Log IOCs")
    for event in so.get_events(safelist=SAFE_PROCESS_TREE_LEAF_HASHES.keys()):
        if isinstance(event, NetworkConnection):
            if event.objectid.time_observed in [float("-inf"), float("inf")]:
                continue
            events_section.add_row(
                TableRow(
                    time_observed=datetime.fromtimestamp(event.objectid.time_observed).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    process_name=f"{getattr(event.process, 'image', None)} ({getattr(event.process, 'pid', None)})",
                    details={
                        "protocol": event.transport_layer_protocol,
                        "domain": so.get_domain_by_destination_ip(event.destination_ip),
                        "dest_ip": event.destination_ip,
                        "dest_port": event.destination_port,
                    },
                )
            )
        elif isinstance(event, Process):
            if event.start_time in [float("-inf"), float("inf")]:
                continue
            _ = add_tag(events_section, "dynamic.process.command_line", event.command_line)
            extract_iocs_from_text_blob(event.command_line, event_ioc_table)
            _ = add_tag(events_section, "dynamic.process.file_name", event.image)
            if isinstance(event.start_time, float) or isinstance(event.start_time, int):
                time_observed = datetime.fromtimestamp(event.start_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            else:
                time_observed = event.start_time
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
    if event_ioc_table.body:
        events_section.add_subsection(event_ioc_table)
    if events_section.body:
        parent_result_section.add_subsection(events_section)


def process_curtain(curtain: Dict[str, Any], parent_result_section: ResultSection, process_map: Dict[int, Dict[str, Any]]) -> None:
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
    for pid in curtain.keys():
        process_name = process_map[int(pid)]["name"] if process_map.get(int(pid)) else "powershell.exe"
        for event in curtain[pid]["events"]:
            for command in event.keys():
                curtain_item = {"process_name": process_name, "original": event[command]["original"], "reformatted": None}
                altered = event[command]["altered"]
                if altered != "No alteration of event.":
                    curtain_item["reformatted"] = altered
                curtain_body.append(curtain_item)
        _ = add_tag(curtain_res, "file.powershell.cmdlet", [behaviour for behaviour in curtain[pid]["behaviors"]])
    if len(curtain_body) > 0:
        [curtain_res.add_row(TableRow(**cur)) for cur in curtain_body]
        parent_result_section.add_subsection(curtain_res)


def convert_sysmon_network(
    sysmon: List[Dict[str, Any]], network: Dict[str, Any], safelist: Dict[str, Dict[str, List[str]]]
) -> None:
    """
    This method converts network connections observed by Sysmon to the format supported by CAPE
    :param sysmon: A list of processes observed during the analysis of the task by the Sysmon tool
    :param network: The JSON of the network section from the report generated by CAPE
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    for event in sysmon:
        event_id = int(event["System"]["EventID"])

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
                    network_conn["time"] = datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").timestamp()
                elif name == "ProcessGuid":
                    network_conn["guid"] = text
                elif name == "ProcessId":
                    network_conn["pid"] = int(text)
                elif name == "Image":
                    network_conn["image"] = text
                elif name == "Protocol":
                    protocol = text.lower()
                elif name == "SourceIp":
                    network_conn["src"] = text
                elif name == "SourcePort":
                    network_conn["sport"] = int(text)
                elif name == "DestinationIp":
                    network_conn["dst"] = text
                elif name == "DestinationPort":
                    network_conn["dport"] = int(text)
            if any(network_conn[key] is None for key in network_conn.keys()) or not protocol:
                continue
            elif any(
                req["dst"] == network_conn["dst"]
                and req["dport"] == network_conn["dport"]
                and req["src"] == network_conn["src"]
                and req["sport"] == network_conn["sport"]
                for req in network[protocol]
            ):
                # Replace record since we have more info from Sysmon
                for req in network[protocol][:]:
                    if (
                        req["dst"] == network_conn["dst"]
                        and req["dport"] == network_conn["dport"]
                        and req["src"] == network_conn["src"]
                        and req["sport"] == network_conn["sport"]
                    ):
                        network[protocol].remove(req)
                        network[protocol].append(network_conn)
            else:
                network[protocol].append(network_conn)
        elif event_id == 22:
            dns_query = {
                "type": "A",
                "request": None,
                "answers": [],
                "time": None,
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
                    dns_query["time"] = datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").timestamp()
                elif name == "ProcessGuid":
                    dns_query["guid"] = text
                elif name == "ProcessId":
                    dns_query["pid"] = int(text)
                elif name == "QueryName":
                    if not is_tag_safelisted(text, ["network.dynamic.domain"], safelist):
                        dns_query["request"] = text
                elif name == "QueryResults":
                    ip = search(IP_REGEX, text)
                    if ip:
                        ip = ip.group(0)
                        dns_query["answers"].append({"data": ip, "type": "A"})
                elif name == "Image":
                    dns_query["image"] = text
            if any(dns_query[key] is None for key in dns_query.keys()):
                continue
            elif any(query["request"] == dns_query["request"] for query in network["dns"]):
                # Replace record since we have more info from Sysmon
                for query in network["dns"][:]:
                    if query["request"] == dns_query["request"]:
                        network["dns"].remove(query)
                        network["dns"].append(dns_query)
            else:
                network["dns"].append(dns_query)


def process_hollowshunter(
    hollowshunter: Dict[str, Any], parent_result_section: ResultSection, process_map: Dict[int, Dict[str, Any]]
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


def process_buffers(process_map: Dict[int, Dict[str, Any]], parent_result_section: ResultSection) -> None:
    """
    This method checks for any buffers found in the process map, and adds them to the Assemblyline report
    :param process_map: A map of process IDs to process names, network calls, and buffers
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :return:
    """
    buffer_res = ResultTableSection("Buffers", auto_collapse=True)
    buffer_ioc_table = ResultTableSection("Buffer IOCs")
    buffer_body = []

    for process, process_details in process_map.items():
        count_per_source_per_process = 0
        process_name_to_be_displayed = f"{process_details.get('name', 'None')} ({process})"
        for call in process_details.get("decrypted_buffers", []):
            buffer = ""
            if call.get("CryptDecrypt"):
                buffer = call["CryptDecrypt"]["buffer"]
            elif call.get("OutputDebugStringA"):
                buffer = call["OutputDebugStringA"]["string"]
            if not buffer:
                continue
            extract_iocs_from_text_blob(buffer, buffer_ioc_table)
            table_row = {"Process": process_name_to_be_displayed, "Source": "Windows API", "Buffer": safe_str(buffer)}
            if table_row not in buffer_body and count_per_source_per_process < BUFFER_ROW_LIMIT_PER_SOURCE_PER_PROCESS:
                buffer_body.append(table_row)
                count_per_source_per_process += 1

        count_per_source_per_process = 0
        for network_call in process_details.get("network_calls", []):
            for api_call in BUFFER_API_CALLS:
                if api_call in network_call:
                    buffer = network_call[api_call]["buffer"]
                    buffer = _remove_bytes_from_buffer(buffer)
                    length_of_ioc_table_pre_extraction = len(buffer_ioc_table.body) if buffer_ioc_table.body else 0
                    extract_iocs_from_text_blob(buffer, buffer_ioc_table, enforce_char_min=True)
                    # We only want to display network buffers if an IOC is found
                    length_of_ioc_table_post_extraction = len(buffer_ioc_table.body) if buffer_ioc_table.body else 0
                    if length_of_ioc_table_pre_extraction == length_of_ioc_table_post_extraction:
                        continue
                    table_row = {"Process": process_name_to_be_displayed, "Source": "Network", "Buffer": safe_str(buffer)}
                    if table_row not in buffer_body and count_per_source_per_process < BUFFER_ROW_LIMIT_PER_SOURCE_PER_PROCESS:
                        buffer_body.append(table_row)
                        count_per_source_per_process += 1

    if len(buffer_body) > 0:
        [buffer_res.add_row(TableRow(**buffer)) for buffer in buffer_body]
        if buffer_ioc_table.body:
            buffer_res.add_subsection(buffer_ioc_table)
            buffer_res.set_heuristic(1006)
        parent_result_section.add_subsection(buffer_res)


def process_cape(cape: Dict[str, Any]) -> Dict[str, int]:
    """
    This method creates a map of payloads and the pids that they were hollowed out of
    :param cape: A dictionary containing the CAPE reporting output
    :return: A map of payloads and the pids that they were hollowed out of
    """
    return {payload["sha256"]: payload["pid"] for payload in cape.get("payloads", [])}


def get_process_map(processes: List[Dict[str, Any]], safelist: Dict[str, Dict[str, List[str]]]) -> Dict[int, Dict[str, Any]]:
    """
    This method creates a process map that maps process IDs with useful details
    :param processes: A list of processes observed by CAPE
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: A map of process IDs to process names, network calls, and decrypted buffers
    """
    process_map: Dict[int, Dict[str, Any]] = {}
    api_calls_of_interest = {
        "getaddrinfo": ["hostname"],  # DNS
        "GetAddrInfoW": ["hostname", "nodename"],  # DNS
        "gethostbyname": ["hostname"],  # DNS
        "connect": ["ip_address", "port"],  # Connecting to IP
        "InternetConnectW": ["username", "service", "password", "hostname", "port", "servername", "serverport"],
        "InternetConnectA": ["username", "service", "password", "hostname", "port"],
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
        "InternetCrackUrlW": ["url"],
        "InternetOpenUrlA": ["url"],
    }
    for process in processes:
        process_name = process["module_path"] if process.get("module_path") else process["process_name"]
        if is_tag_safelisted(process_name, ["dynamic.process.file_name"], safelist):
            continue
        network_calls = []
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
                                args_of_interest[arg] = kv["value"]
                                break
                if args_of_interest:
                    item_to_add = {api: args_of_interest}
                    if category == "network" and item_to_add not in network_calls:
                        network_calls.append(item_to_add)
                    elif category in ["crypto", "system"] and item_to_add not in decrypted_buffers:
                        decrypted_buffers.append(item_to_add)

        pid = process["process_id"]
        process_map[pid] = {"name": process_name, "network_calls": network_calls, "decrypted_buffers": decrypted_buffers}
    return process_map


def _create_signature_result_section(
    name: str, signature: Dict[str, Any], translated_score: int, so_sig: SandboxOntology.Signature
) -> ResultMultiSection:
    """
    This method creates a ResultMultiSection for the given signature
    :param name: The name of the signature
    :param signature: The details of the signature
    :param translated_score: The Assemblyline-adapted score of the signature
    :param so_sig: The signature for the Sandbox Ontology
    :return: A ResultMultiSection containing details about the signature
    """
    sig_res = ResultMultiSection(f"Signature: {name}")
    description = signature.get("description", "No description for signature.")
    sig_res.add_section_part(TextSectionBody(body=description))

    # Setting up the heuristic for each signature
    sig_id = get_category_id(name)
    if sig_id == 9999:
        log.warning(f"Unknown signature detected: {signature}")

    # Creating heuristic
    sig_res.set_heuristic(sig_id)

    # Adding signature and score
    sig_res.heuristic.add_signature_id(name, score=translated_score)

    # Setting the Mitre ATT&CK ID for the heuristic
    attack_ids = signature.get("ttp", {})
    for attack_id in attack_ids:
        if attack_id in revoke_map:
            attack_id = revoke_map[attack_id]
        sig_res.heuristic.add_attack_id(attack_id)
        so_sig.add_attack_id(attack_id)
    for attack_id in sig_res.heuristic.attack_ids:
        so_sig.add_attack_id(attack_id)

    # Getting the signature family and tagging it
    sig_families = [family for family in signature.get("families", []) if family not in SKIPPED_FAMILIES]
    if len(sig_families) > 0:
        sig_res.add_section_part(TextSectionBody(body="\tFamilies: " + ",".join([safe_str(x) for x in sig_families])))
        _ = add_tag(sig_res, "dynamic.signature.family", [family for family in sig_families])

    # Get the evidence that supports why the signature was raised
    mark_count = 0
    message_added = False
    for mark in signature["data"]:
        if mark_count >= 10 and not message_added:
            sig_res.add_section_part(
                TextSectionBody(body=f"There were {len(signature['data']) - mark_count} more marks that were not displayed.")
            )
            message_added = True
        mark_body = KVSectionBody()
        for k, v in mark.items():
            if not v:
                continue
            if k in MARK_KEYS_TO_NOT_DISPLAY:
                continue
            if dumps({k: v}) in sig_res.section_body.body:
                continue
            else:
                if mark_count < 10:
                    if (isinstance(v, str) or isinstance(v, bytes)) and len(v) > 512:
                        v = truncate(v, 512)
                    mark_body.set_item(k, v)
                _tag_mark_values(sig_res, k, v)
        if mark_body.body:
            sig_res.add_section_part(mark_body)
            mark_count += 1

    so_sig.update(name=name, description=description, score=translated_score)
    return sig_res


def _tag_mark_values(sig_res: ResultSection, key: str, value: str) -> None:
    """
    This method tags a given value accordingly by the key
    :param sig_res: The signature result section
    :param key: The mark's key
    :param value: The mark's value for the given key
    :return: None
    """
    delimiters = [":", "->", ",", " ", "("]
    if key.lower() in ["cookie", "process", "binary", "data", "copy", "office_martian", "file", "service", "getasynckeystate", "setwindowshookexw"]:
        if not isinstance(value, str) and isinstance(value, list):
            value = ','.join(value)
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
    elif key.lower() in ["http_request", "url", "suspicious_request", "ioc", "request", "http_downloadurl"]:
        _ = add_tag(sig_res, "network.dynamic.uri", value)
    elif key.lower() in ["dynamicloader"]:
        _ = add_tag(sig_res, "file.pe.exports.function_name", value)
    elif key.endswith("_exe"):
        _ = add_tag(sig_res, "dynamic.process.file_name", key.replace("_", "."))
    elif key.lower() in ["hit"]:
        reg_match = search(YARA_RULE_EXTRACTOR, value)
        if reg_match:
            _ = add_tag(sig_res, "file.rule.yara", reg_match.group(1))


def _process_non_http_traffic_over_http(network_res: ResultSection, unique_netflows: List[Dict[str, Any]]) -> None:
    """
    This method adds a result section detailing non-HTTP network traffic over ports commonly used for HTTP
    :param network_res: The result section that will contain the result section detailing this traffic, if any
    :param unique_netflows: Network flows observed during CAPE analysis
    :return: None
    """
    non_http_traffic_result_section = ResultTableSection("Non-HTTP Traffic Over HTTP Ports")
    non_http_list: List[Dict[str, Any]] = []
    # If there was no HTTP/HTTPS calls made, then confirm that there was no suspicious
    for netflow in unique_netflows:
        if netflow["dest_port"] in [443, 80]:
            non_http_list.append(netflow)
            _ = add_tag(non_http_traffic_result_section, "network.dynamic.ip", netflow["dest_ip"])
            _ = add_tag(non_http_traffic_result_section, "network.dynamic.domain", netflow["domain"])
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


def convert_sysmon_processes(sysmon: List[Dict[str, Any]], safelist: Dict[str, Dict[str, List[str]]], so: SandboxOntology):
    """
    This method creates the GUID -> Process lookup table
    :param sysmon: A list of processes observed during the analysis of the task by the Sysmon tool
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology object instance
    :return: None
    """
    for event in sysmon:
        event_id = int(event["System"]["EventID"])
        process: Dict[str, str] = {}
        event_data = event["EventData"]["Data"]
        for data in event_data:
            name = data["@Name"].lower()
            text = data.get("#text")

            # Process Create and Terminate
            if name == "utctime" and event_id in [1, 5]:
                if event_id == 1:
                    process["start_time"] = datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").timestamp()
                else:
                    process["end_time"] = datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").timestamp()
            elif name == "utctime" and event_id in [10]:
                process["start_time"] = datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").timestamp()
            elif name == "utctime":
                process["time_observed"] = datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").timestamp()
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
                if not is_tag_safelisted(text, ["dynamic.process.file_name"], safelist):
                    process["image"] = text
            elif name in ["parentcommandline"]:
                if not is_tag_safelisted(text, ["dynamic.process.command_line"], safelist):
                    process["pcommand_line"] = text
            elif name in ["commandline"]:
                if not is_tag_safelisted(text, ["dynamic.process.command_line"], safelist):
                    process["command_line"] = text
            elif name == "originalfilename":
                process["original_file_name"] = text
            elif name == "integritylevel":
                process["integrity_level"] = text
            elif name == "hashes":
                split_hash = text.split("=")
                if len(split_hash) == 2:
                    _, hash_value = split_hash
                    process["image_hash"] = hash_value

        if not process.get("guid") or not process.get("image"):
            continue

        if so.is_guid_in_gpm(process["guid"]):
            so.update_process(**process)
        else:
            p = so.create_process(**process)
            so.add_process(p)


def _update_process_map(process_map: Dict[int, Dict[str, Any]], processes: List[Process]) -> None:
    """
    This method updates the process map with the processes added to the sandbox ontology
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param processes: A list of processes
    :return: None
    """
    for process in processes:
        if process.pid in process_map or process.pid == SYSTEM_PROCESS_ID:
            continue

        process_map[process.pid] = {"name": process.image, "network_calls": [], "decrypted_buffers": []}


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
            non_byte_chars.append(res)
    return ','.join(non_byte_chars)


if __name__ == "__main__":
    from sys import argv
    from json import loads

    # pip install PyYAML
    import yaml
    from cape.safe_process_tree_leaf_hashes import SAFE_PROCESS_TREE_LEAF_HASHES
    # from assemblyline.odm.models.ontology.results.sandbox import Sandbox

    report_path = argv[1]
    file_ext = argv[2]
    random_ip_range = argv[3]
    routing = argv[4]
    safelist_path = argv[5]

    with open(safelist_path, "r") as f:
        safelist = yaml.safe_load(f)
    safelist["regex"]["network.dynamic.ip"].append(random_ip_range.replace(".", "\\.").replace("0/24", ".*"))

    so = SandboxOntology(sandbox_name="CAPE Sandbox")

    with open(report_path, "r") as f:
        api_report = loads(f.read())

    al_result = ResultSection("Parent")

    generate_al_result(api_report, al_result, file_ext, random_ip_range, routing, safelist, so)

    so.preprocess_ontology(SAFE_PROCESS_TREE_LEAF_HASHES.keys())
    print(dumps(so.as_primitives(), indent=4))
    # Sandbox(data=so.as_primitives())
