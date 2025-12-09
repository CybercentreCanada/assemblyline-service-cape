import json
import shutil
import os
import sys
from ipaddress import IPv4Network, ip_network
import yaml

import pytest
from assemblyline_service_utilities.common.dynamic_service_helper import (
    Attribute,
    NetworkConnection,
    NetworkDNS,
    NetworkHTTP,
    ObjectID,
    OntologyResults,
    Process,
    Signature,
    attach_dynamic_ontology,
)
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.helper import get_heuristics
from assemblyline.common.heuristics import HeuristicHandler, InvalidHeuristicException
from assemblyline_service_utilities.common.sysmon_helper import UNKNOWN_PROCESS
from assemblyline_service_utilities.testing.helper import check_section_equality
from assemblyline_v4_service.common.result import (
    BODY_FORMAT,
    Heuristic,
    KVSectionBody,
    ProcessItem,
    ResultMultiSection,
    ResultProcessTreeSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
    TextSectionBody,
    Result
)
from cape.safe_process_tree_leaf_hashes import SAFE_PROCESS_TREE_LEAF_HASHES
sys.path.append('.')
from cape.cape_result import (
    ANALYSIS_ERRORS,
    BUFFER_PATH,
    generate_al_result,
    load_ontology_and_result_section,
    process_info,
    process_machine_info,
    process_debug,
    get_process_map,
    process_signatures,
    get_network_map,
    _get_dns_map,
    _get_low_level_flows,
    _process_http_calls,
    process_curtain,
    process_hollowshunter,
    process_buffers,
    process_cape,
    get_process_map,
    build_process_tree,
    process_sysmon,
    process_behavior,
    _remove_bytes_from_buffer,
    convert_processtree_id_to_tree_id,
    _remove_network_http_noise,
    _determine_dns_servers,
    _remove_network_call,
    _massage_host_data,
    _massage_http_ex_data,
    _get_important_fields_from_http_call,
    _is_http_call_safelisted,
    _massage_body_paths,
    _get_destination_ip,
    _uris_are_equal_despite_discrepancies,
    _handle_similar_netloc_and_path,
    _handle_http_headers,
    _create_signature_result_section,
    _is_mark_call,
    _handle_mark_call,
    _handle_mark_data,
    _tag_mark_values,
    _set_heuristic_signature,
    _set_attack_ids,
    _set_families,
    _get_dns_sec,
    _create_network_connection_for_network_flow,
    _setup_network_connection_with_network_http,
    _create_network_http,
    _get_network_connection_by_details,
    _create_network_connection_for_http_call,
    _process_non_http_traffic_over_http,
    _process_unseen_iocs,
    _api_ioc_in_network_traffic,
    _massage_api_urls,
    same_dictionaries,
)

class DictToObject:
    def __init__(self, dictionary):
        for key, value in dictionary.items():
            if isinstance(value, dict) and value:
                setattr(self, key, DictToObject(value))
            else:
                setattr(self, key, value)

class TestCapeResult:
    @pytest.fixture(autouse=True)
    def loaded_samples(self):
        LOADED_SAMPLES = []
        SAMPLES = []
        for sample_path in os.listdir("tests/samples"):
            if os.path.isdir(f"tests/samples/{sample_path}"):
                sample_dict = {
                    "Sample_identifier": sample_path,
                    "Report_path": f"tests/samples/{sample_path}/Report/reports/lite.json",
                    "Files_path": f"tests/samples/{sample_path}/Report/files.json",
                    "Ontology_path": f"tests/samples/{sample_path}/Results/result_ontology.json",
                    "Result_path": f"tests/samples/{sample_path}/Results/result.json",
                    "Sandbox_section": f"tests/samples/{sample_path}/Results/Section.json"
                }
                SAMPLES.append(sample_dict)
        FILES = []
        for sample in SAMPLES:
            report = json.loads(open(sample["Report_path"], "rb").read().decode("utf-8"))
            REPORT_SECTIONS = {
                "info": report.get("info", {}),
                "debug": report.get("debug", {}),
                "signatures": report.get("signatures", {}),
                "network": report.get("network", {}),
                "behavior": report.get("behavior", {}),
                "curtain": report.get("curtain", {}),
                "sysmon": report.get("sysmon", {}),
                "hollowshunter": report.get("hollowshunter", {}),
                "CAPE": report.get("CAPE", {})
            }
            with open(sample["Files_path"], "r") as f:
                for line in f.readlines():
                    FILES.append(json.loads(line))
            ontology = json.loads(open(sample["Ontology_path"], "rb").read().decode("utf-8"))
            ONTOLOGY_SECTIONS = {
                "sandboxes": ontology.get("sandboxes", {}),
                "signatures": ontology.get("signatures", {}),
                "network_connections": ontology.get("network_connections", {}),
                "network_dns": ontology.get("network_dns", {}),
                "network_http": ontology.get("network_http", {}),
                "processes": ontology.get("processes", {}),
            }
            al_results = json.loads(open(sample["Result_path"], "rb").read().decode("utf-8"))
            SCORE = al_results.get("result", {}).get("score", -1)
            RESULT_SECTIONS = al_results
            sandbox = json.loads(open(sample["Sandbox_section"], "rb").read().decode("utf-8"))
            SANDBOX_SECTION = {
                "signatures": sandbox.get("signatures", {}),
                "network_connections": sandbox.get("network_connections", {}),
                "processes": sandbox.get("processes", {}),
                "analysis_information": sandbox.get("analysis_information", {}),
            }
            fully_loaded_sample = {
                "Sample_identifier": sample["Sample_identifier"],
                "Score": SCORE,
                "Report": REPORT_SECTIONS,
                "Ontology": ONTOLOGY_SECTIONS,
                "Result": RESULT_SECTIONS,
                "Sandbox": SANDBOX_SECTION
            }
            LOADED_SAMPLES.append(fully_loaded_sample)
        yield LOADED_SAMPLES

    @pytest.fixture()
    def file_ext(self):
        return "html"

    @pytest.fixture()
    def random_ip_range(self):
        return "169.254.128.0/24"

    @pytest.fixture()
    def routing(self):
        return "internet"

    @pytest.fixture()
    def inetsim_dns_servers(self):
        return "169.254.128.2"

    @pytest.fixture()
    def uses_https_proxy_in_sandbox(self):
        return False

    @pytest.fixture()
    def suspicious_accepted_languages(self):
        return "us"

    @pytest.fixture()
    def safelist(self, random_ip_range):
        safelist_path = "al_config/system_safelist.yaml"
        with open(safelist_path, "r") as f:
            safelist = yaml.safe_load(f)
        safelist["regex"]["network.dynamic.ip"].append(random_ip_range.replace(".", "\\.").replace("0/24", ".*"))
        return safelist

    @pytest.fixture()
    def custom_tree_id_safelist(self):
        custom_processtree_id_safelist = {}
        custom_tree_id_safelist = list(SAFE_PROCESS_TREE_LEAF_HASHES.values())
        custom_tree_id_safelist.extend(
            [
            convert_processtree_id_to_tree_id(item)
            for item in custom_processtree_id_safelist
            if item not in custom_tree_id_safelist
            ]
        )
        return custom_tree_id_safelist

    @pytest.fixture()
    def submission_params(self, file_ext, random_ip_range, routing, inetsim_dns_servers, uses_https_proxy_in_sandbox, suspicious_accepted_languages, safelist, custom_tree_id_safelist):
        my_params = {
            "file_ext": file_ext,
            "random_ip_range": random_ip_range,
            "routing": routing,
            "inetsim_dns_servers": inetsim_dns_servers,
            "uses_https_proxy_in_sandbox": uses_https_proxy_in_sandbox,
            "suspicious_accepted_languages": suspicious_accepted_languages,
            "safelist": safelist,
            "custom_tree_id_safelist": custom_tree_id_safelist
        }
        return my_params

    @pytest.fixture()
    def machine_info(self):
        return {
            "Name": "blahblahwin10x86",
            "Manager": "blah",
            "Platform": "Windows",
            "IP": "1.1.1.1",
            "Tags": [],
        }

    @staticmethod
    def _process_process_info(sample):
        result = Result()
        al_result = ResultSection("Parent")
        result.add_section(al_result)
        ontres = OntologyResults(service_name='CAPE')
        info = sample["Report"].get("info", {})
        process_info(info, al_result, ontres)
        return al_result, ontres


    @staticmethod
    def _process_get_process_map(sample, safelist):
        api_report = sample.get("Report")
        behaviour = api_report.get("behavior", {})
        if behaviour:
            process_map = get_process_map(behaviour.get("processes", {}), safelist)
        else:
            process_map = []
        return process_map
    
    @staticmethod
    def _process_process_sysmon(sample, safelist):
        api_report = sample.get("Report")
        sysmon = api_report.get("sysmon", [])
        if sysmon:
            parsed_sysmon = process_sysmon(sysmon, safelist)
        else:
            parsed_sysmon = []
        return parsed_sysmon
    
    @staticmethod
    def _process_get_dns_map(dns, process_map, parsed_sysmon, routing, dns_servers):
        return _get_dns_map(
                dns,
                process_map, 
                parsed_sysmon, 
                routing, 
                dns_servers
            )
    
    @staticmethod
    def _process_get_network_map(network, validated_random_ip_range, routing, process_map, safelist, inetsim_dns_servers, uses_https_proxy_in_sandbox, suspicious_accepted_languages, parsed_sysmon):
        return get_network_map(
                network,
                validated_random_ip_range,
                routing,
                process_map,
                safelist,
                inetsim_dns_servers,
                uses_https_proxy_in_sandbox,
                suspicious_accepted_languages,
                parsed_sysmon
            )
    
    @staticmethod
    def _process_process_signatures(sigs):
        return process_signatures(sigs)
# Main function for functionality requiring real results
    
    @pytest.mark.dependency(name="info_section")
    def test_process_info(self, loaded_samples):
        for sample in loaded_samples:
            identifier = sample["Sample_identifier"]
            al_result, ontres = self._process_process_info(sample)
            info_section = [section for section in sample["Result"]["result"].get("sections", []) if section["title_text"] == "Analysis Information"][0]
            info_section_object = DictToObject(info_section)
            info_ontology = sample["Ontology"].get("sandboxes", {})[0]
            result_ontology = ontres.sandboxes[0].as_primitives()
            #Fixing the depth, dropped section and unique value
            al_result.subsections[0].depth = 1
            info_section_object.subsections = []
            result_ontology["objectid"].pop("session")
            info_ontology["objectid"].pop("session")
            info_ontology["analysis_metadata"]["machine_metadata"] = None
            assert check_section_equality(al_result.subsections[0], info_section_object), f"{identifier} info section is different"
            assert same_dictionaries(result_ontology, info_ontology), f"{identifier} sandbox ontology is different"

    @pytest.mark.dependency(depends=["info_section"])
    @pytest.mark.usefixtures("machine_info")
    def test_process_machine_info(self, loaded_samples, machine_info):
        for sample in loaded_samples:
            identifier = sample["Sample_identifier"]
            _, ontres = self._process_process_info(sample)
            process_machine_info(machine_info, ontres)
            result_ontology = ontres.sandboxes[0].as_primitives()
            info_ontology = sample["Ontology"].get("sandboxes", {})[0]
            result_metadata = result_ontology["analysis_metadata"]["machine_metadata"]
            info_metadata = info_ontology["analysis_metadata"]["machine_metadata"]
            assert same_dictionaries(result_metadata, info_metadata), f"{identifier} machine metadata info is different"

    def test_process_debug(self, loaded_samples):
        for sample in loaded_samples:
            identifier = sample["Sample_identifier"]
            result = Result()
            al_result = ResultSection("Parent")
            result.add_section(al_result)
            api_report = sample.get("Report")
            debug_report_section = api_report["debug"]
            process_debug(debug_report_section, al_result)
            section = [section for section in sample["Result"]["result"].get("sections", []) if section["title_text"] == "Analysis Errors"]
            debug_section = section[0 ]if len(section) > 0 else None
            if debug_section is not None:
                debug_section_object = DictToObject(debug_section)
            else:
                debug_section_object = None
            if len(al_result.subsections) > 0 or debug_section_object is not None:
                assert check_section_equality(al_result.subsections[0], debug_section_object), f"{identifier} debug section is different"

    @pytest.mark.dependency(name="signatures")
    def test_process_signatures(self, loaded_samples):
        for sample in loaded_samples:
            identifier = sample["Sample_identifier"]
            api_report = sample.get("Report")
            sigs = api_report.get("signatures", [])
            if sigs:
                signatures = self._process_process_signatures(sigs)
            else:
                signatures = []
            essential_signatures = sample["Sandbox"].get("signatures", {})
            for sig in essential_signatures:
                assert sig["name"] in [signature["name"] for signature in signatures],  f"{identifier} signature(s) extracted from report are differents"

    @pytest.mark.dependency(name="process_map")
    @pytest.mark.usefixtures("submission_params")
    def test_get_process_map(self, loaded_samples, submission_params):
        for sample in loaded_samples:
            identifier = sample["Sample_identifier"]
            process_map = self._process_get_process_map(sample, submission_params["safelist"])
            output_processes = sample["Sandbox"]["processes"]
            for pid in process_map.keys():
                matched = False
                for process in output_processes:
                    if (process["pid"] == pid and
                        process["image"] == process_map[pid]["image"] and 
                        process["command_line"] == process_map[pid]["command_line"]   
                    ):
                        matched = True
                        break
                assert matched, f"{identifier} doesn't match process_map"

    @pytest.mark.dependency(name="process_sysmon")
    @pytest.mark.usefixtures("submission_params")
    def test_process_sysmon(self, loaded_samples, submission_params):
         for sample in loaded_samples:
            identifier = sample["Sample_identifier"]
            parsed_sysmon = self._process_process_sysmon(sample, submission_params["safelist"])
            output_connections = sample["Sandbox"]["network_connections"]
            output_processes = sample["Sandbox"]["processes"]
            for pid, event_table in parsed_sysmon.items():
                matched = False
                process_event_found = False
                have_network_connection = False
                some_network_not_matched = False
                list_of_event_id = []
                for event in event_table:
                    list_of_event_id.append(event["event_id"])
                    network_connection_matched = False
                    if event["event_id"] == 1:
                         for process in output_processes:
                            if (process["pid"] == pid and 
                                process["start_time"] == event["start_time"] and
                                process["image"] == event["image"]
                            ):
                                process_event_found = True
                    elif event["event_id"] == 5:
                        for process in output_processes:
                            if (process["pid"] == pid and 
                                process["end_time"] == event["end_time"] and
                                process["image"] == event["image"]
                            ):
                                process_event_found = True
                    elif event["event_id"] in [3,22]:
                        have_network_connection = True
                        if event["event_id"] == 3:
                            for connection in output_connections:
                                if (connection["destination_ip"] == event["dst"] and
                                    connection["destination_port"] == event["dport"] and
                                    connection["source_ip"] == event["src"] and
                                    connection["source_port"] == event["sport"]
                                ):
                                    network_connection_matched = True
                        elif event["event_id"] == 22:
                            for connection in output_connections:
                                if not connection["dns_details"]:
                                    continue
                                if connection["dns_details"]["domain"] == event["request"]:
                                    network_connection_matched = True
                        if not network_connection_matched:
                            some_network_not_matched = True

                if not process_event_found and [process["safelisted"] for process in output_processes if process["pid"] == pid]:
                    matched = True
                elif process_event_found:
                    if not have_network_connection or not some_network_not_matched:
                        matched = True
                elif len(list_of_event_id) == 0 or list_of_event_id == [5]:
                    matched = True
                else:
                    if have_network_connection and not some_network_not_matched:
                        matched = True
                assert matched, f"{identifier} doesn't match sysmon"

    @pytest.mark.dependency(name="dns_map", depends=["process_map", "process_sysmon"])
    @pytest.mark.usefixtures("submission_params")
    def test_get_dns_map(self, loaded_samples, submission_params):
        for sample in loaded_samples:
            identifier = sample["Sample_identifier"]
            api_report = sample.get("Report")
            network = api_report.get("network", {})
            dns = network.get("dns", [])
            dns_servers = _determine_dns_servers(network, submission_params["inetsim_dns_servers"])
            process_map = self._process_get_process_map(sample, submission_params["safelist"])
            parsed_sysmon = self._process_process_sysmon(sample, submission_params["safelist"])
            dns_requests = self._process_get_dns_map(dns, process_map, parsed_sysmon, submission_params["routing"], dns_servers)
            output_connections = sample["Sandbox"]["network_connections"]
            for output_connection in output_connections:
                if output_connection["connection_type"] == "dns":
                    matched = False
                    for dns_request in dns_requests.keys():
                        if output_connection["dns_details"]["domain"] == dns_request:
                            matched = True
                    assert matched, f"{identifier} dns records doesn't match"

    @pytest.mark.dependency(name="low_level_flows", depends=["process_map", "process_sysmon"])
    @pytest.mark.usefixtures("submission_params")
    def test_get_low_level_flows(self, loaded_samples, submission_params):
        for sample in loaded_samples:
            identifier = sample["Sample_identifier"]
            api_report = sample.get("Report")
            network = api_report.get("network", {})
            low_level_flows = {"udp": network.get("udp", []), "tcp": network.get("tcp", [])}
            process_map = self._process_get_process_map(sample, submission_params["safelist"])
            parsed_sysmon = self._process_process_sysmon(sample, submission_params["safelist"])
            low_level_flows = _get_low_level_flows(process_map, parsed_sysmon, low_level_flows)
            output_connections = sample["Sandbox"]["network_connections"]
            for output_connection in output_connections:
                matched = False
                for low_level_flow in low_level_flows:
                    if (output_connection["destination_ip"] == low_level_flow["dest_ip"] and 
                        output_connection["destination_port"] == low_level_flow["dest_port"] and 
                        output_connection["transport_layer_protocol"] == low_level_flow["protocol"] and
                        (output_connection["source_ip"] == low_level_flow["src_ip"] and
                        output_connection["source_port"] == low_level_flow["src_port"] or output_connection["destination_port"] == 53)):
                        matched = True
                assert matched, f"{identifier} network connection doesn't match"

    @pytest.mark.dependency(name="http_calls", depends=["process_map", "process_sysmon", "dns_map"])
    @pytest.mark.usefixtures("submission_params")
    def test_process_http_calls(self, loaded_samples, submission_params):
        for sample in loaded_samples:
            identifier = sample["Sample_identifier"]
            api_report = sample.get("Report")
            network = api_report.get("network", {})
            dns = network.get("dns", [])
            http_level_flows = {
                "http": network.get("http", []),
                "https": network.get("https", []),
                "http_ex": network.get("http_ex", []),
                "https_ex": network.get("https_ex", []),
            }
            dns_servers = _determine_dns_servers(network, submission_params["inetsim_dns_servers"])
            process_map = self._process_get_process_map(sample, submission_params["safelist"])
            parsed_sysmon = self._process_process_sysmon(sample, submission_params["safelist"])
            dns_requests = self._process_get_dns_map(dns, process_map, parsed_sysmon, submission_params["routing"], dns_servers)
            http_calls = _process_http_calls(http_level_flows, process_map, parsed_sysmon, dns_servers, dns_requests, submission_params["safelist"], submission_params["uses_https_proxy_in_sandbox"], submission_params["suspicious_accepted_languages"])
            output_connections = sample["Sandbox"]["network_connections"]
            for output_connection in output_connections:
                if output_connection["connection_type"] == "http":
                    matched = False
                    for http_call in http_calls:
                        if output_connection["http_details"]["request_uri"] == http_call["uri"] and output_connection["http_details"]["request_method"] == http_call["method"] and output_connection["http_details"]["request_headers"] == http_call["request_headers"]:
                            matched = True
                    assert matched, f"{identifier} http records doesn't match"

    @pytest.mark.dependency(name= "network_map", depends=["process_map", "process_sysmon", "dns_map", "low_level_flows", "http_calls"])
    @pytest.mark.usefixtures("submission_params")
    def test_get_network_map(self, loaded_samples, submission_params):
        for sample in loaded_samples:
            identifier = sample["Sample_identifier"]
            api_report = sample.get("Report")
            network = api_report.get("network", {})
            validated_random_ip_range = ip_network(submission_params["random_ip_range"])
            process_map = self._process_get_process_map(sample, submission_params["safelist"])
            parsed_sysmon = self._process_process_sysmon(sample, submission_params["safelist"])
            dns_servers, dns_requests, low_level_flows, http_calls = self._process_get_network_map(
                network,
                validated_random_ip_range,
                submission_params["routing"],
                process_map,
                submission_params["safelist"],
                submission_params["inetsim_dns_servers"],
                submission_params["uses_https_proxy_in_sandbox"],
                submission_params["suspicious_accepted_languages"],
                parsed_sysmon
            )
            output_connections = sample["Sandbox"]["network_connections"]
            for output_connection in output_connections:
                if output_connection["connection_type"] == "dns":
                    matched = False
                    for dns_request in dns_requests.keys():
                        if output_connection["dns_details"]["domain"] == dns_request:
                            matched = True
                    assert matched, f"{identifier} dns records doesn't match"
                elif output_connection["connection_type"] == "http":
                    matched = False
                    for http_call in http_calls:
                        if output_connection["http_details"]["request_uri"] == http_call["uri"] and output_connection["http_details"]["request_method"] == http_call["method"] and output_connection["http_details"]["request_headers"] == http_call["request_headers"]:
                            matched = True
                    assert matched, f"{identifier} http records doesn't match"
                else:
                    matched = False
                    for low_level_flow in low_level_flows:
                        if (output_connection["destination_ip"] == low_level_flow["dest_ip"] and 
                            output_connection["destination_port"] == low_level_flow["dest_port"] and 
                            output_connection["transport_layer_protocol"] == low_level_flow["protocol"] and
                            output_connection["source_ip"] == low_level_flow["src_ip"] and
                            output_connection["source_port"] == low_level_flow["src_port"]):
                                matched = True
                    assert matched, f"{identifier} network connection doesn't match"

    @pytest.mark.dependency(depends=["process_map"])
    @pytest.mark.usefixtures("submission_params")
    def test_process_curtain(self, loaded_samples, submission_params):
        for sample in loaded_samples:
            result = Result()
            al_result = ResultSection("Parent")
            result.add_section(al_result)
            identifier = sample["Sample_identifier"]
            api_report = sample.get("Report")
            curtain = api_report.get("curtain", {})
            process_map = self._process_get_process_map(sample, submission_params["safelist"])
            if curtain:
                process_curtain(curtain, al_result, process_map)
            section = [section for section in sample["Result"]["result"]["sections"] if section["title_text"] == "PowerShell Activity"]
            curtain_section = section[0] if len(section) > 0 else None
            if len(al_result.subsections) > 0 or curtain_section is not None:
                assert check_section_equality(al_result.subsections[0], curtain_section), f"{identifier} curtain section is different"

    @pytest.mark.dependency(depends=["process_map"])
    @pytest.mark.usefixtures("submission_params")
    def test_process_hollowshunter(self, loaded_samples, submission_params):
        for sample in loaded_samples:
            result = Result()
            al_result = ResultSection("Parent")
            result.add_section(al_result)
            identifier = sample["Sample_identifier"]
            api_report = sample.get("Report")
            hollowshunter = api_report.get("hollowshunter", {})
            process_map = self._process_get_process_map(sample, submission_params["safelist"])
            process_hollowshunter(hollowshunter, al_result, process_map)
            section = [section for section in sample["Result"]["result"]["sections"] if section["title_text"] == "HollowsHunter Analysis"]
            hollows_section = section[0] if len(section) > 0 else None
            if len(al_result.subsections) > 0 or hollows_section is not None:
                assert check_section_equality(al_result.subsections[0], hollows_section)

    @pytest.mark.dependency(depends=["process_map"])
    @pytest.mark.usefixtures("submission_params")
    def test_process_buffers(self, loaded_samples, submission_params):
        for sample in loaded_samples:
            result = Result()
            al_result = ResultSection("Parent")
            result.add_section(al_result)
            identifier = sample["Sample_identifier"]
            process_map = self._process_get_process_map(sample, submission_params["safelist"])
            process_buffers(process_map, submission_params["safelist"], al_result)
            section = [section for section in sample["Result"]["result"]["sections"] if section["title_text"] == "Buffers"]
            buffers_section = section[0] if len(section) > 0 else None
            if len(al_result.subsections) > 0 or buffers_section is not None:
                assert check_section_equality(al_result.subsections[0], buffers_section)

    def test_process_cape(self, loaded_samples):
        for sample in loaded_samples:
            result = Result()
            al_result = ResultSection("Parent")
            result.add_section(al_result)
            identifier = sample["Sample_identifier"]
            api_report = sample.get("Report")
            cape = api_report.get("CAPE", {})
            _ = process_cape(cape, al_result)
            section = [section for section in sample["Result"]["result"]["sections"] if section["title_text"] == "Configs Extracted By CAPE"]
            cape_section = section[0] if len(section) > 0 else None 
            if len(al_result.subsections) > 0 or cape_section is not None:
                assert check_section_equality(al_result.subsections[0], cape_section)

    def test_process_behavior(self, loaded_samples):
        for sample in loaded_samples:
            identifier = sample["Sample_identifier"]
            api_report = sample.get("Report")
            behaviour = api_report.get("behavior", {})
            main_process_tuples = process_behavior(behaviour)
            output_processes = sample["Sandbox"]["processes"]
            for pid,_ in main_process_tuples:
                matched = False
                for process in output_processes:
                    if (process["pid"] == pid):
                        matched = True
                assert matched, f"{identifier} doesn't match process behaviour"

    @pytest.mark.dependency(name="load_ontology_and_result_section", depends=["network_map","signatures"])
    @pytest.mark.usefixtures("submission_params")
    def test_load_ontology_and_result_section(self, loaded_samples, submission_params):
        for sample in loaded_samples:
            al_result, ontres = self._process_process_info(sample)
            identifier = sample["Sample_identifier"]
            api_report = sample.get("Report")
            network = api_report.get("network", {})
            sigs = api_report.get("signatures", [])
            process_map = self._process_get_process_map(sample, submission_params["safelist"])
            parsed_sysmon = self._process_process_sysmon(sample, submission_params["safelist"])
            validated_random_ip_range = ip_network(submission_params["random_ip_range"])
            dns_servers, dns_requests, low_level_flow, http_calls = self._process_get_network_map(
                network,
                validated_random_ip_range,
                submission_params["routing"],
                process_map,
                submission_params["safelist"],
                submission_params["inetsim_dns_servers"],
                submission_params["uses_https_proxy_in_sandbox"],
                submission_params["suspicious_accepted_languages"],
                parsed_sysmon
            )
            signatures = self._process_process_signatures(sigs)
            process_events = load_ontology_and_result_section(
                ontres,
                al_result,
                process_map,
                parsed_sysmon,
                dns_servers,
                validated_random_ip_range,
                dns_requests,
                low_level_flow,
                http_calls,
                submission_params["uses_https_proxy_in_sandbox"],
                signatures,
                submission_params["safelist"],
                submission_params["custom_tree_id_safelist"],
                submission_params["routing"],
                submission_params["inetsim_dns_servers"],
            )
            sandbox_section = sample["Sandbox"]
            assert same_dictionaries(process_events, sandbox_section), f"{identifier} sandbox section is different"

    @pytest.mark.dependency(depends=["load_ontology_and_result_section"])
    @pytest.mark.usefixtures("submission_params", "machine_info")
    def test_generate_al_result(self, loaded_samples, submission_params, machine_info):
        for sample in loaded_samples:
            result = Result()
            al_result = ResultSection("Parent")
            result.add_section(al_result)
            ontres = OntologyResults(service_name='CAPE')
            identifier = sample["Sample_identifier"]
            api_report = sample.get("Report")
            _,_,_ = generate_al_result(
                api_report,
                al_result,
                submission_params["file_ext"],
                submission_params["random_ip_range"],
                submission_params["routing"],
                submission_params["safelist"],
                machine_info,
                ontres,
                submission_params["custom_tree_id_safelist"],
                submission_params["inetsim_dns_servers"],
                submission_params["uses_https_proxy_in_sandbox"],
                submission_params["suspicious_accepted_languages"],
            )
            service = ServiceBase()
            ontres.preprocess_ontology(submission_params["custom_tree_id_safelist"])
            attach_dynamic_ontology(service, ontres)
            #Need to process it the same way as the result generated
            output = dict(result=result.finalize())
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
            #They should be equal at this point
            for i in range(0, len(output["result"]["sections"])):
                section_name = output["result"]["sections"][i]["title_text"]
                assert same_dictionaries(output["result"]["sections"][i], sample["Result"]["result"]["sections"][i]), f"{identifier} section {section_name} is different"
            assert same_dictionaries(output, sample["Result"]), f"{identifier} Result section is different" 
            #Need to remove the session and guid from the ontology as they are unique random IDs
            result_ontology = ontres.as_primitives()
            for section in result_ontology.keys():
                for element in result_ontology[section]:
                    if "objectid" in element.keys() and element.get("objectid", None):
                        element["objectid"].pop("session")
                        if "guid" in element["objectid"].keys() and element["objectid"].get("guid", None):
                            element["objectid"].pop("guid")
                    if "attributes" in element.keys() and element.get("attributes", None):
                        element["attributes"][0]["source"].pop("session")
                        element["attributes"][0]["source"].pop("guid")
                    if "pobjectid" in element.keys() and element.get("pobjectid", None):
                        element["pobjectid"].pop("session")
                        if "guid" in element["pobjectid"].keys() and element["pobjectid"].get("guid", None):
                            element["pobjectid"].pop("guid")
            expected_ontology = sample["Ontology"]
            for section in expected_ontology.keys():
                for element in expected_ontology[section]:
                    if "objectid" in element.keys() and element.get("objectid", None):
                        element["objectid"].pop("session")
                        if "guid" in element["objectid"].keys() and element["objectid"].get("guid", None):
                            element["objectid"].pop("guid")
                    if "attributes" in element.keys() and element.get("attributes", None):
                        element["attributes"][0]["source"].pop("session")
                        element["attributes"][0]["source"].pop("guid")
                    if "pobjectid" in element.keys() and element.get("pobjectid", None):
                        element["pobjectid"].pop("session")
                        if "guid" in element["pobjectid"].keys() and element["pobjectid"].get("guid", None):
                            element["pobjectid"].pop("guid")
            assert same_dictionaries(result_ontology, expected_ontology), f"{identifier} ontology is different"

# Utility function which don't need full context or reports and thus will be not added to dependency to other tests
    @staticmethod
    @pytest.mark.parametrize(
        "buffer, expected_output",
        [
            ("", ""),
            ("blah", ""),
            ("blahblah", "blahblah"),
            ("\\x12blahblah", "blahblah"),
            ("\\x12\\x23\\x34\\x45\\x56blahblah\\x67\\x78", "blahblah"),
            ("\\x12a\\x23b\\x34c\\x45de\\x56blahblah\\x67\\x78", "blahblah"),
            ("\\x12a\\x23b\\x34c\\x45de\\x56blahblah\\x67\\x78http/1.1", "blahblah"),
        ],
    )
    def test_remove_bytes_from_buffer(buffer, expected_output):
        assert _remove_bytes_from_buffer(buffer) == expected_output

    @staticmethod
    @pytest.mark.parametrize(
        "sigs, correct_sigs",
        [
            ([], []),
            ([{"name": "network_cnc_http"}], [{"name": "network_cnc_http"}]),
            ([{"name": "network_cnc_http"}, {"name": "network_http"}], [{"name": "network_cnc_http"}]),
        ],
    )
    def test_remove_network_http_noise(sigs, correct_sigs):
        assert _remove_network_http_noise(sigs) == correct_sigs

    @staticmethod
    @pytest.mark.parametrize(
        "network, inetsim_dns_servers, expected_result",
        [
            # Nothing
            ({}, [], []),
            # UDP with no 53 entries
            ({"udp": [{"dst": "127.0.0.1", "dport": 35}]}, [], []),
            # UDP with no 53 entries and INetSim DNS server configured
            ({"udp": [{"dst": "127.0.0.1", "dport": 35}]}, ["10.10.10.10"], ["10.10.10.10"]),
            # UDP with a 53 entry
            ({"udp": [{"dst": "127.0.0.1", "dport": 53}]}, [], ["127.0.0.1"]),
            # UDP with a 53 entry and different INetSim DNS server configured
            ({"udp": [{"dst": "127.0.0.1", "dport": 53}]}, ["10.10.10.10"], ["127.0.0.1", "10.10.10.10"]),
            # UDP with a 53 entry and same INetSim DNS server configured
            ({"udp": [{"dst": "127.0.0.1", "dport": 53}]}, ["127.0.0.1"], ["127.0.0.1"]),
        ],
    )
    def test_determine_dns_servers(network, inetsim_dns_servers, expected_result):
        assert _determine_dns_servers(network, inetsim_dns_servers) == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "dom, dest_ip, dns_servers, resolved_ips, expected_result",
        [
            # No domain, IP should not be removed
            ("", "1.1.1.1", [], {}, False),
            # Domain is not safelisted
            ("blah.com", "1.1.1.1", [], {}, False),
            # Domain is safelisted
            ("blah.ca", "1.1.1.1", [], {}, True),
            # No domain and IP is safelisted
            ("", "127.0.0.1", [], {}, True),
            # No domain and IP is not safelisted but is in the dns servers list
            ("", "8.8.8.8", ["8.8.8.8"], {}, True),
            # Domain is not safelisted but dest_ip is part of the resolved IPs and IP is in the INetSim network
            ("blah.com", "192.0.2.123", [], {"request": [{"answers": "192.0.2.123"}]}, False),
            # Domain is not safelisted but dest_ip is not part of the resolved IPs and IP is in the INetSim network
            ("blah.com", "192.0.2.123", [], {}, True),
        ],
    )
    def test_remove_network_call(dom, dest_ip, dns_servers, resolved_ips, expected_result):
        inetsim_network = IPv4Network("192.0.2.0/24")
        safelist = {
            "match": {"network.dynamic.domain": ["blah.ca"]},
            "regex": {"network.dynamic.ip": ["127\\.0\\.0\\..*"]},
        }
        assert (
            _remove_network_call(dom, dest_ip, dns_servers, resolved_ips, inetsim_network, safelist) == expected_result
        )

    @staticmethod
    def test_massage_host_data():
        assert _massage_host_data("blah.blah") == "blah.blah"
        assert _massage_host_data("blah.blah:80") == "blah.blah"

    @staticmethod
    @pytest.mark.parametrize(
        "host, dns_servers, resolved_ips, http_call, expected_uri, expected_http_call",
        [
            # normal host, no dns servers, no resolved_ips, normal http_call
            (
                "blah.com",
                [],
                {},
                {"uri": "/blah", "protocol": "http", "dst": "127.0.0.1"},
                "http://blah.com/blah",
                {"uri": "/blah", "protocol": "http", "dst": "127.0.0.1"},
            ),
            # host in path/uri, no dns servers, no resolved_ips, normal http_call
            (
                "blah.com",
                [],
                {},
                {"uri": "blah.com/blah", "protocol": "http", "dst": "127.0.0.1"},
                "http://blah.com/blah",
                {"uri": "blah.com/blah", "protocol": "http", "dst": "127.0.0.1"},
            ),
            # http_call[dst] is in dns_servers, but no resolved_ips, normal http_call
            (
                "blah.com",
                ["127.0.0.1"],
                {},
                {"uri": "blah.com/blah", "protocol": "http", "dst": "127.0.0.1"},
                "http://blah.com/blah",
                {"uri": "blah.com/blah", "protocol": "http", "dst": "127.0.0.1"},
            ),
            # http_call[dst] is in dns_servers, with resolved_ips, normal http_call
            (
                "blah.com",
                ["127.0.0.1"],
                {"blah.com": [{"answers": ["1.1.1.1"]}], "1": [{"answers": "blah"}]},
                {"uri": "blah.com/blah", "protocol": "http", "dst": "127.0.0.1"},
                "http://blah.com/blah",
                {"uri": "blah.com/blah", "protocol": "http", "dst": "1.1.1.1"},
            ),
        ],
    )
    def test_massage_http_ex_data(host, dns_servers, resolved_ips, http_call, expected_uri, expected_http_call):
        assert _massage_http_ex_data(host, dns_servers, resolved_ips, http_call) == (expected_uri, expected_http_call)
    
    @staticmethod
    @pytest.mark.parametrize(
        "protocol, host, dns_servers, resolved_ips, http_call, expected_request, expected_port, expected_uri, expected_http_call",
        [
            # non-ex protocol
            # normal host, no dns servers, no resolved_ips, normal http_call
            (
                "http",
                "blah.com",
                [],
                {},
                {"data": "GET blah.com", "uri": "http://blah.com/blah", "port": 123},
                "GET blah.com",
                123,
                "http://blah.com/blah",
                {"data": "GET blah.com", "uri": "http://blah.com/blah", "port": 123},
            ),
            # ex protocol
            # normal host, no dns servers, no resolved_ips, normal http_call
            (
                "http_ex",
                "blah.com",
                [],
                {},
                {"request": "GET blah.com", "dport": 123, "uri": "/blah", "protocol": "http", "dst": "127.0.0.1"},
                "GET blah.com",
                123,
                "http://blah.com/blah",
                {"request": "GET blah.com", "dport": 123, "uri": "/blah", "protocol": "http", "dst": "127.0.0.1"},
            ),
        ],
    )
    def test_get_important_fields_from_http_call(
        protocol,
        host,
        dns_servers,
        resolved_ips,
        http_call,
        expected_request,
        expected_port,
        expected_uri,
        expected_http_call,
    ):
        assert _get_important_fields_from_http_call(protocol, host, dns_servers, resolved_ips, http_call) == (
            expected_request,
            expected_port,
            expected_uri,
            expected_http_call,
        )

    @staticmethod
    @pytest.mark.parametrize(
        "host, safelist, uri, is_http_call_safelisted",
        [
            # Not safelisted
            ("blah.com", {}, "http://blah.com/blah", False),
            # Host is safelisted domain
            ("blah.com", {"match": {"network.dynamic.domain": ["blah.com"]}}, "http://blah.com/blah", True),
            # URI is safelisted URI
            ("blah.com", {"match": {"network.dynamic.uri": ["http://blah.com/blah"]}}, "http://blah.com/blah", True),
            # /wpad.dat is in URI
            ("blah.com", {}, "http://blah.com/wpad.dat", True),
            # URI is not a URI
            ("blah.com", {}, "yabadabadoo", True),
        ],
    )
    def test_is_http_call_safelisted(host, safelist, uri, is_http_call_safelisted):
        assert _is_http_call_safelisted(host, safelist, uri) == is_http_call_safelisted

    @staticmethod
    @pytest.mark.parametrize(
        "http_call, expected_request_body_path, expected_response_body_path",
        [
            # No body paths
            ({}, None, None),
            # Body paths with network/ (note that this always exists if a path exists)
            (
                {"req": {"path": "blah/network/blahblah"}, "resp": {"path": "blah/network/blahblah"}},
                "network/blahblah",
                "network/blahblah",
            ),
        ],
    )
    def test_massage_body_paths(http_call, expected_request_body_path, expected_response_body_path):
        assert _massage_body_paths(http_call) == (expected_request_body_path, expected_response_body_path)

    @staticmethod
    @pytest.mark.parametrize(
        "http_call, dns_servers, expected_destination_ip",
        [
            # http_call has no dst and NetworkDNS object does not exist in ontres, no dns_servers
            ({}, [], None),
            # http_call has dst and dst in dns_servers and NetworkDNS object does not exist in ontres
            ({"dst": "127.0.0.1"}, ["127.0.0.1"], None),
            # http_call has dst and dst not in dns_servers and NetworkDNS object does not exist in ontres
            ({"dst": "127.0.0.1"}, [], "127.0.0.1"),
        ],
    )
    def test_get_destination_ip(http_call, dns_servers, expected_destination_ip):
        ontres = OntologyResults(service_name="blah")
        dns = NetworkDNS("blah.ca", ["1.1.1.1"], None, "A")
        ontres.add_network_dns(dns)

        assert _get_destination_ip(http_call, dns_servers) == expected_destination_ip

    @staticmethod
    @pytest.mark.parametrize(
        "api_uri, pcap_uri, expected_result",
        [
            # These aren't real URIs
            ("", "", False),
            # Both uris start with different schemes but are not the same
            ("https://blah.com/blah", "http://blah.com", False),
            # Both uris start with different schemes and are the same
            ("https://blah.com", "http://blah.com", True),
            # Both uris start with different schemes and are the same with a trailing /
            ("https://blah.com/blah/", "http://blah.com/blah", True),
        ],
    )
    def test_uris_are_equal_despite_discrepancies(api_uri, pcap_uri, expected_result):
        assert _uris_are_equal_despite_discrepancies(api_uri, pcap_uri) == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "api_uri, pcap_uri, expected_result",
    [
        ("http://google.com", "https://google.com", True),
        ("http://google.com", "http://gooooogle.com", False),
        ("http://google.com/", "http://google.com", True),
        ("http://google.com", "https://google.com/", False),
        ("https://google.com/", "http://google.com", True),
    ]
    )
    def test_handle_similar_netloc_and_path(api_uri, pcap_uri, expected_result):
        assert _handle_similar_netloc_and_path(api_uri, pcap_uri) == expected_result, "Difference between handling of similar netloc and path"

    @staticmethod
    @pytest.mark.parametrize(
        "header_string, expected_header_dict",
        [
            ("", {}),
            (None, {}),
            ("GET /blah/blah/blah.doc HTTP/1.1", {}),
            ("GET /blah/blah/blah.doc HTTP/1.1\r\n", {}),
            ("GET /blah/blah/blah.doc HTTP/1.1\r\nblah", {}),
            (
                "GET /blah/blah/blah.doc HTTP/1.1\r\nConnection: Keep-Alive\r\nAccept: */*\r\nIf-Modified-Since: Sat, 01 Jul 2022"
                " 00:00:00 GMT\r\nUser-Agent: Microsoft-CryptoAPI/10.0\r\nHost: blah.blah.com",
                {
                    "Connection": "Keep-Alive",
                    "Accept": "*/*",
                    "IfModifiedSince": "Sat, 01 Jul 2022 00:00:00 GMT",
                    "UserAgent": "Microsoft-CryptoAPI/10.0",
                    "Host": "blah.blah.com",
                },
            ),
        ],
    )
    def test_handle_http_headers(header_string, expected_header_dict):
        assert _handle_http_headers(header_string) == expected_header_dict

    @staticmethod
    def test_is_mark_call():
        assert _is_mark_call(["blah"]) is False
        assert _is_mark_call(["type", "pid", "cid", "call"]) is True

    @staticmethod
    def test_api_ioc_in_network_traffic():
        ioc_list = ["blah.com", "127.0.0.1", "http://blah.com", "http://blah.org:443"]
        # Domain is present
        assert _api_ioc_in_network_traffic("blah.com", ioc_list) is True
        # Domain is not present
        assert _api_ioc_in_network_traffic("blah.ca", ioc_list) is False
        # URI is present
        assert _api_ioc_in_network_traffic("http://blah.com", ioc_list) is True
        # URI is present after requires massaging /
        assert _api_ioc_in_network_traffic("http://blah.com/", ioc_list) is True
        # URI is present after requires massaging, https+443
        assert _api_ioc_in_network_traffic("https://blah.org:443", ioc_list) is True

    @staticmethod
    def test_massage_api_urls():
        # Not a URL
        assert _massage_api_urls("blah") == "blah"
        # :80 spotted, but no scheme
        assert _massage_api_urls("blah.com:80/blah") == "blah.com:80/blah"
        # :80 spotted, and scheme
        assert _massage_api_urls("http://blah.com:80/blah") == "http://blah.com/blah"
        # :443 spotted, and wrong scheme
        assert _massage_api_urls("http://blah.com:443/blah") == "http://blah.com:443/blah"
        # :443 spotted, and scheme
        assert _massage_api_urls("https://blah.com:443/blah") == "https://blah.com/blah"

    @staticmethod
    @pytest.mark.parametrize(
        "dict1, dict2, expected_result",
    [
        ({}, {}, True),
        ({'a': 1}, {'a': 1}, True),
        ({'a': 1, 'b': 2}, {'b': 2, 'a': 1}, True),
        ({'a': {'aa': 1}}, {'a': {'aa': 1}}, True),
        ({'a': {'aa': 1}, 'b': 2}, {'b':2 ,'a': {'aa': 1}}, True),
        ({'a': 2}, {'ab': 2}, False),
        ({'a': [1,2,3]}, {'a': [1,2,3]}, True),
        ({'a': [1,2,3]}, {'a': [1,2,4]}, False),
        ({'a':1, 'b': 2}, {'a': 1}, False)
    ],
    )
    def test_same_dictionaries(dict1, dict2, expected_result):
        assert same_dictionaries(dict1, dict2) == expected_result, "Different dictionnaries found"

  # Secondary function which require context

    def test_create_signature_result_section(self):
        # Case 1: Bare minimum
        name = "blah"
        signature = {"data": []}
        translated_score = 0
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO", "TLP:C")
        ontres = OntologyResults(service_name="blah")
        process_map = {}
        safelist = {}
        uses_https_proxy_in_sandbox = False
        actual_res_sec, _ = _create_signature_result_section(
            name,
            signature,
            translated_score,
            ontres_sig,
            ontres,
            process_map,
            safelist,
            uses_https_proxy_in_sandbox,
        )

        assert actual_res_sec.title_text == "Signature: blah"
        assert actual_res_sec.body == '[["TEXT", "No description for signature.", {}]]'
        assert actual_res_sec.heuristic.heur_id == 9999
        assert ontres_sig.as_primitives() == {
            "actors": [],
            "attacks": [],
            "attributes": [],
            "malware_families": [],
            "name": "blah",
            'classification': 'TLP:C',
            "objectid": {
                "guid": None,
                "ontology_id": "blah",
                "processtree": None,
                "service_name": "blah",
                "session": None,
                "tag": "blah",
                "time_observed": None,
                "treeid": None,
            },
            "type": "CUCKOO",
        }

        # Case 2: More than 10 marks
        signature = {
            "data": [
                {"a": "b"},
                {"b": "b"},
                {"c": "b"},
                {"d": "b"},
                {"e": "b"},
                {"f": "b"},
                {"g": "b"},
                {"h": "b"},
                {"i": "b"},
                {"j": "b"},
                {"k": "b"},
                {"l": "b"},
            ]
        }
        actual_res_sec, _ = _create_signature_result_section(
            name,
            signature,
            translated_score,
            ontres_sig,
            ontres,
            process_map,
            safelist,
            uses_https_proxy_in_sandbox,
        )
        assert (
            actual_res_sec.body
            == '[["TEXT", "No description for signature.", {}], ["KEY_VALUE", {"a": "b"}, {}], ["KEY_VALUE", {"b": "b"}, {}], ["KEY_VALUE", {"c": "b"}, {}], ["KEY_VALUE", {"d": "b"}, {}], ["KEY_VALUE", {"e": "b"}, {}], ["KEY_VALUE", {"f": "b"}, {}], ["KEY_VALUE", {"g": "b"}, {}], ["KEY_VALUE", {"h": "b"}, {}], ["KEY_VALUE", {"i": "b"}, {}], ["KEY_VALUE", {"j": "b"}, {}], ["TEXT", "There were 2 more marks that were not displayed.", {}]]'
        )
        assert ontres_sig.as_primitives() == {
            "actors": [],
            "attacks": [],
            "attributes": [],
            "malware_families": [],
            "name": "blah",
            'classification': 'TLP:C',
            "objectid": {
                "guid": None,
                "ontology_id": "blah",
                "processtree": None,
                "service_name": "blah",
                "session": None,
                "tag": "blah",
                "time_observed": None,
                "treeid": None,
            },
            "type": "CUCKOO",
        }

        # Case 3: Attribute is added
        p = ontres.create_process(
            start_time="1970-01-01 00:00:02",
            pid=1,
            image="blah",
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"),
        )
        ontres.add_process(p)
        signature = {"data": [{"pid": 1, "type": "blah", "cid": "blah", "call": {}}]}
        actual_res_sec, _ = _create_signature_result_section(
            name,
            signature,
            translated_score,
            ontres_sig,
            ontres,
            process_map,
            safelist,
            uses_https_proxy_in_sandbox,
        )
        assert actual_res_sec.body == '[["TEXT", "No description for signature.", {}]]'
        attr_as_primitives = ontres_sig.attributes[0].as_primitives()
        attr_as_primitives["source"].pop("guid")
        assert attr_as_primitives == {
            "action": None,
            "domain": None,
            "event_record_id": None,
            "file_hash": None,
            "meta": None,
            "source": {
                "ontology_id": "blah",
                "processtree": None,
                "service_name": "CAPE",
                "session": None,
                "tag": "blah",
                "time_observed": "1970-01-01 00:00:02",
                "treeid": None,
            },
            "target": None,
            "uri": None,
        }
        #Case disabled because no filtering like that made atm
        # Case 4: False Positive Signature with False Positive mark
        #signature = {"data": [{"pid": 1, "type": "blah", "cid": "blah", "call": {}}, {"domain": "google.com"}]}
        #safelist = {"match": {"network.dynamic.domain": ["google.com"]}}
        #actual_res_sec, _ = _create_signature_result_section(
        #    name,
        #    signature,
        #    translated_score,
        #    ontres_sig,
        #    ontres,
        #    process_map,
        #    safelist,
        #    uses_https_proxy_in_sandbox,
        #)
        #assert actual_res_sec is None

        # Case 5: True Positive Signature with False Positive mark
        signature = {
            "data": [
                {"pid": 1, "type": "blah", "cid": "blah", "call": {}},
                {"domain": "google.com"},
                {"domain": "google.ru"},
            ]
        }
        safelist = {"match": {"network.dynamic.domain": ["google.com"]}}
        actual_res_sec, _ = _create_signature_result_section(
            name,
            signature,
            translated_score,
            ontres_sig,
            ontres,
            process_map,
            safelist,
            uses_https_proxy_in_sandbox,
        )
        assert (
            actual_res_sec.body
            == '[["TEXT", "No description for signature.", {}], ["KEY_VALUE", {"domain": "google.ru"}, {}]]'
        )

        # Case 6: Procmem_yara signature special case
        name = "procmem_yara"
        signature = {
            'name': 'procmem_yara',
            'description': 'Yara detections observed in process dumps, payloads or dropped files',
            'severity': 4,
            'weight': 1,
            'confidence': 100,
            'references': [],
            'data': [{'Hit': "PID  trigged the Yara rule 'embedded_win_api'"}, {'Hit': "PID 4876 trigged the Yara rule 'INDICATOR_EXE_Packed_GEN01'"}],
            'new_data': [],
            'alert': False,
            'families': []
        }
        translated_score = 500
        actual_res_sec, _ = _create_signature_result_section(
            name,
            signature,
            translated_score,
            ontres_sig,
            ontres,
            process_map,
            safelist,
            uses_https_proxy_in_sandbox,
        )
        assert actual_res_sec.heuristic.score == 500
        assert actual_res_sec.heuristic.name == "CAPE Yara Hit"

    def test_handle_mark_call(self):
        # Case 1: pid is None
        pid = None
        action = "blah"
        attributes = []
        ontres = OntologyResults(service_name="blah")
        _handle_mark_call(pid, action, attributes, ontres)
        assert attributes == []

        # Case 2: Source does not exist
        pid = 1
        _handle_mark_call(pid, action, attributes, ontres)
        assert attributes == []

        # Case 3: Source does exist and attributes is empty
        p = ontres.create_process(
            start_time="1970-01-01 00:00:02",
            pid=1,
            image="blah",
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"),
        )
        ontres.add_process(p)
        _handle_mark_call(pid, action, attributes, ontres)
        attribute_as_prim = attributes[0].as_primitives()
        attribute_as_prim["source"].pop("guid")
        assert attribute_as_prim == {
            "action": "blah",
            "domain": None,
            "event_record_id": None,
            "file_hash": None,
            "meta": None,
            "source": {
                "ontology_id": "blah",
                "processtree": None,
                "service_name": "CAPE",
                "session": None,
                "tag": "blah",
                "time_observed": "1970-01-01 00:00:02",
                "treeid": None,
            },
            "target": None,
            "uri": None,
        }

        # Case 4: action is None
        action = None
        _handle_mark_call(pid, action, attributes, ontres)
        attribute_as_prim = attributes[1].as_primitives()
        attribute_as_prim["source"].pop("guid")
        assert attribute_as_prim == {
            "action": None,
            "domain": None,
            "event_record_id": None,
            "file_hash": None,
            "meta": None,
            "source": {
                "ontology_id": "blah",
                "processtree": None,
                "service_name": "CAPE",
                "session": None,
                "tag": "blah",
                "time_observed": "1970-01-01 00:00:02",
                "treeid": None,
            },
            "target": None,
            "uri": None,
        }

    def test_handle_mark_data(self):
        # Case 1: Bare minimum
        mark_items = {}
        sig_res = ResultMultiSection("blah")
        sig_res.add_section_part(TextSectionBody(body="blah"))
        sig_res.add_section_part(KVSectionBody(body={"b": "a"}))
        mark_count = 0
        mark_body = KVSectionBody()
        attributes = []
        process_map = {}
        safelist = {}
        ontres = OntologyResults(service_name="blah")
        ioc_res = _handle_mark_data(
            mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres
        )
        assert mark_body.body is None
        assert ioc_res is None

        # Case 2: Basic mark items
        mark_items = [("a", "b")]
        ioc_res = _handle_mark_data(
            mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres
        )
        assert mark_body.body == '{"a": "b"}'
        assert ioc_res is None

        # Case 3: not v, k in MARK_KEYS_TO_NOT_DISPLAY, dumps({k: v}) in sig_res.section_body.body
        mark_items = [("a", None), ("data_being_encrypted", "blah"), ("b", "a")]
        ioc_res = _handle_mark_data(
            mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres
        )
        assert mark_body.body == '{"a": "b"}'
        assert ioc_res is None

        # Case 4: mark_count >= 10
        mark_count = 10
        ioc_res = _handle_mark_data(
            mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres
        )
        assert mark_body.body == '{"a": "b"}'
        assert ioc_res is None

        # Case 5: Add multiple mark items
        mark_count = 0
        mark_items = [("c", "d"), ("d", "e")]
        ioc_res = _handle_mark_data(
            mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres
        )
        assert mark_body.body == '{"a": "b", "c": "d", "d": "e"}'
        assert ioc_res is None

        # Case 6: Add mark item of type bytes
        mark_items = [("f", b"blah")]
        with pytest.raises(TypeError):
            _handle_mark_data(mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres)

        # Case 7: Mark item contains a safelisted value
        safelist = {"match": {"network.dynamic.domain": ["google.com"]}}
        mark_items = [("f", "google.com")]
        ioc_res = _handle_mark_data(
            mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres
        )
        assert mark_body.body == '{"a": "b", "c": "d", "d": "e"}'
        assert ioc_res is None

        # Case 8: Mark item value is a list
        mark_items = [("g", [0, 1, 2])]
        ioc_res = _handle_mark_data(
            mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres
        )
        assert mark_body.body == '{"a": "b", "c": "d", "d": "e", "g": [0, 1, 2]}'
        assert ioc_res is None

        # Case 8: Mark item value is not a string or a list
        mark_items = [("h", 999)]
        ioc_res = _handle_mark_data(
            mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres
        )
        assert mark_body.body == '{"a": "b", "c": "d", "d": "e", "g": [0, 1, 2], "h": 999}'
        assert ioc_res is None

        # Case 9: Add mark item (str) with long value
        mark_items = [("f", "blah" * 150)]
        ioc_res = _handle_mark_data(
            mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres
        )
        assert json.loads(mark_body.body)["f"] == "blah" * 128 + "..."
        assert ioc_res is None

    @staticmethod
    @pytest.mark.parametrize(
        "key, value, expected_tags, uses_https_proxy_in_sandbox",
        [
            #  Standard key for dynamic.process.file_name, nothing special with value
            ("cookie", "blah", {"dynamic.process.file_name": ["blah"]}, False),
            # Standard key for dynamic.process.file_name, process: in value
            ("setwindowshookexw", "process: blah", {"dynamic.process.file_name": ["blah"]}, False),
            # Standard key for dynamic.process.file_name, process: and delimiter in value
            ("setwindowshookexw", "process: blah -> blahblah", {"dynamic.process.file_name": ["blah"]}, False),
            # Standard key for dynamic.process.file_name, delimiter in value, special case
            ("file", "C:\\blah\\blah\\blah", {"dynamic.process.file_name": ["C:\\blah\\blah\\blah"]}, False),
            # Standard key for dynamic.process.file_name, delimiter in value, order of delimiters matters
            ("process", "regsrv32.exe, PID 123", {"dynamic.process.file_name": ["regsrv32.exe"]}, False),
            # Standard key for dynamic.process.command_line, nothing special with value
            ("command", "blah", {"dynamic.process.command_line": ["blah"]}, False),
            # Standard key for network.dynamic.ip, nothing special with value
            ("ip", "1.1.1.1", {"network.dynamic.ip": ["1.1.1.1"]}, False),
            # Standard key for network.dynamic.ip, : in value
            ("ip", "1.1.1.1:blah", {"network.dynamic.ip": ["1.1.1.1"], "network.port": ["blah"]}, False),
            # Standard key for network.dynamic.ip, : and ( in value
            ("ip", "1.1.1.1:blah (blahblah", {"network.dynamic.ip": ["1.1.1.1"], "network.port": ["blah"]}, False),
            # Standard key for dynamic.registry_key, nothing special with value
            ("regkey", "blah", {"dynamic.registry_key": ["blah"]}, False),
            # Standard key for network.dynamic.uri, nothing special with value
            (
                "url",
                "http://blah.com/blahblah",
                {
                    "network.dynamic.uri": ["http://blah.com/blahblah"],
                    "network.dynamic.domain": ["blah.com"],
                    "network.dynamic.uri_path": ["/blahblah"],
                },
                False,
            ),
            # Standard key for file.pe.exports.function_name, nothing special with value
            ("dynamicloader", "blah", {"file.pe.exports.function_name": ["blah"]}, False),
            # Key that ends in _exe for file.pe.exports.function_name, nothing special with value
            ("wscript_exe", "blah", {"dynamic.process.file_name": ["wscript.exe"]}, False),
            # Standard key for file.rule.cape, nothing special with value
            ("hit", "blah blah blah 'iwantthis'", {"file.rule.cape": ["CAPE.iwantthis"]}, False),
            # Standard key for file.rule.cape, value has PID in it
            ("hit", "PID 2392 trigged the Yara rule 'iwantthis'", {"file.rule.cape": ["CAPE.iwantthis"]}, False),
            # IOC found in data
            ("data", "Hey you I want to callout to http://blah.com", {}, False),
            # Standard key for network.dynamic.uri, test uses_https_proxy_in_sandbox
            (
                "url",
                "http://blah.com/blahblah:443",
                {
                    "network.dynamic.uri": ["https://blah.com/blahblah"],
                    "network.dynamic.domain": ["blah.com"],
                    "network.dynamic.uri_path": ["/blahblah"],
                },
                True,
            ),
        ],
    )
    def test_tag_mark_values(key, value, expected_tags, uses_https_proxy_in_sandbox):
        ontres = OntologyResults("CAPE")
        actual_res_sec = ResultSection("blah")
        iocs_res = _tag_mark_values(actual_res_sec, key, value, [], {}, ontres, None, uses_https_proxy_in_sandbox)
        assert actual_res_sec.tags == expected_tags
        if key == "data":
            correct_iocs_res = ResultTableSection("IOCs found in Signature data")
            correct_iocs_res.add_row(TableRow({"ioc_type": "domain", "ioc": "blah.com"}))
            correct_iocs_res.add_row(TableRow({"ioc_type": "uri", "ioc": "http://blah.com"}))
            correct_iocs_res.add_tag("network.static.domain", "blah.com")
            correct_iocs_res.add_tag("network.static.uri", "http://blah.com")
            assert check_section_equality(iocs_res, correct_iocs_res)

    def test_set_heuristic_signature(self):
        # Case 1: Unknown signature with 0 score
        name = "blah"
        signature = {"a": "b"}
        sig_res = ResultMultiSection("blah")
        translated_score = 0
        _set_heuristic_signature(name, signature, sig_res, translated_score)
        assert sig_res.heuristic.heur_id == 9999
        assert sig_res.heuristic.signatures == {name: 1}
        assert sig_res.heuristic.score == 0

        # Case 2: Known signature with 100 score
        name = "http_request"
        signature = {"http_request": "b"}
        sig_res = ResultMultiSection("blah")
        translated_score = 100
        _set_heuristic_signature(name, signature, sig_res, translated_score)
        assert sig_res.heuristic.heur_id == 41
        assert sig_res.heuristic.signatures == {name: 1}
        assert sig_res.heuristic.score == 100

        # Case 3: Known signature exception "procmem_yara"
        name = "procmem_yara"
        signature = {"procmem_yara": "anything"}
        sig_res = ResultMultiSection("blah")
        translated_score = 0
        _set_heuristic_signature(name, signature, sig_res, translated_score)
        assert sig_res.heuristic.heur_id == 55
        assert sig_res.heuristic.signatures == {name: 1}
        assert sig_res.heuristic.score == 0

    def test_set_attack_ids(self):
        # Case 1: No Attack IDs
        attack_ids = {}
        sig_res = ResultMultiSection("blah")
        sig_res.set_heuristic(1)
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO", "TLP:C")
        _set_attack_ids(attack_ids, sig_res, ontres_sig)
        assert sig_res.heuristic.attack_ids == []
        assert ontres_sig.attacks == []

        # Case 2: Multiple Attack IDs
        attack_ids = {"T1001": {"a": "b"}, "T1003": {"a": "b"}, "T1021": {"a": "b"}}
        _set_attack_ids(attack_ids, sig_res, ontres_sig)
        assert sig_res.heuristic.attack_ids == ["T1001", "T1003", "T1021"]
        assert [attack_id["attack_id"] for attack_id in ontres_sig.attacks] == ["T1001", "T1003", "T1021"]

        # Case 3: Attack ID in revoke_map
        attack_ids = {"G0042": {"a": "b"}}
        _set_attack_ids(attack_ids, sig_res, ontres_sig)
        assert sig_res.heuristic.attack_ids == ["T1001", "T1003", "T1021", "G0040"]
        assert [attack_id["attack_id"] for attack_id in ontres_sig.attacks] == ["T1001", "T1003", "T1021", "G0040"]

    def test_set_families(self):
        # Case 1: No families
        families = []
        sig_res = ResultMultiSection("blah")
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO", "TLP:C")
        _set_families(families, sig_res, ontres_sig)
        assert sig_res.body is None
        assert ontres_sig.malware_families == []

        # Case 2: Multiple families
        families = ["blah", "blahblah", "blahblahblah"]
        _set_families(families, sig_res, ontres_sig)
        assert sig_res.body == '[["TEXT", "\\tFamilies: blah,blahblah,blahblahblah", {}]]'
        assert ontres_sig.malware_families == ["blah", "blahblah", "blahblahblah"]

        # Case 3: Families in SKIPPED_FAMILIES
        families = ["generic", "wow"]
        sig_res = ResultMultiSection("blah")
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO", "TLP:C")
        _set_families(families, sig_res, ontres_sig)
        assert sig_res.body == '[["TEXT", "\\tFamilies: wow", {}]]'
        assert ontres_sig.malware_families == ["wow"]

    def test_get_dns_sec(self):
        # Nothing test
        resolved_ips = {}
        safelist = []
        assert _get_dns_sec(resolved_ips, safelist) is None

        # Standard test with no type
        resolved_ips = {"blah.com": [{"answers": {"answer": "1.1.1.1", "type": "None"}}]}
        expected_res_sec = ResultSection(
            "Protocol: DNS",
            body_format=BODY_FORMAT.TABLE,
            body=json.dumps([{"domain": "blah.com", "answer": "1.1.1.1", "type": None}]),
        )
        expected_res_sec.set_heuristic(1000)
        expected_res_sec.add_tag("network.protocol", "dns")
        expected_res_sec.add_tag("network.dynamic.ip", "1.1.1.1")
        expected_res_sec.add_tag("network.dynamic.domain", "blah.com")
        actual_res_sec = _get_dns_sec(resolved_ips, safelist)
        assert check_section_equality(actual_res_sec, expected_res_sec)

        # Standard test with type
        resolved_ips = {"blah.com": [{"answers": {"answer": "1.1.1.1", "type": "A"}, "type": "A"}]}
        expected_res_sec = ResultSection(
            "Protocol: DNS",
            body_format=BODY_FORMAT.TABLE,
            body=json.dumps([{"domain": "blah.com", "answer": "1.1.1.1", "type": "A"}]),
        )
        expected_res_sec.set_heuristic(1000)
        expected_res_sec.add_tag("network.protocol", "dns")
        expected_res_sec.add_tag("network.dynamic.ip", "1.1.1.1")
        expected_res_sec.add_tag("network.dynamic.domain", "blah.com")
        actual_res_sec = _get_dns_sec(resolved_ips, safelist)
        assert check_section_equality(actual_res_sec, expected_res_sec)

        # Non-standard DNS query
        resolved_ips = {"blah.com": [{"answers": {"answer": "1.1.1.1", "type": "TXT"}, "type": "TXT"}]}
        expected_res_sec = ResultSection(
            "Protocol: DNS",
            body_format=BODY_FORMAT.TABLE,
            body=json.dumps([{"domain": "blah.com", "answer": "1.1.1.1", "type": "TXT"}]),
        )
        expected_res_sec.set_heuristic(1000)
        expected_res_sec.add_tag("network.protocol", "dns")
        expected_res_sec.add_tag("network.dynamic.ip", "1.1.1.1")
        expected_res_sec.add_tag("network.dynamic.domain", "blah.com")
        expected_dns_query_res_sec = ResultSection(
            "Non-Standard DNS Query Used", body="CAPE detected a non-standard DNS query being used"
        )
        expected_dns_query_res_sec.set_heuristic(1009)
        expected_dns_query_res_sec.add_line(f"\t-\tTXT")
        expected_res_sec.add_subsection(expected_dns_query_res_sec)
        actual_res_sec = _get_dns_sec(resolved_ips, safelist)
        assert check_section_equality(actual_res_sec, expected_res_sec)

    @staticmethod
    @pytest.mark.parametrize(
        "network_flow, expected_netflow",
        [
            # No image, timestamp is not string
            (
                {
                    "src_ip": "127.0.0.1",
                    "src_port": 123,
                    "dest_ip": "1.1.1.1",
                    "dest_port": 321,
                    "protocol": "tcp",
                    "timestamp": 1,
                    "pid": None,
                },
                {
                    "connection_type": None,
                    "destination_ip": "1.1.1.1",
                    "destination_port": 321,
                    "direction": "outbound",
                    "dns_details": None,
                    "http_details": None,
                    "objectid": {
                        "ontology_id": "network_7hKNdOVlLWYVZUUVUNbDgs",
                        "processtree": None,
                        "service_name": "CAPE",
                        "session": "blah",
                        "tag": "1.1.1.1:321",
                        "time_observed": "1970-01-01 00:00:01.000",
                        "treeid": None,
                    },
                    "process": None,
                    "source_ip": "127.0.0.1",
                    "source_port": 123,
                    "transport_layer_protocol": "tcp",
                },
            ),
            # No image, timestamp is string
            (
                {
                    "src_ip": "127.0.0.1",
                    "src_port": 123,
                    "dest_ip": "1.1.1.1",
                    "dest_port": 321,
                    "protocol": "tcp",
                    "timestamp": "1970-01-01 00:00:01.000",
                    "pid": None,
                },
                {
                    "connection_type": None,
                    "destination_ip": "1.1.1.1",
                    "destination_port": 321,
                    "direction": "outbound",
                    "dns_details": None,
                    "http_details": None,
                    "objectid": {
                        "ontology_id": "network_7hKNdOVlLWYVZUUVUNbDgs",
                        "processtree": None,
                        "service_name": "CAPE",
                        "session": "blah",
                        "tag": "1.1.1.1:321",
                        "time_observed": "1970-01-01 00:00:01.000",
                        "treeid": None,
                    },
                    "process": None,
                    "source_ip": "127.0.0.1",
                    "source_port": 123,
                    "transport_layer_protocol": "tcp",
                },
            ),
            # Image
            (
                {
                    "src_ip": "127.0.0.1",
                    "src_port": 123,
                    "dest_ip": "1.1.1.1",
                    "dest_port": 321,
                    "protocol": "tcp",
                    "timestamp": "1970-01-01 00:00:01.000",
                    "pid": 123,
                    "image": "blah.exe",
                },
                {
                    "connection_type": None,
                    "destination_ip": "1.1.1.1",
                    "destination_port": 321,
                    "direction": "outbound",
                    "dns_details": None,
                    "http_details": None,
                    "objectid": {
                        "ontology_id": "network_7hKNdOVlLWYVZUUVUNbDgs",
                        "processtree": None,
                        "service_name": "CAPE",
                        "session": "blah",
                        "tag": "1.1.1.1:321",
                        "time_observed": "1970-01-01 00:00:01.000",
                        "treeid": None,
                    },
                    "process": None,
                    "source_ip": "127.0.0.1",
                    "source_port": 123,
                    "transport_layer_protocol": "tcp",
                },
            ),
        ],
    )
    def test_create_network_connection_for_network_flow(network_flow, expected_netflow):
        session = "blah"
        ontres = OntologyResults(service_name="CAPE")
        p = Process(
            objectid=OntologyResults.create_objectid(tag="blah.exe", ontology_id="blah", service_name="CAPE"),
            image="blah.exe",
            start_time="1970-01-01 00:00:01",
            end_time="1970-01-01 00:00:10",
            pid=123,
        )
        ontres.add_process(p)

        _create_network_connection_for_network_flow(network_flow, session, ontres)
        prims = ontres.netflows[0].as_primitives()
        prims["objectid"].pop("guid")
        assert prims == expected_netflow

    @staticmethod
    @pytest.mark.parametrize(
        "uri, http_call, request_headers, response_headers, request_body_path, response_body_path, port, destination_ip, expected_nc, expected_nh",
        [
            # NetworkConnection does not exist
            (
                "http://blah.com/blah",
                {"method": "GET"},
                {},
                {},
                None,
                None,
                123,
                "127.0.0.1",
                {
                    "connection_type": "http",
                    "destination_ip": "127.0.0.1",
                    "destination_port": 123,
                    "direction": "outbound",
                    "dns_details": None,
                    "http_details": {
                        "request_body": None,
                        "request_headers": {},
                        "request_method": "GET",
                        "request_uri": "http://blah.com/blah",
                        "response_body": None,
                        "response_headers": {},
                        "response_status_code": None,
                    },
                    "objectid": {
                        "guid": None,
                        "ontology_id": "network_http_2aYE9AQoYvRmYHrorTmETw",
                        "processtree": None,
                        "service_name": "blah",
                        "session": None,
                        "tag": "127.0.0.1:123",
                        "time_observed": None,
                        "treeid": None,
                    },
                    "process": None,
                    "source_ip": None,
                    "source_port": None,
                    "transport_layer_protocol": "tcp",
                },
                {
                    "request_body": None,
                    "request_headers": {},
                    "request_method": "GET",
                    "request_uri": "http://blah.com/blah",
                    "response_body": None,
                    "response_headers": {},
                    "response_status_code": None,
                },
            ),
            # NetworkConnection does exist
            (
                "http://blah.com/blah",
                {"method": "GET"},
                {},
                {},
                "blah",
                "blah",
                123,
                "1.1.1.1",
                {
                    "connection_type": "http",
                    "destination_ip": "1.1.1.1",
                    "destination_port": 123,
                    "direction": "outbound",
                    "dns_details": None,
                    "http_details": {
                        "request_body": None,
                        "request_headers": {},
                        "request_method": "GET",
                        "request_uri": "http://blah.com/blah",
                        "response_body": None,
                        "response_headers": {},
                        "response_status_code": None,
                    },
                    "objectid": {
                        "guid": None,
                        "ontology_id": "blah",
                        "processtree": None,
                        "service_name": "CAPE",
                        "session": None,
                        "tag": "blah",
                        "time_observed": None,
                        "treeid": None,
                    },
                    "process": None,
                    "source_ip": None,
                    "source_port": None,
                    "transport_layer_protocol": "tcp",
                },
                {
                    "request_body": None,
                    "request_headers": {},
                    "request_method": "GET",
                    "request_uri": "http://blah.com/blah",
                    "response_body": None,
                    "response_headers": {},
                    "response_status_code": None,
                },
            ),
        ],
    )
    def test_setup_network_connection_with_network_http(
        uri,
        http_call,
        request_headers,
        response_headers,
        request_body_path,
        response_body_path,
        port,
        destination_ip,
        expected_nc,
        expected_nh,
    ):
        ontres = OntologyResults(service_name="blah")

        sandbox = ontres.create_sandbox(
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"),
            sandbox_name="CAPE",
        )
        ontres.add_sandbox(sandbox)

        nc = NetworkConnection(
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"),
            destination_ip="1.1.1.1",
            destination_port=123,
            transport_layer_protocol="tcp",
            direction="outbound",
        )
        ontres.add_network_connection(nc)

        actual_nc, actual_nh = _setup_network_connection_with_network_http(
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

        assert actual_nc.as_primitives() == expected_nc
        assert actual_nh.as_primitives() == expected_nh

    @staticmethod
    @pytest.mark.parametrize(
        "uri, http_call, request_headers, response_headers, request_body_path, response_body_path, expected_nh",
        [
            # No body paths
            (
                "http://blah.com/blah",
                {"method": "GET"},
                {},
                {},
                None,
                None,
                {
                    "request_body": None,
                    "request_headers": {},
                    "request_method": "GET",
                    "request_uri": "http://blah.com/blah",
                    "response_body": None,
                    "response_headers": {},
                    "response_status_code": None,
                },
            ),
            # Body paths
            (
                "http://blah.com/blah",
                {"method": "GET"},
                {},
                {},
                "blah",
                "blah",
                {
                    "request_body": None,
                    "request_headers": {},
                    "request_method": "GET",
                    "request_uri": "http://blah.com/blah",
                    "response_body": None,
                    "response_headers": {},
                    "response_status_code": None,
                },
            ),
        ],
    )
    def test_create_network_http(
        uri, http_call, request_headers, response_headers, request_body_path, response_body_path, expected_nh
    ):
        ontres = OntologyResults(service_name="blah")
        assert (
            _create_network_http(
                uri, http_call, request_headers, response_headers, request_body_path, response_body_path, ontres
            ).as_primitives()
            == expected_nh
        )

    @staticmethod
    @pytest.mark.parametrize(
        "destination_ip, destination_port, expected_nc",
        [
            # No network connection with details
            ("127.0.0.1", 123, None),
            # Network connection with details
            (
                "1.1.1.1",
                123,
                {
                    "connection_type": None,
                    "destination_ip": "1.1.1.1",
                    "destination_port": 123,
                    "direction": "outbound",
                    "dns_details": None,
                    "http_details": None,
                    "objectid": {
                        "guid": None,
                        "ontology_id": "blah",
                        "processtree": None,
                        "service_name": "CAPE",
                        "session": None,
                        "tag": "blah",
                        "time_observed": None,
                        "treeid": None,
                    },
                    "process": None,
                    "source_ip": None,
                    "source_port": None,
                    "transport_layer_protocol": "tcp",
                },
            ),
        ],
    )
    def test_get_network_connection_by_details(destination_ip, destination_port, expected_nc):
        ontres = OntologyResults(service_name="blah")
        nc = NetworkConnection(
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"),
            destination_ip="1.1.1.1",
            destination_port=123,
            transport_layer_protocol="tcp",
            direction="outbound",
        )
        ontres.add_network_connection(nc)

        if destination_ip == "127.0.0.1":
            assert _get_network_connection_by_details(destination_ip, destination_port, ontres) == expected_nc
        elif destination_ip == "1.1.1.1":
            assert (
                _get_network_connection_by_details(destination_ip, destination_port, ontres).as_primitives()
                == expected_nc
            )

    @staticmethod
    @pytest.mark.parametrize(
        "http_call, destination_ip, destination_port, expected_nc",
        [
            # The bare minimum
            (
                {},
                "127.0.0.1",
                123,
                {
                    "connection_type": "http",
                    "destination_ip": "127.0.0.1",
                    "destination_port": 123,
                    "direction": "outbound",
                    "dns_details": None,
                    "http_details": {
                        "request_body": None,
                        "request_headers": {},
                        "request_method": "GET",
                        "request_uri": "http://blah.com/blah",
                        "response_body": None,
                        "response_headers": {},
                        "response_status_code": None,
                    },
                    "objectid": {
                        "guid": None,
                        "ontology_id": "network_http_2aYE9AQoYvRmYHrorTmETw",
                        "processtree": None,
                        "service_name": "blah",
                        "session": None,
                        "tag": "127.0.0.1:123",
                        "time_observed": None,
                        "treeid": None,
                    },
                    "process": None,
                    "source_ip": None,
                    "source_port": None,
                    "transport_layer_protocol": "tcp",
                },
            ),
            # The bare minimum with source_ip and source_port
            (
                {"src": "1.1.1.1", "sport": 321},
                "127.0.0.1",
                123,
                {
                    "connection_type": "http",
                    "destination_ip": "127.0.0.1",
                    "destination_port": 123,
                    "direction": "outbound",
                    "dns_details": None,
                    "http_details": {
                        "request_body": None,
                        "request_headers": {},
                        "request_method": "GET",
                        "request_uri": "http://blah.com/blah",
                        "response_body": None,
                        "response_headers": {},
                        "response_status_code": None,
                    },
                    "objectid": {
                        "guid": None,
                        "ontology_id": "network_http_5JKYqWSPzDSn2OnZra0Z7D",
                        "processtree": None,
                        "service_name": "blah",
                        "session": None,
                        "tag": "127.0.0.1:123",
                        "time_observed": None,
                        "treeid": None,
                    },
                    "process": None,
                    "source_ip": "1.1.1.1",
                    "source_port": 321,
                    "transport_layer_protocol": "tcp",
                },
            ),
        ],
    )
    def test_create_network_connection_for_http_call(http_call, destination_ip, destination_port, expected_nc):
        ontres = OntologyResults(service_name="blah")
        sandbox = ontres.create_sandbox(
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"),
            sandbox_name="CAPE",
        )
        ontres.add_sandbox(sandbox)
        nh = NetworkHTTP("http://blah.com/blah", "GET")
        assert (
            _create_network_connection_for_http_call(
                http_call, destination_ip, destination_port, nh, ontres
            ).as_primitives()
            == expected_nc
        )

    def test_process_non_http_traffic_over_http(self):
        test_parent_section = ResultSection("blah")
        network_flows = [
            {"dest_port": 80, "dest_ip": "127.0.0.1", "domain": "blah.com"},
            {"dest_port": 443, "dest_ip": "127.0.0.2", "domain": "blah2.com"},
        ]
        correct_result_section = ResultSection("Non-HTTP Traffic Over HTTP Ports")
        correct_result_section.set_heuristic(1005)
        correct_result_section.add_tag("network.dynamic.ip", "127.0.0.1")
        correct_result_section.add_tag("network.dynamic.ip", "127.0.0.2")
        correct_result_section.add_tag("network.dynamic.domain", "blah.com")
        correct_result_section.add_tag("network.dynamic.domain", "blah2.com")
        correct_result_section.add_tag("network.port", 80)
        correct_result_section.add_tag("network.port", 443)
        correct_result_section.set_body(json.dumps(network_flows), BODY_FORMAT.TABLE)
        _process_non_http_traffic_over_http(test_parent_section, network_flows)
        assert check_section_equality(test_parent_section.subsections[0], correct_result_section)

    def test_process_unseen_iocs(self):
        default_so = OntologyResults(service_name="CAPE")
        nh = default_so.create_network_http(request_uri="http://blah.ca/blah", request_method="get")
        default_so.add_network_http(nh)
        nh2 = default_so.create_network_http(request_uri="https://blah.ca/blah", request_method="get")
        default_so.add_network_http(nh2)
        nd = default_so.create_network_dns(domain="blah.ca", resolved_ips=["1.1.1.1"], lookup_type="A")
        default_so.add_network_dns(nd)

        # Do nothing
        parent_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah")
        _process_unseen_iocs(parent_result_section, {}, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)

        # Unseen URI
        parent_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah")
        unseen_res = ResultTableSection(
            "Unseen IOCs found in API calls",
            tags={
                "network.dynamic.domain": ["blah.com"],
                "network.dynamic.uri": ["http://blah.com/blah"],
                "network.dynamic.uri_path": ["/blah"],
            },
        )
        unseen_res.add_row(TableRow({"ioc_type": "domain", "ioc": "blah.com"}))
        unseen_res.add_row(TableRow({"ioc_type": "uri", "ioc": "http://blah.com/blah"}))
        unseen_res.set_heuristic(1013)
        correct_result_section.add_subsection(unseen_res)
        process_map = {123: {"network_calls": [{"arguments": {"URL": "http://blah.com/blah"}}]}}
        _process_unseen_iocs(parent_result_section, process_map, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)

        # Seen URI
        parent_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah")
        process_map = {123: {"network_calls": [{"arguments": {"URL": "http://blah.ca/blah"}}]}}
        _process_unseen_iocs(parent_result_section, process_map, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)

        # Seen URI after massaging
        parent_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah")
        process_map = {
            123: {
                "network_calls": [{"arguments": {"URL": "http://blah.ca/blah:80", "HOSTNAME": "https://blah.ca/blah:443"}}]
            }
        }
        _process_unseen_iocs(parent_result_section, process_map, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)

        # Seen URI in blob
        parent_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah")
        process_map = {
            123: {
                "network_calls": [
                    {
                        "arguments": {
                            "URL": "blahblahblah http://blah.ca/blah blahblahblah",
                            "HOSTNAME": "blahblahblah https://blah.ca/blah blahblahblah",
                        }
                    }
                ]
            }
        }
        _process_unseen_iocs(parent_result_section, process_map, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)

        # Seen URI in blob after massaging
        parent_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah")
        process_map = {
            123: {
                "network_calls": [
                    {
                        "arguments": {
                            "URL": "blahblahblah http://blah.ca/blah blahblahblah",
                            "HOSTNAME": "blahblahblah https://blah.ca/blah blahblahblah",
                        }
                    }
                ]
            }
        }
        _process_unseen_iocs(parent_result_section, process_map, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)

        # Unseen domain in blob but it is too short
        parent_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah")
        process_map = {
            123: {
                "network_calls": [
                    {
                        "arguments": {
                            "URL": "blahblahblah a.com blahblahblah",
                            "HOSTNAME": "blahblahblah b.org blahblahblah",
                        }
                    }
                ]
            }
        }
        _process_unseen_iocs(parent_result_section, process_map, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)
