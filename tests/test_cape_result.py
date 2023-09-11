import json
from ipaddress import IPv4Network, ip_network
from json import dumps, loads

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
)
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
)
from cape.cape_result import (
    ANALYSIS_ERRORS,
    _add_process_context,
    _api_ioc_in_network_traffic,
    _create_network_connection_for_http_call,
    _create_network_connection_for_network_flow,
    _create_network_http,
    _create_signature_result_section,
    _determine_dns_servers,
    _get_destination_ip,
    _get_dns_map,
    _get_dns_sec,
    _get_important_fields_from_http_call,
    _get_low_level_flows,
    _get_network_connection_by_details,
    _handle_http_headers,
    _handle_mark_call,
    _handle_mark_data,
    _is_http_call_safelisted,
    _is_mark_call,
    _is_network_flow_a_connect_match,
    _link_flow_with_process,
    _link_process_to_http_call,
    _massage_api_urls,
    _massage_body_paths,
    _massage_host_data,
    _massage_http_ex_data,
    _process_http_calls,
    _process_non_http_traffic_over_http,
    _process_unseen_iocs,
    _remove_bytes_from_buffer,
    _remove_network_call,
    _remove_network_http_noise,
    _set_attack_ids,
    _set_families,
    _set_heuristic_signature,
    _setup_network_connection_with_network_http,
    _tag_mark_values,
    _tag_network_flow,
    _update_process_map,
    _uris_are_equal_despite_discrepancies,
    build_process_tree,
    convert_cape_processes,
    generate_al_result,
    get_process_api_sums,
    get_process_map,
    process_all_events,
    process_behaviour,
    process_buffers,
    process_cape,
    process_curtain,
    process_debug,
    process_hollowshunter,
    process_info,
    process_network,
)
from test_cape_main import create_tmp_manifest, remove_tmp_manifest


class TestCapeResult:
    @classmethod
    def setup_class(cls):
        create_tmp_manifest()

    @classmethod
    def teardown_class(cls):
        remove_tmp_manifest()

    @staticmethod
    @pytest.mark.parametrize(
        "api_report",
        [
            ({}),
            (
                {
                    "info": {"id": "blah"},
                    "debug": "blah",
                    "signatures": [{"name": "blah"}],
                    "network": "blah",
                    "behavior": {"blah": "blah"},
                    "curtain": "blah",
                    "sysmon": {},
                    "hollowshunter": "blah",
                }
            ),
            (
                {
                    "info": {"id": "blah"},
                    "debug": "blah",
                    "signatures": [{"name": "ransomware"}],
                    "network": "blah",
                    "behavior": {"blah": "blah"},
                    "curtain": "blah",
                    "sysmon": {},
                    "hollowshunter": "blah",
                }
            ),
            ({"signatures": [{"name": "blah"}], "info": {"id": "blah"}, "behavior": {"summary": "blah", "blah": "blah"}}),
            ({"signatures": [{"name": "blah"}], "info": {"id": "blah"}, "behavior": {"processtree": "blah"}}),
            ({"signatures": [{"name": "blah"}], "info": {"id": "blah"}, "behavior": {"processes": "blah"}}),
            ({"signatures": [{"name": "blah"}], "info": {"id": "blah"}, "behavior": {"processes": "blah"}, "CAPE": {}}),
        ],
    )
    def test_generate_al_result(api_report, mocker):
        correct_process_map = {"blah": "blah"}
        mocker.patch("cape.cape_result.process_info")
        mocker.patch("cape.cape_result.process_machine_info")
        mocker.patch("cape.cape_result.process_debug")
        mocker.patch("cape.cape_result.get_process_map", return_value=correct_process_map)
        mocker.patch("cape.cape_result.process_signatures", return_value=False)
        mocker.patch("cape.cape_result.convert_sysmon_processes", return_value=None)
        mocker.patch("cape.cape_result.convert_sysmon_network", return_value=None)
        mocker.patch("cape.cape_result.process_behaviour", return_value=[])
        mocker.patch("cape.cape_result.process_network", return_value=["blah"])
        mocker.patch("cape.cape_result.process_all_events")
        mocker.patch("cape.cape_result.build_process_tree")
        mocker.patch("cape.cape_result.process_curtain")
        mocker.patch("cape.cape_result.process_hollowshunter")
        mocker.patch("cape.cape_result.process_buffers")
        mocker.patch("cape.cape_result.process_cape")
        so = OntologyResults()
        al_result = ResultSection("blah")
        file_ext = "blah"
        safelist = {}
        machine_info = {"blah": "blah"}
        custom_tree_id_safelist = list()
        inetsim_dns_servers = list()

        output = generate_al_result(
            api_report, al_result, file_ext, ip_network("192.0.2.0/24"), "blah", safelist, machine_info,
            so, custom_tree_id_safelist, inetsim_dns_servers, False
        )

        assert output == ({}, [])
        if api_report == {}:
            assert al_result.subsections == []
        elif api_report.get("behavior", {}).get("blah") == "blah":
            correct_result_section = ResultSection(
                title_text="Sample Did Not Execute",
                body=f"Either no program is available to execute a file with the extension: {file_ext} OR see the '{ANALYSIS_ERRORS}' section for details.",
            )
            assert check_section_equality(al_result.subsections[0], correct_result_section)
        else:
            assert al_result.subsections == []

    @staticmethod
    @pytest.mark.parametrize(
        "info, correct_body, expected_am",
        [
            (
                {"started": "1970-01-01 00:00:01", "ended": "1970-01-01 00:00:01", "duration": "blah", "id": 1, "route": "blah", "version": "blah"},
                '{"CAPE Task ID": 1, "Duration": -1, "Routing": "blah", "CAPE Version": "blah"}',
                {"routing": "blah", "start_time": "1970-01-01 00:00:01.000", "end_time": "1970-01-01 00:00:01.000", "task_id": 1},
            ),
            (
                {
                    "started": "1970-01-01 00:00:01",
                    "ended": "1970-01-01 00:00:01",
                    "duration": "1",
                    "id": 1,
                    "route": "blah",
                    "version": "blah",
                },
                '{"CAPE Task ID": 1, "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01.000 to 1970-01-01 00:00:01.000)", "Routing":'
                ' "blah", "CAPE Version": "blah"}',
                {"routing": "blah", "start_time": "1970-01-01 00:00:01.000", "end_time": "1970-01-01 00:00:01.000", "task_id": 1},
            ),
            (
                {
                    "id": 1,
                    "started": "1970-01-01 00:00:01",
                    "ended": "1970-01-01 00:00:01",
                    "duration": "1",
                    "route": "blah",
                    "version": "blah",
                },
                '{"CAPE Task ID": 1, "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01.000 to 1970-01-01 00:00:01.000)", "Routing":'
                ' "blah", "CAPE Version": "blah"}',
                {"routing": "blah", "start_time": "1970-01-01 00:00:01.000", "end_time": "1970-01-01 00:00:01.000", "task_id": 1},
            ),
        ],
    )
    def test_process_info(info, correct_body, expected_am):
        al_result = ResultSection("blah")
        so = OntologyResults(service_name="CAPE")
        # default_am = so.analysis_metadata.as_primitives()
        process_info(info, al_result, so)
        correct_res_sec = ResultSection("Analysis Information")
        correct_res_sec.set_body(correct_body, BODY_FORMAT.KEY_VALUE)
        assert check_section_equality(al_result.subsections[0], correct_res_sec)
        # for key, value in expected_am.items():
        #     default_am[key] = value
        expected_am["machine_metadata"] = None
        assert so.sandboxes[0].analysis_metadata.as_primitives() == expected_am
        assert so.sandboxes[0].sandbox_version == "blah"

    @staticmethod
    @pytest.mark.parametrize(
        "debug, correct_body",
        [
            ({"errors": [], "log": ""}, None),
            ({"errors": ["BLAH"], "log": ""}, "BLAH"),
            ({"errors": ["BLAH", "BLAH"], "log": ""}, "BLAH\nBLAH"),
            ({"errors": [], "log": "blah"}, None),
            ({"errors": [], "log": "blahblahblahblahblah"}, None),
            ({"errors": [], "log": "ERROR: blahblahblahblahblah"}, "Blahblahblahblahblah"),
            ({"errors": [], "log": "ERROR: blahblahblahblahblah\nERROR: blahblahblahblahblah\n"}, "Blahblahblahblahblah"),
        ],
    )
    def test_process_debug(debug, correct_body):
        al_result = ResultSection("blah")
        process_debug(debug, al_result)

        if correct_body is None:
            assert al_result.subsections == []
        else:
            correct_result_section = ResultSection(title_text="Analysis Errors")
            correct_result_section.set_body(correct_body)
            assert check_section_equality(al_result.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize("behaviour, expected", [
        ({"processes": []}, []),
        (
            {
                "processes": [
                    {"parent_id": 123, "process_id": 321, "process_name": "blah.exe"}
                ],
                "apistats": {
                    "blah": "blah"
                }
            },
        [(321, 'blah.exe')]),
        (
            {
                "processes": [
                    {"parent_id": 123, "process_id": 321, "process_name": "iexplore.exe"},
                    {"parent_id": 321, "process_id": 999, "process_name": "iexplore.exe"}
                ],
                "apistats": {
                    "blah": "blah"
                }
            },
        [(321, 'iexplore.exe'), (999, 'iexplore.exe')]),
    ])
    def test_process_behaviour(behaviour, expected, mocker):
        mocker.patch("cape.cape_result.get_process_api_sums", return_value={"blah": "blah"})
        mocker.patch("cape.cape_result.convert_cape_processes")
        safelist = {}
        so = OntologyResults()
        main_process_tuples = process_behaviour(behaviour, safelist, so)
        assert main_process_tuples == expected

    @staticmethod
    @pytest.mark.parametrize(
        "apistats, correct_api_sums",
        [
            ({}, {}),
            ({"0": {"blah": 2}}, {"0": 2}),
        ],
    )
    def test_get_process_api_sums(apistats, correct_api_sums):
        assert get_process_api_sums(apistats) == correct_api_sums

    @staticmethod
    @pytest.mark.parametrize(
        "processes, correct_event",
        [
            (
                [
                    {
                        "process_id": 0,
                        "module_path": "blah",
                        "environ": {"CommandLine": "blah"},
                        "parent_id": 1,
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "pguid": "{12345678-1234-5678-1234-567812345679}",
                        "first_seen": "1970-01-01 00:00:01,000",
                    }
                ],
                {
                    "start_time": "1970-01-01 00:00:01.000",
                    "end_time": "9999-12-31 23:59:59.999999",
                    "objectid": {
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "tag": "blah",
                        "treeid": None,
                        "time_observed": "1970-01-01 00:00:01.000",
                        "processtree": None,
                        "ontology_id": "process_2YK9t8RtV7Kuz78PASKGw0",
                        "service_name": "CAPE",
                    },
                    "pobjectid": None,
                    "pimage": None,
                    "pcommand_line": None,
                    "ppid": 1,
                    "pid": 0,
                    "image": "blah",
                    "command_line": "blah",
                    "integrity_level": None,
                    "image_hash": None,
                    "original_file_name": None,
                },
            ),
            (
                [
                    {
                        "process_id": 0,
                        "module_path": "",
                        "environ": {"CommandLine": "blah"},
                        "parent_id": 1,
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "first_seen": "1970-01-01 00:00:01,000",
                    }
                ],
                {},
            ),
            ([], {}),
        ],
    )
    def test_convert_cape_processes(processes, correct_event, mocker):
        safelist = {}
        so = OntologyResults(service_name="CAPE")
        mocker.patch.object(so, "sandboxes", return_value="blah")
        convert_cape_processes(processes, safelist, so)
        if correct_event:
            proc_as_prims = so.get_processes()[0].as_primitives()
            _ = proc_as_prims["objectid"].pop("session")
            assert proc_as_prims == correct_event
        else:
            assert so.get_processes() == []

    @staticmethod
    @pytest.mark.parametrize(
        "events, is_process_martian, correct_body",
        [
            (
                [
                    {
                        "pid": 0,
                        "image": "blah",
                        "command_line": "blah",
                        "ppid": 1,
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "start_time": "1970-01-01 00:00:01.000",
                        "pguid": "{12345678-1234-5678-1234-567812345678}",
                        "objectid": OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE")
                    }
                ],
                False,
                {
                    "pid": 0,
                    "name": "blah",
                    "cmd": "blah",
                    "signatures": {},
                    "children": [],
                },
            ),
            (
                [
                    {
                        "pid": 0,
                        "image": "blah",
                        "command_line": "blah",
                        "ppid": 1,
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "start_time": "1970-01-01 00:00:01.000",
                        "pguid": "{12345678-1234-5678-1234-567812345678}",
                        "objectid": OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE")
                    }
                ],
                True,
                {
                    "pid": 0,
                    "name": "blah",
                    "cmd": "blah",
                    "signatures": {},
                    "children": [],
                },
            ),
            ([], False, None),
            (
                [
                    {
                        "pid": 0,
                        "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\blah.exe",
                        "command_line": "blah",
                        "ppid": 1,
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "start_time": "1970-01-01 00:00:01.000",
                        "pguid": "{12345678-1234-5678-1234-567812345678}",
                        "objectid": OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE")
                    }
                ],
                False,
                {
                    "pid": 0,
                    "name": "C:\\Users\\buddy\\AppData\\Local\\Temp\\blah.exe",
                    "cmd": "blah",
                    "signatures": {},
                    "children": [],
                },
            ),
        ],
    )
    def test_build_process_tree(events, is_process_martian, correct_body):
        default_so = OntologyResults()
        for event in events:
            p = default_so.create_process(**event)
            default_so.add_process(p)
        correct_res_sec = ResultProcessTreeSection(title_text="Spawned Process Tree")
        actual_res_sec = ResultSection("blah")
        custom_tree_id_safelist = list()
        if correct_body:
            correct_res_sec.add_process(ProcessItem(**correct_body))
            if is_process_martian:
                correct_res_sec.set_heuristic(19)
                correct_res_sec.heuristic.add_signature_id("process_martian", score=10)
            build_process_tree(actual_res_sec, is_process_martian, default_so, custom_tree_id_safelist)
            assert actual_res_sec.subsections[0].section_body.__dict__ == correct_res_sec.section_body.__dict__
        else:
            build_process_tree(actual_res_sec, is_process_martian, default_so, custom_tree_id_safelist)
            assert actual_res_sec.subsections == []

    # TODO: complete unit tests for process_signatures
    @staticmethod
    def test_process_signatures():
        pass

    @staticmethod
    def test_add_process_context():
        ontres = OntologyResults(service_name="CAPE")

        # Nothing happens
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO")
        sig_res = ResultMultiSection("blah")
        correct_sig_res = ResultMultiSection("blah")
        _add_process_context(ontres_sig, sig_res, ontres)
        assert check_section_equality(sig_res, correct_sig_res)

        # Object ID does not exist
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO")
        ontres_sig.add_attribute(Attribute(ObjectID("blah", "blah", "blah")))
        sig_res = ResultMultiSection("blah")
        correct_sig_res = ResultMultiSection("blah")
        _add_process_context(ontres_sig, sig_res, ontres)
        assert check_section_equality(sig_res, correct_sig_res)

        # Object ID DOES exist
        p_objectid = OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE")
        p = ontres.create_process(
            pid=1,
            ppid=1,
            guid="{12345678-1234-5678-1234-567812345679}",
            command_line="blah blah.com",
            image="blah",
            start_time="1970-01-01 00:00:01.000",
            pguid="{12345678-1234-5678-1234-567812345679}",
            objectid=p_objectid
        )
        ontres.add_process(p)
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO")
        ontres_sig.add_attribute(Attribute(p_objectid))
        sig_res = ResultMultiSection("blah")
        correct_sig_res = ResultMultiSection("blah")
        correct_sig_res.add_section_part(TextSectionBody("Processes involved: blah (1)"))
        _add_process_context(ontres_sig, sig_res, ontres)
        assert check_section_equality(sig_res, correct_sig_res)

    @staticmethod
    @pytest.mark.parametrize("network, inetsim_dns_servers, expected_result", [
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
    ])
    def test_determine_dns_servers(network, inetsim_dns_servers, expected_result):
        assert _determine_dns_servers(network, inetsim_dns_servers) == expected_result

    @staticmethod
    @pytest.mark.parametrize("dom, dest_ip, dns_servers, resolved_ips, expected_result", [
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
        ("blah.com", "192.0.2.123", [], {"192.0.2.123": []}, False),
        # Domain is not safelisted but dest_ip is not part of the resolved IPs and IP is in the INetSim network
        ("blah.com", "192.0.2.123", [], {}, True),
    ])
    def test_remove_network_call(dom, dest_ip, dns_servers, resolved_ips, expected_result):
        inetsim_network = IPv4Network("192.0.2.0/24")
        safelist = {"match": {"network.dynamic.domain": ["blah.ca"]}, "regex": {"network.dynamic.ip": ["127\.0\.0\..*"]}}
        assert _remove_network_call(dom, dest_ip, dns_servers, resolved_ips, inetsim_network, safelist) == expected_result

    @staticmethod
    @pytest.mark.parametrize("network_flow, connect, expected_result", [
        # No image, connect exists with matching ip via ip_address, port
        ({"image": None, "dest_ip": "127.0.0.1", "dest_port": 999, "domain": None}, {"ip_address": "127.0.0.1", "port": 999}, True),
        # No image, connect exists with matching ip via hostname, port
        ({"image": None, "dest_ip": "127.0.0.1", "dest_port": 999, "domain": None}, {"hostname": "127.0.0.1", "port": 999}, True),
        # No image, connect exists with matching domain via url
        ({"image": None, "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999}, {"url": "http://blah.com/blah", "port": 999}, True),
        # No image, connect exists with matching domain via url with port
        ({"image": None, "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999}, {"url": "http://blah.com:999/blah", "port": 999}, True),
        # No image, connect exists with domain in url but should not run because domain is not the domain in the url
        ({"image": None, "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999}, {"url": "http://blah.org/blah.com", "port": 999}, False),
        # No image, connect exists with matching domain via servername
        ({"image": None, "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999}, {"servername": "blah.com", "port": 999}, True),

    ])
    def test_is_network_flow_a_connect_match(network_flow, connect, expected_result):
        assert _is_network_flow_a_connect_match(network_flow, connect) is expected_result

    @staticmethod
    @pytest.mark.parametrize("network_flow, process_map, expected_result", [
        # No image
        ({"image": None}, {}, {"image": None}),
        # Network flow image already is set
        ({"image": "blah"}, {}, {"image": "blah"}),
        # No image, connect exists but it's useless
        ({"image": None}, {123: {"network_calls": [{"connect": {}}]}}, {"image": None}),
        # No image, connect exists with matching ip via ip_address, port
        ({"image": None, "dest_ip": "127.0.0.1", "dest_port": 999}, {123: {"network_calls": [{"connect": {"ip_address": "127.0.0.1", "port": 999}}], "name": "blah.exe"}}, {"image": "blah.exe", "dest_ip": "127.0.0.1", "dest_port": 999, "pid": 123}),
        # No image, connect exists with matching ip via hostname, port
        ({"image": None, "dest_ip": "127.0.0.1", "dest_port": 999}, {123: {"network_calls": [{"connect": {"hostname": "127.0.0.1", "port": 999}}], "name": "blah.exe"}}, {"image": "blah.exe", "dest_ip": "127.0.0.1", "dest_port": 999, "pid": 123}),
        # No image, connect exists with matching domain via url
        ({"image": None, "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999}, {123: {"network_calls": [{"connect": {"url": "http://blah.com/blah", "port": 999}}], "name": "blah.exe"}}, {"image": "blah.exe", "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999, "pid": 123}),
        # No image, connect exists with matching domain via url with port
        ({"image": None, "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999}, {123: {"network_calls": [{"connect": {"url": "http://blah.com:999/blah", "port": 999}}], "name": "blah.exe"}}, {"image": "blah.exe", "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999, "pid": 123}),
        # No image, connect exists with domain in url but should not run because domain is not the domain in the url
        ({"image": None, "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999}, {123: {"network_calls": [{"connect": {"url": "http://blah.org/blah.com", "port": 999}}], "name": "blah.exe"}}, {"image": None, "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999}),
        # No image, connect exists with matching domain via servername
        ({"image": None, "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999}, {123: {"network_calls": [{"connect": {"servername": "blah.com", "port": 999}}], "name": "blah.exe"}}, {"image": "blah.exe", "domain": "blah.com", "dest_ip": "127.0.0.1", "dest_port": 999, "pid": 123}),
        # Sysmon unknown image name, but guid matches.
        ({"image": UNKNOWN_PROCESS, "dest_ip": "127.0.0.1", "dest_port": 999, "guid": "{12345678-1234-5678-1234-567812345679}", "pid": 123}, {123: {"network_calls": [{"connect": {"ip_address": "127.0.0.1", "port": 999}}], "name": "blah.exe"}}, {"image": "blah.exe", "dest_ip": "127.0.0.1", "dest_port": 999, "guid": "{12345678-1234-5678-1234-567812345679}", "pid": 123}),
        # Sysmon unknown image name, but pid and timestamp matches.
        ({"image": UNKNOWN_PROCESS, "dest_ip": "127.0.0.1", "dest_port": 999, "timestamp": "1970-01-01 00:00:03", "pid": 123}, {123: {"network_calls": [{"connect": {"ip_address": "127.0.0.1", "port": 999}}], "name": "blah.exe"}}, {"image": "blah.exe", "dest_ip": "127.0.0.1", "dest_port": 999, "timestamp": "1970-01-01 00:00:03", "pid": 123}),
    ])
    def test_link_flow_with_process(network_flow, process_map, expected_result):
        ontres = OntologyResults(service_name="CAPE")
        p = ontres.create_process(
            image="blah.exe",
            start_time="1970-01-01 00:00:01",
            end_time="1970-01-01 00:00:10",
            pid=123,
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE", guid="{12345678-1234-5678-1234-567812345679}")
        )
        ontres.add_process(p)

        assert _link_flow_with_process(network_flow, process_map, ontres) == expected_result

    @staticmethod
    @pytest.mark.parametrize("dom, network_flow, dest_ip, expected_tags", [
        # Nothing interest, just tagging some things
        ("", {"protocol": "tcp", "src_ip": "127.0.0.1", "dest_port": 123, "src_port": 321}, "", {'network.protocol': ['tcp'], 'network.dynamic.ip': ['127.0.0.1'], 'network.port': [123, 321]}),
        # Domain
        ("blah.com", {"protocol": "tcp", "src_ip": "127.0.0.1", "dest_port": 123, "src_port": 321}, "", {'network.dynamic.domain': ['blah.com'], 'network.protocol': ['tcp'], 'network.dynamic.ip': ['127.0.0.1'], 'network.port': [123, 321]}),
        # Safelisted dest IP and src IP
        ("", {"protocol": "tcp", "src_ip": "192.168.0.123", "dest_port": 123, "src_port": 321}, "192.168.0.321", {'network.protocol': ['tcp'], 'network.port': [123, 321]}),
        # Non-safelisted dest IP and src IP
        ("", {"protocol": "tcp", "src_ip": "192.168.1.123", "dest_port": 123, "src_port": 321}, "192.168.1.231", {'network.protocol': ['tcp'], 'network.dynamic.ip': ['192.168.1.231', '192.168.1.123'], 'network.port': [123, 321]}),
    ])
    def test_tag_network_flow(dom, network_flow, dest_ip, expected_tags):
        netflows_sec = ResultTableSection("blah")
        safelist = {"regex": {"network.dynamic.ip": ["192\.168\.0\..*"]}}
        _tag_network_flow(netflows_sec, dom, network_flow, dest_ip, safelist)
        assert netflows_sec.tags == expected_tags

    @staticmethod
    @pytest.mark.parametrize("network_flow, expected_netflow", [
        # No image, timestamp is not string
        ({"src_ip": "127.0.0.1", "src_port": 123, "dest_ip": "1.1.1.1", "dest_port": 321, "protocol": "tcp", "timestamp": 1, "pid": None}, {
            'connection_type': None,
            'destination_ip': '1.1.1.1',
            'destination_port': 321,
            'direction': 'outbound',
            'dns_details': None,
            'http_details': None,
            'objectid': {'ontology_id': 'network_7hKNdOVlLWYVZUUVUNbDgs',
                         'processtree': None,
                         'service_name': 'CAPE',
                         'session': 'blah',
                         'tag': '1.1.1.1:321',
                         'time_observed': '1970-01-01 00:00:01.000',
                         'treeid': None},
            'process': None,
            'source_ip': '127.0.0.1',
            'source_port': 123,
            'transport_layer_protocol': 'tcp',
        }),
        # No image, timestamp is string
        ({"src_ip": "127.0.0.1", "src_port": 123, "dest_ip": "1.1.1.1", "dest_port": 321, "protocol": "tcp", "timestamp": '1970-01-01 00:00:01.000', "pid": None}, {
            'connection_type': None,
            'destination_ip': '1.1.1.1',
            'destination_port': 321,
            'direction': 'outbound',
            'dns_details': None,
            'http_details': None,
            'objectid': {'ontology_id': 'network_7hKNdOVlLWYVZUUVUNbDgs',
                         'processtree': None,
                         'service_name': 'CAPE',
                         'session': 'blah',
                         'tag': '1.1.1.1:321',
                         'time_observed': '1970-01-01 00:00:01.000',
                         'treeid': None},
            'process': None,
            'source_ip': '127.0.0.1',
            'source_port': 123,
            'transport_layer_protocol': 'tcp',
        }),
        # Image
        ({"src_ip": "127.0.0.1", "src_port": 123, "dest_ip": "1.1.1.1", "dest_port": 321, "protocol": "tcp", "timestamp": '1970-01-01 00:00:01.000', "pid": 123, "image": "blah.exe"}, {
            'connection_type': None,
            'destination_ip': '1.1.1.1',
            'destination_port': 321,
            'direction': 'outbound',
            'dns_details': None,
            'http_details': None,
            'objectid': {'ontology_id': 'network_7hKNdOVlLWYVZUUVUNbDgs',
                         'processtree': None,
                         'service_name': 'CAPE',
                         'session': 'blah',
                         'tag': '1.1.1.1:321',
                         'time_observed': '1970-01-01 00:00:01.000',
                         'treeid': None},
            'process': None,
            'source_ip': '127.0.0.1',
            'source_port': 123,
            'transport_layer_protocol': 'tcp',
        }),
    ])
    def test_create_network_connection_for_network_flow(network_flow, expected_netflow):
        session = "blah"
        ontres = OntologyResults(service_name="CAPE")
        p = Process(objectid=OntologyResults.create_objectid(tag="blah.exe", ontology_id="blah", service_name="CAPE"), image="blah.exe", start_time="1970-01-01 00:00:01", end_time="1970-01-01 00:00:10", pid=123)
        ontres.add_process(p)

        _create_network_connection_for_network_flow(network_flow, session, ontres)
        prims = ontres.netflows[0].as_primitives()
        prims["objectid"].pop("guid")
        assert prims == expected_netflow

    @staticmethod
    def test_process_network():
        inetsim_network = IPv4Network("192.0.2.0/24")
        inetsim_dns_servers = []
        routing = "inetsim"
        safelist =  {
            'match': {
                'file.path': []
            }, 'regex': {
                'network.dynamic.domain': ['.+\\.adobe\\.com$', 'files\\.acrobat\\.com$', 'play\\.google\\.com$', '.+\\.android\\.pool\\.ntp\\.org$', 'android\\.googlesource\\.com$', 'schemas\\.android\\.com$', 'xmlpull\\.org$', 'schemas\\.openxmlformats\\.org$', 'img-s-msn-com\\.akamaized\\.net$', 'fbstatic-a\\.akamaihd\\.net$', 'ajax\\.aspnetcdn\\.com$', '(www\\.)?w3\\.org$', 'ocsp\\.omniroot\\.com$', '^wpad\\..*$', 'dns\\.msftncsi\\.com$', 'www\\.msftncsi\\.com$', 'ipv6\\.msftncsi\\.com$', '.+\\.microsoft\\.com$', '.+\\.live\\.com$', 'client\\.wns\\.windows\\.com$', 'dns\\.msftncsi\\.com$', 'ocsp\\.msocsp\\.com$', 'www\\.msftconnecttest\\.com$', 'www\\.msftncsi\\.com$', '(([a-z]-ring(-fallback)?)|(fp)|(segments-[a-z]))\\.msedge\\.net$', 'ow1\\.res\\.office365\\.com$', 'fp-(as-nocache|vp)\\.azureedge\\.net$', '(?:outlookmobile|client)-office365-tas\\.msedge\\.net$', 'config\\.messenger\\.msn\\.com$', 'aadcnd\\.ms(?:ft)?auth\\.net$', 'login\\.microsoftonline\\.com$', 'skydrivesync\\.policies\\.live\\.net$', 'api\\.onedrive\\.com$', 'microsoftwindows\\.client\\.cbs$', '.+\\.windowsupdate\\.com$', 'time\\.(microsoft|windows)\\.com$', '.+\\.windows\\.com$', 'kms\\.core\\.windows\\.net$', 'i\\.gyazo\\.com$', '.+\\.edgesuite\\.net$', 'cdn\\.content\\.prod\\.cms\\.msn\\.com$', '((www|arc)\\.)?msn\\.com$', '(www\\.)?static-hp-eas\\.s-msn\\.com$', 'img\\.s-msn\\.com$', '((api|www|platform)\\.)?bing\\.com$', 'md-ssd-.+\\.blob\\.core\\.windows\\.net$', '.+\\.table\\.core\\.windows\\.net$', '.+\\.blob\\.core\\.windows\\.net$', '.+\\.opinsights\\.azure\\.com$', 'agentserviceapi\\.azure-automation\\.net$', 'agentserviceapi\\.guestconfiguration\\.azure\\.com$', '.+\\.blob\\.storage\\.azure\\.net$', 'config\\.edge\\.skype\\.com$', 'cdn\\.onenote\\.net$', '(www\\.)?verisign\\.com$', 'csc3-(2010|2004|2009-2)-crl\\.verisign\\.com$', 'csc3-2010-aia\\.verisign\\.com$', 'ocsp\\.verisign\\.com$', 'logo\\.verisign\\.com$', 'crl\\.verisign\\.com$', '(changelogs|daisy|ntp|ddebs|security|motd)\\.ubuntu\\.com$', '(azure|ca)\\.archive\\.ubuntu\\.com$', '.+\\.local$', 'local$', 'localhost$', '.+\\.comodoca\\.com$', '(?:crl|ocsp)\\.sectigo\\.com$', '^[0-9a-f\\.]+\\.ip6\\.arpa$', '^[0-9\\.]+\\.in-addr\\.arpa$', '(www\\.)?java\\.com$', 'sldc-esd\\.oracle\\.com$', 'javadl\\.sun\\.com$', 'javadl-esd-secure\\.oracle\\.com$', 'ocsp\\.digicert\\.com$', 'crl[0-9]\\.digicert\\.com$', 's[a-z0-9]?\\.symc[bd]\\.com$', '(evcs|ts)-(ocsp|crl)\\.ws\\.symantec\\.com$', 'ocsp\\.thawte\\.com$', 'ocsp[0-9]?\\.globalsign\\.com$', 'crl\\.globalsign\\.(com|net)$', '(?:crl|ocsp)\\.certum\\.pl$', 'ocsp\\.usertrust\\.com$', 'google\\.com$', 'ajax\\.googleapis\\.com$', 'fonts\\.googleapis\\.com$', 'update\\.googleapis\\.com$', 'lh3\\.googleusercontent\\.com$', 'www\\.google-analytics\\.com$', '(www\\.)?inetsim\\.org$', 'does-not-exist\\.example\\.com$', '.+\\.agentsvc\\.azure-automation\\.net$', 'code\\.jquery\\.com$', 'use\\.typekit\\.net$', 'cdnjs\\.cloudflare\\.com$', 'svgshare\\.com$', 'maxcdn\\.boostrapcdn\\.com$', 'stackpath\\.boostrapcdn\\.com$', 'man\\.boostrapcdn\\.com$', 'use\\.fontawesome\\.com$', 'cdn\\.jsdelivr\\.net$', 'api\\.snapcraft\\.io$', 'upload\\.wikimedia\\.org$', 'ailab\\.criteo\\.com$'],
                'network.dynamic.ip': ['(^1\\.1\\.1\\.1$)|(^8\\.8\\.8\\.8$)', '(?:127\\.|10\\.|192\\.168|172\\.1[6-9]\\.|172\\.2[0-9]\\.|172\\.3[01]\\.).*', '255\\.255\\.255\\.255', '169\\.169\\.169\\.169', '239\\.255\\.255\\.250', '224\\..*', '169\\.254\\.169\\.254', '168\\.63\\.129\\.16', '192\\.0\\.2\\..*'],
                'network.dynamic.uri': ['(?:ftp|http)s?://localhost(?:$|/.*)', '(?:ftp|http)s?://(?:(?:(?:10|127)(?:\\.(?:[2](?:[0-5][0-5]|[01234][6-9])|[1][0-9][0-9]|[1-9][0-9]|[0-9])){3})|(?:172\\.(?:1[6-9]|2[0-9]|3[0-1])(?:\\.(?:2[0-4][0-9]|25[0-5]|[1][0-9][0-9]|[1-9][0-9]|[0-9])){2}|(?:192\\.168(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){2})))(?:$|/.*)', 'https?://schemas\\.android\\.com/apk/res(-auto|/android)', 'https?://android\\.googlesource\\.com/toolchain/llvm-project', 'https?://xmlpull\\.org/v1/doc/features\\.html(?:$|.*)', 'https?://schemas\\.openxmlformats\\.org(?:$|/.*)', 'https?://.+\\.microsoft\\.com(?:$|/.*)', 'https?://config\\.messenger\\.msn\\.com(?:$|/.*)', 'https?://aadcdn\\.ms(?:ft)?auth\\.net(?:$|/.*)', 'https?://ctldl\\.windowsupdate\\.com(?:$|/.*)', 'https?://ca\\.archive\\.ubuntu\\.com(?:$|/.*)', 'https?://config\\.edge\\.skype\\.com(?:$|/.*)', 'https?://(www|oscp|crl|logo|csc3-2010-(crl|aia))\\.verisign\\.com(?:$|/.*)', 'https?://wpad\\..*/wpad\\.dat', 'https?://ocsp\\.digicert\\.com/.*', 'https?://crl[0-9]\\.digicert\\.com/.*', 'https?://s[a-z0-9]?\\.symc[bd]\\.com/.*', 'https?://(evcs|ts)-(ocsp|crl)\\.ws\\.symantec\\.com/.*', 'https?://ocsp\\.thawte\\.com/.*', 'https?://ocsp\\.entrust\\.net/.*', 'https?://crl\\.entrust\\.net/.*', 'https?://ocsp[0-9]?\\.globalsign\\.com/.*', 'https?://crl\\.globalsign\\.(com|net)/.*', 'https?://www\\.w3\\.org/.*', 'https?://www\\.google\\.com', '(?:https?://)?files\\.acrobat\\.com(?:(?::443)|(?:/.*))', 'https?://acroipm2?\\.adobe\\.com/.*', 'https?://code\\.jquery\\.com/.*', 'https?://cdnjs\\.cloudflare\\.com/.*'],
                'network.dynamic.uri_path': ['\\/11\\/rdr\\/enu\\/win\\/nooem\\/none\\/message\\.zip'],
            }
        }

        # Example 1: Nothing
        network = {}
        parent_result_section = ResultSection("blah")
        ontres = OntologyResults(service_name="blah")
        sandbox = ontres.create_sandbox(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), sandbox_name="CAPE")
        ontres.add_sandbox(sandbox)
        process_map = {}

        correct_result_section = ResultSection("blah")

        process_network(network, parent_result_section, inetsim_network, routing, process_map, safelist, ontres, inetsim_dns_servers, False)
        assert check_section_equality(parent_result_section, correct_result_section)
        assert ontres.netflows == []

        # Example 2: a7fa12546adfdcd0601c3c0e8e56994cc0b9e72cf0f62edadab6028f24b68543
        network = {
            "udp": [
                 {
                    'src': '192.168.0.23', 'sport': 64269, 'dst': '192.168.0.4', 'dport': 53, 'offset': 4316, 'time': 1681924858.656266
                }, {
                    'src': '192.168.0.23', 'sport': 56091, 'dst': '192.168.0.4', 'dport': 53, 'offset': 5830, 'time': 1681924861.568375
                }, {
                    'src': '192.168.0.23', 'sport': 64270, 'dst': '192.168.0.4', 'dport': 53, 'offset': 6061, 'time': 1681924861.674406
                }, {
                    'src': '192.168.0.23', 'sport': 49926, 'dst': '192.168.0.4', 'dport': 53, 'offset': 6290, 'time': 1681924865.561247
                }, {
                    'src': '192.168.0.23', 'sport': 61972, 'dst': '192.168.0.4', 'dport': 53, 'offset': 6370, 'time': 1681924865.608088
                }, {
                    'src': '192.168.0.23', 'sport': 60422, 'dst': '192.168.0.4', 'dport': 53, 'offset': 8635, 'time': 1681924865.780254
                }, {
                    'src': '192.168.0.23', 'sport': 59412, 'dst': '192.168.0.4', 'dport': 53, 'offset': 16737, 'time': 1681924866.626783
                }, {
                    'src': '192.168.0.23', 'sport': 51511, 'dst': '192.168.0.4', 'dport': 53, 'offset': 16837, 'time': 1681924866.626895
                }, {
                    'src': '192.168.0.23', 'sport': 63491, 'dst': '192.168.0.4', 'dport': 53, 'offset': 17198, 'time': 1681924867.642186
                }, {
                    'src': '192.168.0.23', 'sport': 51004, 'dst': '192.168.0.4', 'dport': 53, 'offset': 17298, 'time': 1681924867.642679
                }, {
                    'src': '192.168.0.23', 'sport': 60861, 'dst': '192.168.0.4', 'dport': 53, 'offset': 17663, 'time': 1681924879.751643
                }, {
                    'src': '192.168.0.23', 'sport': 63820, 'dst': '192.168.0.4', 'dport': 53, 'offset': 17898, 'time': 1681924880.767634
                }
            ],
            "tcp": [
                {
                    'src': '192.168.0.23', 'sport': 49743, 'dst': '192.0.2.169', 'dport': 443, 'offset': 264, 'time': 1681924852.477152
                }, {
                    'src': '192.168.0.23', 'sport': 49744, 'dst': '192.0.2.169', 'dport': 443, 'offset': 1142, 'time': 1681924852.490897
                }, {
                    'src': '192.168.0.23', 'sport': 49746, 'dst': '192.0.2.169', 'dport': 443, 'offset': 2410, 'time': 1681924852.508985
                }, {
                    'src': '192.168.0.23', 'sport': 49747, 'dst': '192.0.2.169', 'dport': 443, 'offset': 3216, 'time': 1681924852.524264
                }, {
                    'src': '192.168.0.23', 'dst': '192.0.2.80', 'time': '2023-04-19 17:21:03.000', 'dport': 80, 'sport': 49767, 'guid': '{0b406823-22f7-6440-1701-000000002200}', 'pid': 1760, 'image': 'C:\\Windows\\SMaster64.exe'
                }, {
                    'src': '192.168.0.23', 'dst': '95.216.164.28', 'time': '2023-04-19 17:21:03.000', 'dport': 80, 'sport': 49764, 'guid': '{0b406823-22fc-6440-2401-000000002200}', 'pid': 1008, 'image': 'C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe'
                }, {
                    'src': '192.168.0.23', 'dst': '95.216.164.28', 'time': '2023-04-19 17:21:03.000', 'dport': 80, 'sport': 49763, 'guid': '{0b406823-22fc-6440-2401-000000002200}', 'pid': 1008, 'image': 'C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe'
                }, {
                    'src': '192.168.0.23', 'dst': '192.0.2.214', 'time': '2023-04-19 17:21:03.000', 'dport': 443, 'sport': 49762, 'guid': '{0b406823-22fc-6440-2401-000000002200}', 'pid': 1008, 'image': 'C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe'
                }, {
                    'src': '192.168.0.23', 'dst': '192.0.2.214', 'time': '2023-04-19 17:21:03.000', 'dport': 443, 'sport': 49761, 'guid': '{0b406823-22fc-6440-2401-000000002200}', 'pid': 1008, 'image': 'C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe'
                }, {
                    'src': '192.168.0.23', 'dst': '192.0.2.214', 'time': '2023-04-19 17:21:03.000', 'dport': 443, 'sport': 49760, 'guid': '{0b406823-22fc-6440-2401-000000002200}', 'pid': 1008, 'image': 'C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe'
                }, {
                    'src': '192.168.0.23', 'dst': '192.0.2.170', 'time': '2023-04-19 17:21:03.000', 'dport': 80, 'sport': 49759, 'guid': '{0b406823-22f7-6440-1701-000000002200}', 'pid': 1760, 'image': 'C:\\Windows\\SMaster64.exe'
                }, {
                    'src': '192.168.0.23', 'dst': '192.0.2.164', 'time': '2023-04-19 17:21:03.000', 'dport': 443, 'sport': 49758, 'guid': '{0b406823-22fc-6440-2401-000000002200}', 'pid': 1008, 'image': 'C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe'
                }, {
                    'src': '192.168.0.23', 'dst': '192.0.2.164', 'time': '2023-04-19 17:21:03.000', 'dport': 443, 'sport': 49757, 'guid': '{0b406823-22fc-6440-2401-000000002200}', 'pid': 1008, 'image': 'C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe'
                }, {
                    'src': '192.168.0.23', 'dst': '192.0.2.164', 'time': '2023-04-19 17:21:03.000', 'dport': 443, 'sport': 49756, 'guid': '{0b406823-22fc-6440-2401-000000002200}', 'pid': 1008, 'image': 'C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe'
                }
            ],
            "dns": [{
                    'request': '4.100.163.10.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.inetsim.org'}]
                }, {
                    'request': '214.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'steamcommunity.com'}]
                }, {
                    'request': '28.164.216.95.in-addr.arpa', 'type': 'PTR', 'answers': []
                }, {
                    'request': '2.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.f.f.ip6.arpa', 'type': 'PTR', 'answers': []
                }, {
                    'type': 'A', 'request': 'steamcommunity.com', 'answers': [{'data': '192.0.2.214', 'type': 'A'}], 'time': '2023-04-19 17:21:03.000', 'guid': '{0b406823-22fc-6440-2401-000000002200}', 'pid': 1008, 'image': 'C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe'
                }, {
                    'type': 'A', 'request': 't.me', 'answers': [{'data': '192.0.2.164', 'type': 'A'}], 'time': '2023-04-19 17:21:02', 'guid': '{0b406823-22fc-6440-2401-000000002200}', 'pid': 1008, 'image': 'C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe'
                }
            ],
            "http": [],
            "http_ex": [ {
                    'src': '192.168.0.23', 'sport': 49763, 'dst': '95.216.164.28', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': '95.216.164.28', 'uri': '/897', 'status': 200, 'request': 'GET /897 HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36\r\nHost: 95.216.164.28', 'resp': {
                        'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/251603/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'
                    }
                }, {
                    'src': '192.168.0.23', 'sport': 49764, 'dst': '95.216.164.28', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': '95.216.164.28', 'uri': '/package.zip', 'status': 200, 'request': 'GET /package.zip HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36\r\nHost: 95.216.164.28\r\nCache-Control: no-cache', 'resp': {
                        'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/251603/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'
                    }
                }
            ],
            "https": [],
            "https_ex": [],
        }
        parent_result_section = ResultSection("blah")
        ontres = OntologyResults(service_name="blah")
        sandbox = ontres.create_sandbox(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), sandbox_name="CAPE")
        ontres.add_sandbox(sandbox)
        process_map =  {
            1008: {
                'name': 'C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe', 'network_calls': [
                    {'InternetConnectA': {'service': '3', 'servername': 't.me', 'serverport': '0'}},
                    {'WSASend': {'buffer': '\\x16\\x03\\x03\\x00\\x9d\\x01\\x00\\x00\\x99\\x03\\x03d@"\\xff\\xe0\\xbe\\xb3C\\xe1\\x05\\xfcc\\x82@\\xb4\\xefXu\\x99qV\\xb1\\x06\\xe9\\x96\\x0b\\x99\\xab\\xd1\\xc7\\x92]\\x00\\x00&\\xc0,\\xc0+\\xc00\\xc0/\\xc0$\\xc0#\\xc0(\\xc0\'\\xc0\n\\xc0\t\\xc0\\x14\\xc0\\x13\\x00\\x9d\\x00\\x9c\\x00=\\x00<\\x005\\x00/\\x00\n\\x01\\x00\\x00J\\x00\\x00\\x00\t\\x00\\x07\\x00\\x00\\x04t.me\\x00\n\\x00\\x08\\x00\\x06\\x00\\x1d\\x00\\x17\\x00\\x18\\x00\\x0b\\x00\\x02\\x01\\x00\\x00\r\\x00\\x1a\\x00\\x18\\x08\\x04\\x08\\x05\\x08\\x06\\x04\\x01\\x05\\x01\\x02\\x01\\x04\\x03\\x05\\x03\\x02\\x03\\x02\\x02\\x06\\x01\\x06\\x03\\x00#\\x00\\x00\\x00\\x17\\x00\\x00\\xff\\x01\\x00\\x01\\x00'}},
                    {'WSASend': {'buffer': '\\x16\\x03\\x01\\x00g\\x01\\x00\\x00c\\x03\\x01d@"\\xff\\xe5\\xcf\\x17\'~AS/\\xcc\\xab\\xc26%/\\x95z\\x1e\\xfe!\\xdc\\x1fO\\xeb\\xff\\x1a\\xfc)\\xfd\\x00\\x00\\x0e\\xc0\n\\xc0\t\\xc0\\x14\\xc0\\x13\\x005\\x00/\\x00\n\\x01\\x00\\x00,\\x00\\x00\\x00\t\\x00\\x07\\x00\\x00\\x04t.me\\x00\n\\x00\\x08\\x00\\x06\\x00\\x1d\\x00\\x17\\x00\\x18\\x00\\x0b\\x00\\x02\\x01\\x00\\x00#\\x00\\x00\\x00\\x17\\x00\\x00\\xff\\x01\\x00\\x01\\x00'}},
                    {'InternetConnectA': {'service': '3', 'servername': 'steamcommunity.com', 'serverport': '0'}},
                    {'WSASend': {'buffer': '\\x16\\x03\\x03\\x00\\xab\\x01\\x00\\x00\\xa7\\x03\\x03d@"\\xff\\x05\\xf1#\\xa8pu\\x92\\xf8\\xb9TC\\x0b\\xcb\\xef\\xcaz\\xf8A\\xbbSZ\\x91\\xa8\\xae\nx\\xa5:\\x00\\x00&\\xc0,\\xc0+\\xc00\\xc0/\\xc0$\\xc0#\\xc0(\\xc0\'\\xc0\n\\xc0\t\\xc0\\x14\\xc0\\x13\\x00\\x9d\\x00\\x9c\\x00=\\x00<\\x005\\x00/\\x00\n\\x01\\x00\\x00X\\x00\\x00\\x00\\x17\\x00\\x15\\x00\\x00\\x12steamcommunity.com\\x00\n\\x00\\x08\\x00\\x06\\x00\\x1d\\x00\\x17\\x00\\x18\\x00\\x0b\\x00\\x02\\x01\\x00\\x00\r\\x00\\x1a\\x00\\x18\\x08\\x04\\x08\\x05\\x08\\x06\\x04\\x01\\x05\\x01\\x02\\x01\\x04\\x03\\x05\\x03\\x02\\x03\\x02\\x02\\x06\\x01\\x06\\x03\\x00#\\x00\\x00\\x00\\x17\\x00\\x00\\xff\\x01\\x00\\x01\\x00'}},
                    {'WSASend': {'buffer': '\\x16\\x03\\x01\\x00u\\x01\\x00\\x00q\\x03\\x01d@"\\xffl\\x8d\\x11\\xd5\\x11\\x92\\xfb\\xa4\\xcb:\\x08\\xd5*\\xe6\\xaf\\x80\\xa5\\xc3\\xba_\\xf0h\\xb7O\\x82\\xa3\\\\xda\\x00\\x00\\x0e\\xc0\n\\xc0\t\\xc0\\x14\\xc0\\x13\\x005\\x00/\\x00\n\\x01\\x00\\x00:\\x00\\x00\\x00\\x17\\x00\\x15\\x00\\x00\\x12steamcommunity.com\\x00\n\\x00\\x08\\x00\\x06\\x00\\x1d\\x00\\x17\\x00\\x18\\x00\\x0b\\x00\\x02\\x01\\x00\\x00#\\x00\\x00\\x00\\x17\\x00\\x00\\xff\\x01\\x00\\x01\\x00'}},
                    {'InternetCrackUrlA': {'url': 'http://95.216.164.28:80'}},
                    {'InternetConnectA': {'service': '3', 'servername': '95.216.164.28', 'serverport': '80'}},
                    {'WSASend': {'buffer': 'GET /897 HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36\r\nHost: 95.216.164.28\r\n\r\n'}},
                    {'InternetCrackUrlA': {'url': 'http://95.216.164.28:80/package.zip'}},
                    {'WSASend': {'buffer': 'GET /package.zip HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36\r\nHost: 95.216.164.28\r\nCache-Control: no-cache\r\n\r\n'}},
                    {'InternetOpenUrlA': {'url': 'http://95.216.164.28:80/package.zip'}}
                ], 'decrypted_buffers': []
            }, 4676: {
                'name': 'C:\\Windows\\SysWOW64\\WerFault.exe', 'network_calls': [], 'decrypted_buffers': []
            }
        }

        correct_result_section = ResultSection("blah")
        correct_network_result_section = ResultSection("Network Activity")
        dns_subsection = ResultTableSection("Protocol: DNS", tags={'network.protocol': ['dns'], 'network.dynamic.domain': ['steamcommunity.com', 't.me']})
        dns_subsection.add_row(TableRow({'domain': 'steamcommunity.com', 'answer': '192.0.2.214', "type": "A"}))
        dns_subsection.add_row(TableRow({'domain': 't.me', 'answer': '192.0.2.164', "type": "A"}))
        dns_subsection.set_heuristic(1000)
        correct_network_result_section.add_subsection(dns_subsection)
        tcp_udp_subsection = ResultTableSection("TCP/UDP Network Traffic", tags={'network.protocol': ['tcp'], 'network.dynamic.ip': ['95.216.164.28'], 'network.port': [80, 49764, 49763, 443, 49762, 49761, 49760, 49758, 49757, 49756], 'network.dynamic.domain': ['steamcommunity.com', 't.me']})
        tcp_udp_subsection.set_heuristic(1004)
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.23", "src_port": 49764, "domain": None, "dest_ip": "95.216.164.28", "dest_port": 80, "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe", "pid": 1008, "guid": "{0b406823-22fc-6440-2401-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.23", "src_port": 49763, "domain": None, "dest_ip": "95.216.164.28", "dest_port": 80, "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe", "pid": 1008, "guid": "{0b406823-22fc-6440-2401-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.23", "src_port": 49762, "domain": "steamcommunity.com", "dest_ip": "192.0.2.214", "dest_port": 443, "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe", "pid": 1008, "guid": "{0b406823-22fc-6440-2401-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.23", "src_port": 49761, "domain": "steamcommunity.com", "dest_ip": "192.0.2.214", "dest_port": 443, "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe", "pid": 1008, "guid": "{0b406823-22fc-6440-2401-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.23", "src_port": 49760, "domain": "steamcommunity.com", "dest_ip": "192.0.2.214", "dest_port": 443, "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe", "pid": 1008, "guid": "{0b406823-22fc-6440-2401-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.23", "src_port": 49758, "domain": "t.me", "dest_ip": "192.0.2.164", "dest_port": 443, "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe", "pid": 1008, "guid": "{0b406823-22fc-6440-2401-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.23", "src_port": 49757, "domain": "t.me", "dest_ip": "192.0.2.164", "dest_port": 443, "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe", "pid": 1008, "guid": "{0b406823-22fc-6440-2401-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.23", "src_port": 49756, "domain": "t.me", "dest_ip": "192.0.2.164", "dest_port": 443, "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\a7fa12546adfdcd0601c.exe", "pid": 1008, "guid": "{0b406823-22fc-6440-2401-000000002200}"}))
        tcp_udp_subsection.add_subsection(ResultSection("TCP Network Traffic Detected", auto_collapse=True, heuristic=Heuristic(1010)))
        correct_network_result_section.add_subsection(tcp_udp_subsection)
        http_subsection = ResultTableSection("Protocol: HTTP/HTTPS", tags={'network.protocol': ['http'], 'network.dynamic.ip': ['95.216.164.28'], 'network.dynamic.uri': ['http://95.216.164.28/897', 'http://95.216.164.28/package.zip'], 'network.dynamic.uri_path': ['/897', '/package.zip']})
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"UserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", "Host": "95.216.164.28"}, "uri": "http://95.216.164.28/897"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"UserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", "Host": "95.216.164.28", "CacheControl": "no-cache"}, "uri": "http://95.216.164.28/package.zip"}))
        http_subsection.set_heuristic(1002)
        access_remote_subsection = ResultSection("Access Remote File", body="The sample attempted to download the following files:\n\thttp://95.216.164.28/package.zip", tags={'network.dynamic.ip': ['95.216.164.28'], 'network.dynamic.uri': ['http://95.216.164.28/package.zip'], 'network.dynamic.uri_path': ['/package.zip']})
        access_remote_subsection.set_heuristic(1003)
        http_subsection.add_subsection(access_remote_subsection)
        http_header_ioc_subsection = ResultTableSection("IOCs found in HTTP/HTTPS Headers", tags={'network.dynamic.ip': ['95.216.164.28']})
        http_header_ioc_subsection.add_row(TableRow({"ioc_type": "ip", "ioc": "95.216.164.28"}))
        http_subsection.add_subsection(http_header_ioc_subsection)
        correct_network_result_section.add_subsection(http_subsection)
        unseen_subsection = ResultTableSection("Unseen IOCs found in API calls", tags={'network.dynamic.ip': ['95.216.164.28'], 'network.dynamic.uri': ['http://95.216.164.28']})
        unseen_subsection.add_row(TableRow({"ioc_type": "uri", "ioc": "http://95.216.164.28"}))
        unseen_subsection.set_heuristic(1013)
        correct_network_result_section.add_subsection(unseen_subsection)
        correct_result_section.add_subsection(correct_network_result_section)

        correct_netflows = [
            {'objectid': {'tag': '95.216.164.28:80', 'ontology_id': 'network_nVxpq7pEoHUB2klPW635C', 'service_name': 'blah', 'guid': '{D108591A-BD96-46EB-A2BC-EC9515A67509}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-19 17:21:03.000', 'session': None}, 'destination_ip': '95.216.164.28', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.23', 'source_port': 49764, 'http_details': {'request_uri': 'http://95.216.164.28/897', 'request_method': 'GET', 'request_headers': {'UserAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36', 'Host': '95.216.164.28'}, 'response_headers': {}, 'request_body': None, 'response_status_code': 200, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '95.216.164.28:80', 'ontology_id': 'network_38NX6IQ0fRInDC8oJj8Wcn', 'service_name': 'blah', 'guid': '{482EA9DA-0D43-4020-8FB2-423CB56E8593}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-19 17:21:03.000', 'session': None}, 'destination_ip': '95.216.164.28', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.23', 'source_port': 49763, 'http_details': None, 'dns_details': None, 'connection_type': None},
            {'objectid': {'tag': '192.0.2.214:443', 'ontology_id': 'network_1NMBizTw6LVscAQk6AzSa3', 'service_name': 'blah', 'guid': '{8C74A811-3385-41AB-AABA-16F76E54D975}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-19 17:21:03.000', 'session': None}, 'destination_ip': '192.0.2.214', 'destination_port': 443, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.23', 'source_port': 49762, 'http_details': None, 'dns_details': None, 'connection_type': None},
            {'objectid': {'tag': '192.0.2.214:443', 'ontology_id': 'network_42ZYGeRxVdlLMX1tkygMgT', 'service_name': 'blah', 'guid': '{551CAC81-8453-496E-87A2-62E80F908693}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-19 17:21:03.000', 'session': None}, 'destination_ip': '192.0.2.214', 'destination_port': 443, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.23', 'source_port': 49761, 'http_details': None, 'dns_details': None, 'connection_type': None},
            {'objectid': {'tag': '192.0.2.214:443', 'ontology_id': 'network_5AXmSU6EMjdmMVSlhli1wt', 'service_name': 'blah', 'guid': '{4EBCA6D1-CA3C-43CE-BCBB-E16584CE9131}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-19 17:21:03.000', 'session': None}, 'destination_ip': '192.0.2.214', 'destination_port': 443, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.23', 'source_port': 49760, 'http_details': None, 'dns_details': None, 'connection_type': None},
            {'objectid': {'tag': '192.0.2.164:443', 'ontology_id': 'network_974wSt1tqtBKhh6wfVJR0', 'service_name': 'blah', 'guid': '{6489BEA9-36AF-43D0-A42A-EB7D4F7BFB56}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-19 17:21:03.000', 'session': None}, 'destination_ip': '192.0.2.164', 'destination_port': 443, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.23', 'source_port': 49758, 'http_details': None, 'dns_details': None, 'connection_type': None},
            {'objectid': {'tag': '192.0.2.164:443', 'ontology_id': 'network_6dF5xejdde84vtwKjhOfnN', 'service_name': 'blah', 'guid': '{A2DD66EE-F7B6-4978-A88A-567B0D147AA3}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-19 17:21:03.000', 'session': None}, 'destination_ip': '192.0.2.164', 'destination_port': 443, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.23', 'source_port': 49757, 'http_details': None, 'dns_details': None, 'connection_type': None},
            {'objectid': {'tag': '192.0.2.164:443', 'ontology_id': 'network_1BWIArDQYnvlvMpkfHkwrm', 'service_name': 'blah', 'guid': '{A17304BF-B11E-4AB1-B6F7-07E179CF90D8}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-19 17:21:03.000', 'session': None}, 'destination_ip': '192.0.2.164', 'destination_port': 443, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.23', 'source_port': 49756, 'http_details': None, 'dns_details': None, 'connection_type': None},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{6345E36D-688C-4B90-9CE8-BBBCA611C05E}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'steamcommunity.com', 'resolved_ips': ['192.0.2.214'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{E3F55ED1-FC55-40B0-8C0C-CA55A74FACCD}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 't.me', 'resolved_ips': ['192.0.2.164'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
        ]

        process_network(network, parent_result_section, inetsim_network, routing, process_map, safelist, ontres, inetsim_dns_servers, False)
        assert check_section_equality(parent_result_section, correct_result_section)

        for index, netflow in enumerate(ontres.netflows):
            # Ignore guids since they are random
            netflow_as_prims = netflow.as_primitives()
            _ = netflow_as_prims["objectid"].pop("guid")
            _ = correct_netflows[index]["objectid"].pop("guid")
            assert netflow_as_prims == correct_netflows[index]

        # Example 3: 9af570e04b3f8c29f6036566b80fb4db15a6c95020e74b3ca46d666d60e0c21a

        network =  {
            'hosts': [],
            'domains': [
                {'domain': 'crl.sectigo.com', 'ip': ''},
                {'domain': 'microsoft.com', 'ip': ''},
                {'domain': 'google.com', 'ip': ''},
                {'domain': 'xfinity.com', 'ip': ''},
                {'domain': 'linkedin.com', 'ip': ''}, {'domain': 'broadcom.com', 'ip': ''},
                {'domain': 'yahoo.com', 'ip': ''},
                {'domain': 'irs.gov', 'ip': ''},
                {'domain': 'oracle.com', 'ip': ''},
                {'domain': 'verisign.com', 'ip': ''},
                {'domain': 'cisco.com', 'ip': ''}
            ],
            'tcp': [
                {'src': '192.168.0.23', 'sport': 49161, 'dst': '192.0.2.87', 'dport': 80, 'offset': 2295, 'time': 1681236894.454876},
                {'src': '192.168.0.23', 'sport': 49164, 'dst': '192.0.2.47', 'dport': 80, 'offset': 5587, 'time': 1681236894.676448},
                {'src': '192.168.0.23', 'sport': 49167, 'dst': '192.0.2.87', 'dport': 80, 'offset': 8268, 'time': 1681236894.757466},
                {'src': '192.168.0.23', 'sport': 49169, 'dst': '192.0.2.69', 'dport': 80, 'offset': 11353, 'time': 1681236894.970593},
                {'src': '192.168.0.23', 'sport': 49171, 'dst': '192.0.2.80', 'dport': 80, 'offset': 14371, 'time': 1681236895.352653},
                {'src': '192.168.0.23', 'sport': 49177, 'dst': '192.0.2.91', 'dport': 80, 'offset': 17193, 'time': 1681236904.142734},
                {'src': '192.168.0.23', 'sport': 49179, 'dst': '192.0.2.52', 'dport': 80, 'offset': 20368, 'time': 1681236904.850333},
                {'src': '192.168.0.23', 'sport': 49181, 'dst': '192.0.2.248', 'dport': 80, 'offset': 23242, 'time': 1681236905.010919},
                {'src': '192.168.0.23', 'sport': 49182, 'dst': '192.0.2.135', 'dport': 80, 'offset': 25033, 'time': 1681236905.107963},
                {'src': '192.168.0.23', 'sport': 49184, 'dst': '192.0.2.248', 'dport': 80, 'offset': 27721, 'time': 1681236905.183833},
                {'src': '192.168.0.23', 'sport': 49185, 'dst': '192.0.2.135', 'dport': 80, 'offset': 29314, 'time': 1681236905.224961},
                {'src': '192.168.0.23', 'sport': 49206, 'dst': '192.168.0.4', 'dport': 80, 'offset': 32373, 'time': 1681236912.77151},
                {'src': '192.168.0.23', 'sport': 49214, 'dst': '192.168.0.4', 'dport': 80, 'offset': 34626, 'time': 1681236915.904021},
                {'src': '192.168.0.23', 'sport': 49221, 'dst': '192.168.0.4', 'dport': 80, 'offset': 38306, 'time': 1681236917.948759},
                {'src': '192.168.0.23', 'sport': 49224, 'dst': '192.168.0.4', 'dport': 8080, 'offset': 41154, 'time': 1681236917.987778},
                {'src': '192.168.0.23', 'sport': 49226, 'dst': '192.168.0.4', 'dport': 8080, 'offset': 44093, 'time': 1681236918.086288},
                {'src': '192.168.0.23', 'sport': 49232, 'dst': '192.168.0.4', 'dport': 8080, 'offset': 46838, 'time': 1681236920.107651},
                {'src': '192.168.0.23', 'sport': 49236, 'dst': '192.168.0.4', 'dport': 8080, 'offset': 49672, 'time': 1681236922.196139},
                {'src': '192.168.0.23', 'sport': 49240, 'dst': '192.0.2.70', 'dport': 80, 'offset': 52726, 'time': 1681236923.792768},
                {'src': '192.168.0.23', 'sport': 49243, 'dst': '192.168.0.4', 'dport': 8080, 'offset': 55679, 'time': 1681236924.351569},
                {'src': '192.168.0.23', 'sport': 49245, 'dst': '192.168.0.4', 'dport': 8080, 'offset': 58515, 'time': 1681236926.44681},
                {'src': '192.168.0.23', 'sport': 49247, 'dst': '192.168.0.4', 'dport': 8080, 'offset': 61335, 'time': 1681236928.533608},
                {'src': '192.168.0.23', 'sport': 49249, 'dst': '192.168.0.4', 'dport': 8080, 'offset': 64153, 'time': 1681236930.653275},
                {'src': '192.168.0.23', 'sport': 49251, 'dst': '192.168.0.4', 'dport': 8080, 'offset': 66987, 'time': 1681236932.738152},
                {'src': '192.168.0.23', 'sport': 49253, 'dst': '192.168.0.4', 'dport': 8080, 'offset': 69823, 'time': 1681236934.83033},
                {'src': '192.168.0.23', 'sport': 49255, 'dst': '192.0.2.80', 'dport': 80, 'offset': 72461, 'time': 1681237002.995569},
                {'src': '192.168.0.23', 'sport': 49259, 'dst': '192.0.2.170', 'dport': 80, 'offset': 75109, 'time': 1681237070.668603},
                {'src': '192.168.0.23', 'sport': 49261, 'dst': '192.0.2.170', 'dport': 80, 'offset': 77749, 'time': 1681237070.789282}
            ],
            'udp': [
                {'src': '192.168.0.23', 'sport': 58135, 'dst': '192.168.0.4', 'dport': 53, 'offset': 246, 'time': 1681236887.58671},
                {'src': '192.168.0.23', 'sport': 62839, 'dst': '192.168.0.4', 'dport': 53, 'offset': 3649, 'time': 1681236894.508235},
                {'src': '192.168.0.23', 'sport': 53057, 'dst': '192.168.0.4', 'dport': 53, 'offset': 10911, 'time': 1681236894.851074},
                {'src': '192.168.0.23', 'sport': 59585, 'dst': '192.168.0.4', 'dport': 53, 'offset': 13929, 'time': 1681236895.275177},
                {'src': '192.168.0.23', 'sport': 55545, 'dst': '192.168.0.4', 'dport': 53, 'offset': 19928, 'time': 1681236904.214732},
                {'src': '192.168.0.23', 'sport': 55901, 'dst': '192.168.0.4', 'dport': 53, 'offset': 24595, 'time': 1681236905.057781},
                {'src': '192.168.0.23', 'sport': 54716, 'dst': '192.168.0.4', 'dport': 53, 'offset': 31915, 'time': 1681236912.745269},
                {'src': '192.168.0.23', 'sport': 50723, 'dst': '192.168.0.4', 'dport': 53, 'offset': 43665, 'time': 1681236918.032215},
                {'src': '192.168.0.23', 'sport': 60142, 'dst': '192.168.0.4', 'dport': 53, 'offset': 50755, 'time': 1681236922.216916},
                {'src': '192.168.0.23', 'sport': 56854, 'dst': '192.168.0.4', 'dport': 53, 'offset': 55247, 'time': 1681236924.296496},
                {'src': '192.168.0.23', 'sport': 55694, 'dst': '192.168.0.4', 'dport': 53, 'offset': 60913, 'time': 1681236928.483562},
                {'src': '192.168.0.23', 'sport': 53435, 'dst': '192.168.0.4', 'dport': 53, 'offset': 66555, 'time': 1681236932.685878}
            ],
            'icmp': [],
            'http': [
                {'count': 1, 'host': 'crl.sectigo.com', 'port': 80, 'data': 'GET /SectigoPublicCodeSigningRootR46.crl HTTP/1.1\r\nConnection: Keep-Alive\r\nAccept: */*\r\nUser-Agent: Microsoft-CryptoAPI/6.1\r\nHost: crl.sectigo.com\r\n\r\n', 'uri': 'http://crl.sectigo.com/SectigoPublicCodeSigningRootR46.crl', 'body': '', 'path': '/SectigoPublicCodeSigningRootR46.crl', 'user-agent': 'Microsoft-CryptoAPI/6.1', 'version': '1.1', 'method': 'GET'},
                {'count': 1, 'host': 'crl.sectigo.com', 'port': 80, 'data': 'GET /SectigoPublicCodeSigningCAR36.crl HTTP/1.1\r\nConnection: Keep-Alive\r\nAccept: */*\r\nUser-Agent: Microsoft-CryptoAPI/6.1\r\nHost: crl.sectigo.com\r\n\r\n', 'uri': 'http://crl.sectigo.com/SectigoPublicCodeSigningCAR36.crl', 'body': '', 'path': '/SectigoPublicCodeSigningCAR36.crl', 'user-agent': 'Microsoft-CryptoAPI/6.1', 'version': '1.1', 'method': 'GET'},
                {'count': 2, 'host': 'microsoft.com:443', 'port': 8080, 'data': 'CONNECT microsoft.com:443 HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)\r\nHost: microsoft.com:443\r\nContent-Length: 0\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n', 'uri': 'http://microsoft.com:443', 'body': '', 'path': '', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'version': '1.0', 'method': 'CONNECT'},
                {'count': 2, 'host': 'google.com:443', 'port': 8080, 'data': 'CONNECT google.com:443 HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)\r\nHost: google.com:443\r\nContent-Length: 0\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n', 'uri': 'http://google.com:443', 'body': '', 'path': '', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'version': '1.0', 'method': 'CONNECT'},
                {'count': 2, 'host': 'xfinity.com:443', 'port': 8080, 'data': 'CONNECT xfinity.com:443 HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)\r\nHost: xfinity.com:443\r\nContent-Length: 0\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n', 'uri': 'http://xfinity.com:443', 'body': '', 'path': '', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'version': '1.0', 'method': 'CONNECT'},
                {'count': 2, 'host': 'linkedin.com:443', 'port': 8080, 'data': 'CONNECT linkedin.com:443 HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)\r\nHost: linkedin.com:443\r\nContent-Length: 0\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n', 'uri': 'http://linkedin.com:443', 'body': '', 'path': '', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'version': '1.0', 'method': 'CONNECT'},
                {'count': 2, 'host': 'broadcom.com:443', 'port': 8080, 'data': 'CONNECT broadcom.com:443 HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)\r\nHost: broadcom.com:443\r\nContent-Length: 0\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n', 'uri': 'http://broadcom.com:443', 'body': '', 'path': '', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'version': '1.0', 'method': 'CONNECT'},
                {'count': 2, 'host': 'yahoo.com:443', 'port': 8080, 'data': 'CONNECT yahoo.com:443 HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)\r\nHost: yahoo.com:443\r\nContent-Length: 0\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n', 'uri': 'http://yahoo.com:443', 'body': '', 'path': '', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'version': '1.0', 'method': 'CONNECT'},
                {'count': 2, 'host': 'irs.gov:443', 'port': 8080, 'data': 'CONNECT irs.gov:443 HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)\r\nHost: irs.gov:443\r\nContent-Length: 0\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n', 'uri': 'http://irs.gov:443', 'body': '', 'path': '', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'version': '1.0', 'method': 'CONNECT'},
                {'count': 2, 'host': 'oracle.com:443', 'port': 8080, 'data': 'CONNECT oracle.com:443 HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)\r\nHost: oracle.com:443\r\nContent-Length: 0\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n', 'uri': 'http://oracle.com:443', 'body': '', 'path': '', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'version': '1.0', 'method': 'CONNECT'},
                {'count': 2, 'host': 'verisign.com:443', 'port': 8080, 'data': 'CONNECT verisign.com:443 HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)\r\nHost: verisign.com:443\r\nContent-Length: 0\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n', 'uri': 'http://verisign.com:443', 'body': '', 'path': '', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'version': '1.0', 'method': 'CONNECT'},
                {'count': 2, 'host': 'cisco.com:443', 'port': 8080, 'data': 'CONNECT cisco.com:443 HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)\r\nHost: cisco.com:443\r\nContent-Length: 0\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n', 'uri': 'http://cisco.com:443', 'body': '', 'path': '', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'version': '1.0', 'method': 'CONNECT'}
            ],
            'dns': [
                {'request': 'crl.sectigo.com', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.135'}]},
                {'request': 'microsoft.com', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.126'}]},
                {'request': 'google.com', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.31'}]},
                {'request': 'xfinity.com', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.212'}]},
                {'request': 'linkedin.com', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.136'}]},
                {'request': 'broadcom.com', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.40'}]},
                {'request': 'yahoo.com', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.204'}]},
                {'request': 'irs.gov', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.37'}]},
                {'request': 'oracle.com', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.166'}]},
                {'request': 'verisign.com', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.76'}]},
                {'request': 'cisco.com', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.137'}]}
            ],
            'smtp': [],
            'irc': [],
            'dead_hosts': [],
            'http_ex': [
                {'src': '192.168.0.23', 'sport': 49182, 'dst': '192.0.2.135', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'crl.sectigo.com', 'uri': '/SectigoPublicCodeSigningRootR46.crl', 'status': 200, 'request': 'GET /SectigoPublicCodeSigningRootR46.crl HTTP/1.1\r\nConnection: Keep-Alive\r\nAccept: */*\r\nUser-Agent: Microsoft-CryptoAPI/6.1\r\nHost: crl.sectigo.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 11 Apr 2023 18:15:05 GMT', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/243513/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}},
                {'src': '192.168.0.23', 'sport': 49185, 'dst': '192.0.2.135', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'crl.sectigo.com', 'uri': '/SectigoPublicCodeSigningCAR36.crl', 'status': 200, 'request': 'GET /SectigoPublicCodeSigningCAR36.crl HTTP/1.1\r\nConnection: Keep-Alive\r\nAccept: */*\r\nUser-Agent: Microsoft-CryptoAPI/6.1\r\nHost: crl.sectigo.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 11 Apr 2023 18:15:05 GMT', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/243513/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}
            ],
            'https_ex': [],
            'smtp_ex': []
        }
        parent_result_section = ResultSection("blah")
        ontres = OntologyResults(service_name="blah")
        sandbox = ontres.create_sandbox(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), sandbox_name="CAPE")
        ontres.add_sandbox(sandbox)
        process_map = {
            512: {'name': 'C:\\Windows\\System32\\rundll32.exe', 'network_calls': [], 'decrypted_buffers': []},
            1296: {'name': 'C:\\Windows\\System32\\wermgr.exe', 'network_calls': [{'InternetCrackUrlA': {'url': 'https://microsoft.com:443/'}}, {'InternetConnectA': {'service': '3', 'servername': 'microsoft.com', 'serverport': '443'}}, {'GetAddrInfoW': {'nodename': 'wpad'}}, {'GetAddrInfoW': {'nodename': 'microsoft.com'}}, {'InternetCrackUrlA': {'url': 'https://google.com:443/'}}, {'InternetConnectA': {'service': '3', 'serverport': '443'}}, {'InternetCrackUrlA': {'url': 'https://xfinity.com:443/'}}, {'InternetConnectA': {'service': '3', 'servername': 'xfinity.com', 'serverport': '443'}}, {'GetAddrInfoW': {'nodename': 'xfinity.com'}}, {'InternetCrackUrlA': {'url': 'https://linkedin.com:443/'}}, {'InternetConnectA': {'service': '3', 'servername': 'linkedin.com', 'serverport': '443'}}, {'GetAddrInfoW': {'nodename': 'linkedin.com'}}, {'InternetCrackUrlA': {'url': 'https://broadcom.com:443/'}}, {'InternetConnectA': {'service': '3', 'servername': 'broadcom.com', 'serverport': '443'}}, {'GetAddrInfoW': {'nodename': 'broadcom.com'}}, {'InternetCrackUrlA': {'url': 'https://yahoo.com:443/'}}, {'InternetConnectA': {'service': '3', 'servername': 'yahoo.com', 'serverport': '443'}}, {'GetAddrInfoW': {'nodename': 'yahoo.com'}}, {'InternetCrackUrlA': {'url': 'https://irs.gov:443/'}}, {'InternetConnectA': {'service': '3', 'servername': 'irs.gov', 'serverport': '443'}}, {'GetAddrInfoW': {'nodename': 'irs.gov'}}, {'InternetCrackUrlA': {'url': 'https://oracle.com:443/'}}, {'InternetConnectA': {'service': '3', 'servername': 'oracle.com', 'serverport': '443'}}, {'GetAddrInfoW': {'nodename': 'oracle.com'}}, {'InternetCrackUrlA': {'url': 'https://verisign.com:443/'}}, {'InternetCrackUrlA': {'url': 'https://cisco.com:443/'}}, {'InternetConnectA': {'service': '3', 'servername': 'cisco.com', 'serverport': '443'}}, {'GetAddrInfoW': {'nodename': 'cisco.com'}}], 'decrypted_buffers': []}
        }

        correct_result_section = ResultSection("blah")
        correct_network_result_section = ResultSection("Network Activity")

        dns_subsection = ResultTableSection("Protocol: DNS", tags={'network.protocol': ['dns'], 'network.dynamic.domain': ['microsoft.com', 'xfinity.com', 'linkedin.com', 'broadcom.com', 'yahoo.com', 'irs.gov', 'oracle.com', 'cisco.com']})
        dns_subsection.add_row(TableRow({"domain": "microsoft.com", "answer": "192.0.2.126", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "xfinity.com", "answer": "192.0.2.212", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "linkedin.com", "answer": "192.0.2.136", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "broadcom.com", "answer": "192.0.2.40", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "yahoo.com", "answer": "192.0.2.204", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "irs.gov", "answer": "192.0.2.37", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "oracle.com", "answer": "192.0.2.166", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "cisco.com", "answer": "192.0.2.137", "type": "A"}))
        dns_subsection.set_heuristic(1000)

        http_subsection = ResultTableSection("Protocol: HTTP/HTTPS", tags={'network.protocol': ['http'], 'network.dynamic.domain': ['microsoft.com', 'xfinity.com', 'linkedin.com', 'broadcom.com', 'yahoo.com', 'irs.gov', 'oracle.com', 'cisco.com'], 'network.dynamic.uri': ['http://microsoft.com:443', 'http://xfinity.com:443', 'http://linkedin.com:443', 'http://broadcom.com:443', 'http://yahoo.com:443', 'http://irs.gov:443', 'http://oracle.com:443', 'http://cisco.com:443']})
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "CONNECT", "request": {"UserAgent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)", "Host": "microsoft.com:443", "ContentLength": "0", "ProxyConnection": "Keep-Alive", "Pragma": "no-cache"}, "uri": "http://microsoft.com:443"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "CONNECT", "request": {"UserAgent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)", "Host": "xfinity.com:443", "ContentLength": "0", "ProxyConnection": "Keep-Alive", "Pragma": "no-cache"}, "uri": "http://xfinity.com:443"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "CONNECT", "request": {"UserAgent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)", "Host": "linkedin.com:443", "ContentLength": "0", "ProxyConnection": "Keep-Alive", "Pragma": "no-cache"}, "uri": "http://linkedin.com:443"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "CONNECT", "request": {"UserAgent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)", "Host": "broadcom.com:443", "ContentLength": "0", "ProxyConnection": "Keep-Alive", "Pragma": "no-cache"}, "uri": "http://broadcom.com:443"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "CONNECT", "request": {"UserAgent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)", "Host": "yahoo.com:443", "ContentLength": "0", "ProxyConnection": "Keep-Alive", "Pragma": "no-cache"}, "uri": "http://yahoo.com:443"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "CONNECT", "request": {"UserAgent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)", "Host": "irs.gov:443", "ContentLength": "0", "ProxyConnection": "Keep-Alive", "Pragma": "no-cache"}, "uri": "http://irs.gov:443"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "CONNECT", "request": {"UserAgent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)", "Host": "oracle.com:443", "ContentLength": "0", "ProxyConnection": "Keep-Alive", "Pragma": "no-cache"}, "uri": "http://oracle.com:443"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "CONNECT", "request": {"UserAgent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)", "Host": "cisco.com:443", "ContentLength": "0", "ProxyConnection": "Keep-Alive", "Pragma": "no-cache"}, "uri": "http://cisco.com:443"}))
        http_subsection.set_heuristic(1002)

        http_header_ioc_subsection = ResultTableSection("IOCs found in HTTP/HTTPS Headers", tags={'network.dynamic.domain': ['broadcom.com', 'cisco.com', 'irs.gov', 'linkedin.com', 'microsoft.com', 'oracle.com', 'xfinity.com', 'yahoo.com']})
        http_header_ioc_subsection.add_row(TableRow({"ioc_type": "domain", "ioc": "broadcom.com"}))
        http_header_ioc_subsection.add_row(TableRow({"ioc_type": "domain", "ioc": "cisco.com"}))
        http_header_ioc_subsection.add_row(TableRow({"ioc_type": "domain", "ioc": "irs.gov"}))
        http_header_ioc_subsection.add_row(TableRow({"ioc_type": "domain", "ioc": "linkedin.com"}))
        http_header_ioc_subsection.add_row(TableRow({"ioc_type": "domain", "ioc": "microsoft.com"}))
        http_header_ioc_subsection.add_row(TableRow({"ioc_type": "domain", "ioc": "oracle.com"}))
        http_header_ioc_subsection.add_row(TableRow({"ioc_type": "domain", "ioc": "xfinity.com"}))
        http_header_ioc_subsection.add_row(TableRow({"ioc_type": "domain", "ioc": "yahoo.com"}))
        http_subsection.add_subsection(http_header_ioc_subsection)

        correct_network_result_section.add_subsection(dns_subsection)
        correct_network_result_section.add_subsection(http_subsection)

        unseen_subsection = ResultTableSection("Unseen IOCs found in API calls", tags={'network.dynamic.uri': ['https://google.com/', 'https://verisign.com/'], 'network.dynamic.uri_path': ['/']})
        for uri in ["https://google.com/", "https://verisign.com/"]:
            unseen_subsection.add_row(TableRow({"ioc_type": "uri", "ioc": uri}))
        unseen_subsection.set_heuristic(1013)
        correct_network_result_section.add_subsection(unseen_subsection)

        correct_result_section.add_subsection(correct_network_result_section)

        correct_netflows = [
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{3622D059-774A-4EF9-B0C8-532FC23E6F50}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'crl.sectigo.com', 'resolved_ips': ['192.0.2.135'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{E100429A-B64B-4FE5-92C4-422F1F762228}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'microsoft.com', 'resolved_ips': ['192.0.2.126'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{34B30464-218E-4479-A15E-FF5E44A267B6}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'google.com', 'resolved_ips': ['192.0.2.31'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{FEDF2594-1B2A-44D1-B7B3-A9449D5C3648}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'xfinity.com', 'resolved_ips': ['192.0.2.212'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{02ECC30A-4B95-4FE6-906B-16C41D64D045}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'linkedin.com', 'resolved_ips': ['192.0.2.136'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{7F8677C6-EB9F-4606-ABBA-AE35D1CD4A9A}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'broadcom.com', 'resolved_ips': ['192.0.2.40'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{BA39A4D8-E129-467C-B07A-128DDB22A6DC}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'yahoo.com', 'resolved_ips': ['192.0.2.204'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{31D4685B-5B60-409E-BC3B-E45DEDB22F3D}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'irs.gov', 'resolved_ips': ['192.0.2.37'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{2FEE8808-8B2E-4281-A52C-6AE2DF9478D1}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'oracle.com', 'resolved_ips': ['192.0.2.166'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{4DF101B4-83E0-4482-8FA6-89A12B9DDE72}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'verisign.com', 'resolved_ips': ['192.0.2.76'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{4080F751-56B4-4F64-916C-E22CA60A6A6D}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'cisco.com', 'resolved_ips': ['192.0.2.137'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.0.2.126:8080', 'ontology_id': 'network_5p4ftHudCdnVUAj31rdsMI', 'service_name': 'blah', 'guid': None, 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.0.2.126', 'destination_port': 8080, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': {'request_uri': 'http://microsoft.com:443', 'request_method': 'CONNECT', 'request_headers': {'UserAgent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'Host': 'microsoft.com:443', 'ContentLength': '0', 'ProxyConnection': 'Keep-Alive', 'Pragma': 'no-cache'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.212:8080', 'ontology_id': 'network_6jmFGVclkPvkNdl1jV3IKn', 'service_name': 'blah', 'guid': None, 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.0.2.212', 'destination_port': 8080, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': {'request_uri': 'http://xfinity.com:443', 'request_method': 'CONNECT', 'request_headers': {'UserAgent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'Host': 'xfinity.com:443', 'ContentLength': '0', 'ProxyConnection': 'Keep-Alive', 'Pragma': 'no-cache'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.136:8080', 'ontology_id': 'network_1xAEZjQ4BRYVLhkhqnLW7s', 'service_name': 'blah', 'guid': None, 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.0.2.136', 'destination_port': 8080, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': {'request_uri': 'http://linkedin.com:443', 'request_method': 'CONNECT', 'request_headers': {'UserAgent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'Host': 'linkedin.com:443', 'ContentLength': '0', 'ProxyConnection': 'Keep-Alive', 'Pragma': 'no-cache'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.40:8080', 'ontology_id': 'network_4NJE7N2LxXqkmhnOeiyeyJ', 'service_name': 'blah', 'guid': None, 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.0.2.40', 'destination_port': 8080, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': {'request_uri': 'http://broadcom.com:443', 'request_method': 'CONNECT', 'request_headers': {'UserAgent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'Host': 'broadcom.com:443', 'ContentLength': '0', 'ProxyConnection': 'Keep-Alive', 'Pragma': 'no-cache'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.204:8080', 'ontology_id': 'network_6G6qoKNghfhARRjhbuYXvm', 'service_name': 'blah', 'guid': None, 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.0.2.204', 'destination_port': 8080, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': {'request_uri': 'http://yahoo.com:443', 'request_method': 'CONNECT', 'request_headers': {'UserAgent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'Host': 'yahoo.com:443', 'ContentLength': '0', 'ProxyConnection': 'Keep-Alive', 'Pragma': 'no-cache'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.37:8080', 'ontology_id': 'network_2XR4mKi8aVMo7AiRXWBdPb', 'service_name': 'blah', 'guid': None, 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.0.2.37', 'destination_port': 8080, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': {'request_uri': 'http://irs.gov:443', 'request_method': 'CONNECT', 'request_headers': {'UserAgent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'Host': 'irs.gov:443', 'ContentLength': '0', 'ProxyConnection': 'Keep-Alive', 'Pragma': 'no-cache'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.166:8080', 'ontology_id': 'network_3o0sXAgPMLOtY0oyhZNXAt', 'service_name': 'blah', 'guid': None, 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.0.2.166', 'destination_port': 8080, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': {'request_uri': 'http://oracle.com:443', 'request_method': 'CONNECT', 'request_headers': {'UserAgent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'Host': 'oracle.com:443', 'ContentLength': '0', 'ProxyConnection': 'Keep-Alive', 'Pragma': 'no-cache'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.137:8080', 'ontology_id': 'network_7B56MgYJTkA9OI4Axf8Skp', 'service_name': 'blah', 'guid': None, 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.0.2.137', 'destination_port': 8080, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': {'request_uri': 'http://cisco.com:443', 'request_method': 'CONNECT', 'request_headers': {'UserAgent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'Host': 'cisco.com:443', 'ContentLength': '0', 'ProxyConnection': 'Keep-Alive', 'Pragma': 'no-cache'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
        ]

        process_network(network, parent_result_section, inetsim_network, routing, process_map, safelist, ontres, inetsim_dns_servers, False)
        assert check_section_equality(parent_result_section, correct_result_section)

        for index, netflow in enumerate(ontres.netflows):
            # Ignore guids since they are random
            netflow_as_prims = netflow.as_primitives()
            _ = netflow_as_prims["objectid"].pop("guid")
            _ = correct_netflows[index]["objectid"].pop("guid")
            assert netflow_as_prims == correct_netflows[index]

        # Example 4: 6524def57baff2ce300ce270da2428227e82bb8fed432d5bdf926c645c4cb42f

        network = {
            'pcap_sha256': 'db1ff9ef62cc5cc50a7ba37a38a700a08153d8efa7763c58e439ed68a4b3d63d',
            'hosts': [],
            'domains': [{'domain': 'pumyxiv.com', 'ip': ''}, {'domain': 'lysyfyj.com', 'ip': ''}, {'domain': 'galyqaz.com', 'ip': ''}, {'domain': 'vonyzuf.com', 'ip': ''}, {'domain': 'qedyfyq.com', 'ip': ''}, {'domain': 'qekyqop.com', 'ip': ''}, {'domain': 'lymyxid.com', 'ip': ''}, {'domain': 'lyryvex.com', 'ip': ''}, {'domain': 'gadyfuh.com', 'ip': ''}, {'domain': 'vopybyt.com', 'ip': ''}, {'domain': 'puvytuq.com', 'ip': ''}, {'domain': 'volyqat.com', 'ip': ''}, {'domain': 'vofygum.com', 'ip': ''}, {'domain': 'qeqyxov.com', 'ip': ''}, {'domain': 'vowycac.com', 'ip': ''}, {'domain': 'lyxywer.com', 'ip': ''}, {'domain': 'lygygin.com', 'ip': ''}, {'domain': 'gaqycos.com', 'ip': ''}, {'domain': 'qexyryl.com', 'ip': ''}, {'domain': 'vojyjof.com', 'ip': ''}, {'domain': 'gahyhob.com', 'ip': ''}, {'domain': 'qetyvep.com', 'ip': ''}, {'domain': 'qegyhig.com', 'ip': ''}, {'domain': 'vocyruk.com', 'ip': ''}, {'domain': 'qegyqaq.com', 'ip': ''}, {'domain': 'purydyv.com', 'ip': ''}, {'domain': 'lyvytuj.com', 'ip': ''}, {'domain': 'qeqysag.com', 'ip': ''}, {'domain': 'lyxylux.com', 'ip': ''}, {'domain': 'puzywel.com', 'ip': ''}, {'domain': 'gaqydeb.com', 'ip': ''}, {'domain': 'lysynur.com', 'ip': ''}, {'domain': 'vofymik.com', 'ip': ''}, {'domain': 'pufygug.com', 'ip': ''}, {'domain': 'puvyxil.com', 'ip': ''}, {'domain': 'volykyc.com', 'ip': ''}, {'domain': 'pujyjav.com', 'ip': ''}, {'domain': 'qexylup.com', 'ip': ''}, {'domain': 'pufymoq.com', 'ip': ''}, {'domain': 'qebytiq.com', 'ip': ''}, {'domain': 'vowydef.com', 'ip': ''}, {'domain': 'lykyjad.com', 'ip': ''}, {'domain': 'gacyryw.com', 'ip': ''}, {'domain': 'ganypih.com', 'ip': ''}, {'domain': 'pupybul.com', 'ip': ''}, {'domain': 'galykes.com', 'ip': ''}, {'domain': 'qekykev.com', 'ip': ''}, {'domain': 'pumypog.com', 'ip': ''}, {'domain': 'lygymoj.com', 'ip': ''}, {'domain': 'gatyvyz.com', 'ip': ''}, {'domain': 'gacyzuz.com', 'ip': ''}, {'domain': 'vonypom.com', 'ip': ''}, {'domain': 'lyryfyd.com', 'ip': ''}, {'domain': 'vocyzit.com', 'ip': ''}, {'domain': 'purycap.com', 'ip': ''}, {'domain': 'gadyniw.com', 'ip': ''}, {'domain': 'qedynul.com', 'ip': ''}, {'domain': 'lymysan.com', 'ip': ''}, {'domain': 'gahyqah.com', 'ip': ''}, {'domain': 'puzylyp.com', 'ip': ''}, {'domain': 'vojyqem.com', 'ip': ''}, {'domain': 'qetyfuv.com', 'ip': ''}, {'domain': 'gatyfus.com', 'ip': ''}, {'domain': 'lyvyxor.com', 'ip': ''}, {'domain': 'lykymox.com', 'ip': ''}, {'domain': 'ganyzub.com', 'ip': ''}, {'domain': 'pupydeq.com', 'ip': ''}, {'domain': 'vopydek.com', 'ip': ''}, {'domain': 'qebylug.com', 'ip': ''}, {'domain': 'pujymip.com', 'ip': ''}, {'domain': 'gatydaw.com', 'ip': ''}, {'domain': 'lyvylyn.com', 'ip': ''}, {'domain': 'qetysal.com', 'ip': ''}, {'domain': 'puvylyg.com', 'ip': ''}, {'domain': 'gahynus.com', 'ip': ''}, {'domain': 'lyrysor.com', 'ip': ''}, {'domain': 'vocykem.com', 'ip': ''}, {'domain': 'gacykeh.com', 'ip': ''}, {'domain': 'qegynuv.com', 'ip': ''}, {'domain': 'purypol.com', 'ip': ''}, {'domain': 'lygynud.com', 'ip': ''}, {'domain': 'qexykaq.com', 'ip': ''}, {'domain': 'vowypit.com', 'ip': ''}, {'domain': 'lyxyjaj.com', 'ip': ''}, {'domain': 'gaqypiz.com', 'ip': ''}, {'domain': 'pufybyv.com', 'ip': ''}, {'domain': 'vofybyf.com', 'ip': ''}, {'domain': 'puzyjoq.com', 'ip': ''}, {'domain': 'qeqytup.com', 'ip': ''}, {'domain': 'gadyveb.com', 'ip': ''}, {'domain': 'lymytux.com', 'ip': ''}, {'domain': 'volyjok.com', 'ip': ''}, {'domain': 'galyhiw.com', 'ip': ''}, {'domain': 'qedyveg.com', 'ip': ''}, {'domain': 'pumytup.com', 'ip': ''}, {'domain': 'vonyryc.com', 'ip': ''}, {'domain': 'vojymic.com', 'ip': ''}, {'domain': 'lysyvan.com', 'ip': ''}, {'domain': 'pupycag.com', 'ip': ''}, {'domain': 'qekyhil.com', 'ip': ''}, {'domain': 'ganyrys.com', 'ip': ''}, {'domain': 'lykygur.com', 'ip': ''}, {'domain': 'qebyrev.com', 'ip': ''}, {'domain': 'vopycom.com', 'ip': ''}, {'domain': 'pujygul.com', 'ip': ''}, {'domain': 'gatycoh.com', 'ip': ''}, {'domain': 'lyvywed.com', 'ip': ''}, {'domain': 'vojygut.com', 'ip': ''}, {'domain': 'puvywav.com', 'ip': ''}, {'domain': 'gahyfyz.com', 'ip': ''}, {'domain': 'qetyxiq.com', 'ip': ''}, {'domain': 'lyryxij.com', 'ip': ''}, {'domain': 'vocyqaf.com', 'ip': ''}, {'domain': 'qegyfyp.com', 'ip': ''}, {'domain': 'lygyfex.com', 'ip': ''}, {'domain': 'vowyzuk.com', 'ip': ''}, {'domain': 'gacyqob.com', 'ip': ''}, {'domain': 'qexyqog.com', 'ip': ''}, {'domain': 'pufydep.com', 'ip': ''}, {'domain': 'gaqyzuw.com', 'ip': ''}, {'domain': 'puryxuq.com', 'ip': ''}, {'domain': 'lyxymin.com', 'ip': ''}, {'domain': 'qeqylyl.com', 'ip': ''}, {'domain': 'vofydac.com', 'ip': ''}, {'domain': 'puzymig.com', 'ip': ''}, {'domain': 'gadydas.com', 'ip': ''}, {'domain': 'lymylyr.com', 'ip': ''}, {'domain': 'volymum.com', 'ip': ''}, {'domain': 'qedysov.com', 'ip': ''}, {'domain': 'ganyhus.com', 'ip': ''}, {'domain': 'qetyraq.com', 'ip': ''}, {'domain': 'qebyhuv.com', 'ip': ''}, {'domain': 'puzybeq.com', 'ip': ''}, {'domain': 'purywoq.com', 'ip': ''}, {'domain': 'lygyxux.com', 'ip': ''}, {'domain': 'vowyqik.com', 'ip': ''}, {'domain': 'gahycuz.com', 'ip': ''}, {'domain': 'pufyxyp.com', 'ip': ''}, {'domain': 'lymyjix.com', 'ip': ''}, {'domain': 'volybak.com', 'ip': ''}, {'domain': 'vofyzyc.com', 'ip': ''}, {'domain': 'lyxynej.com', 'ip': ''}, {'domain': 'qeqyqul.com', 'ip': ''}, {'domain': 'pumyjip.com', 'ip': ''}, {'domain': 'vocygef.com', 'ip': ''}, {'domain': 'lysytyn.com', 'ip': ''}, {'domain': 'vojycit.com', 'ip': ''}, {'domain': 'puvygyv.com', 'ip': ''}, {'domain': 'qegyxup.com', 'ip': ''}, {'domain': 'lyvygyd.com', 'ip': ''}, {'domain': 'gadypub.com', 'ip': ''}, {'domain': 'qexyfag.com', 'ip': ''}, {'domain': 'lyxyfan.com', 'ip': ''}, {'domain': 'gatyrah.com', 'ip': ''}, {'domain': 'pujycil.com', 'ip': ''}, {'domain': 'lyrywoj.com', 'ip': ''}, {'domain': 'lykyvor.com', 'ip': ''}, {'domain': 'qedytyg.com', 'ip': ''}, {'domain': 'vonyjuc.com', 'ip': ''}, {'domain': 'puzydog.com', 'ip': ''}, {'domain': 'gacyfeb.com', 'ip': ''}, {'domain': 'qekyvol.com', 'ip': ''}, {'domain': 'vopyrem.com', 'ip': ''}, {'domain': 'galyvaw.com', 'ip': ''}, {'domain': 'vofypuf.com', 'ip': ''}, {'domain': 'qeqykop.com', 'ip': ''}, {'domain': 'gaqyqiw.com', 'ip': ''}, {'domain': 'pupyteg.com', 'ip': ''}, {'domain': 'galynuh.com', 'ip': ''}, {'domain': 'pumylel.com', 'ip': ''}, {'domain': 'pupypiv.com', 'ip': ''}, {'domain': 'lykynyj.com', 'ip': ''}, {'domain': 'qekynuq.com', 'ip': ''}, {'domain': 'vojybek.com', 'ip': ''}, {'domain': 'gatypub.com', 'ip': ''}, {'domain': 'qebykap.com', 'ip': ''}, {'domain': 'pujybyq.com', 'ip': ''}, {'domain': 'ganykaz.com', 'ip': ''}, {'domain': 'vonyket.com', 'ip': ''}, {'domain': 'lysysod.com', 'ip': ''}, {'domain': 'vopypif.com', 'ip': ''}, {'domain': 'pufycol.com', 'ip': ''}, {'domain': 'lyvyjox.com', 'ip': ''}, {'domain': 'lyxygud.com', 'ip': ''}, {'domain': 'gaqyreh.com', 'ip': ''}, {'domain': 'qexyhuv.com', 'ip': ''}, {'domain': 'lygyvar.com', 'ip': ''}, {'domain': 'qetytug.com', 'ip': ''}, {'domain': 'vowyrym.com', 'ip': ''}, {'domain': 'gacyhis.com', 'ip': ''}, {'domain': 'gahyvew.com', 'ip': ''}, {'domain': 'qegysoq.com', 'ip': ''}, {'domain': 'puvyjop.com', 'ip': ''}, {'domain': 'vocyjic.com', 'ip': ''}, {'domain': 'qegyval.com', 'ip': ''}, {'domain': 'lyrytun.com', 'ip': ''}, {'domain': 'pufypiq.com', 'ip': ''}, {'domain': 'puvymul.com', 'ip': ''}, {'domain': 'gaqykab.com', 'ip': ''}, {'domain': 'qexynyp.com', 'ip': ''}, {'domain': 'lyxynyx.com', 'ip': ''}, {'domain': 'lygysij.com', 'ip': ''}, {'domain': 'purylev.com', 'ip': ''}, {'domain': 'purytyg.com', 'ip': ''}, {'domain': 'gacynuz.com', 'ip': ''}, {'domain': 'vocymut.com', 'ip': ''}, {'domain': 'lyryled.com', 'ip': ''}, {'domain': 'gahydoh.com', 'ip': ''}, {'domain': 'qetylyv.com', 'ip': ''}, {'domain': 'vojydam.com', 'ip': ''}, {'domain': 'gatyzys.com', 'ip': ''}, {'domain': 'pujydag.com', 'ip': ''}, {'domain': 'qekyfeg.com', 'ip': ''}, {'domain': 'vopyzuc.com', 'ip': ''}, {'domain': 'lykyfen.com', 'ip': ''}, {'domain': 'qebyqil.com', 'ip': ''}, {'domain': 'ganyqow.com', 'ip': ''}, {'domain': 'pupyxup.com', 'ip': ''}, {'domain': 'galyfyb.com', 'ip': ''}, {'domain': 'vonyqok.com', 'ip': ''}, {'domain': 'lysyxux.com', 'ip': ''}, {'domain': 'pumywaq.com', 'ip': ''}, {'domain': 'qedyxip.com', 'ip': ''}, {'domain': 'volygyf.com', 'ip': ''}, {'domain': 'lymywaj.com', 'ip': ''}, {'domain': 'puzyguv.com', 'ip': ''}, {'domain': 'gadyciz.com', 'ip': ''}, {'domain': 'qeqyreq.com', 'ip': ''}, {'domain': 'vofycot.com', 'ip': ''}, {'domain': 'vowykaf.com', 'ip': ''}, {'domain': 'lyvymir.com', 'ip': ''}],
            'tcp': [{'src': '192.168.0.9', 'dst': '192.0.2.80', 'time': '2023-04-18 18:04:58', 'dport': 80, 'sport': 50219, 'guid': '{61a591c8-db48-643e-ce02-000000002200}', 'pid': 5080, 'image': 'C:\\Windows\\SMaster64.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.42', 'time': '2023-04-18 18:04:58', 'dport': 80, 'sport': 50218, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.85', 'time': '2023-04-18 18:03:44.000', 'dport': 80, 'sport': 50217, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.181', 'time': '2023-04-18 18:03:44.000', 'dport': 80, 'sport': 50216, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.80', 'time': '2023-04-18 18:03:44.000', 'dport': 80, 'sport': 50215, 'guid': '{61a591c8-db48-643e-ce02-000000002200}', 'pid': 5080, 'image': 'C:\\Windows\\SMaster64.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.42', 'time': '2023-04-18 18:03:32', 'dport': 80, 'sport': 50134, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.42', 'time': '2023-04-18 18:03:32', 'dport': 80, 'sport': 50133, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.42', 'time': '2023-04-18 18:03:32', 'dport': 80, 'sport': 50129, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.57', 'time': '2023-04-18 18:03:04.000', 'dport': 80, 'sport': 50126, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.125', 'time': '2023-04-18 18:03:04.000', 'dport': 80, 'sport': 50124, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.131', 'time': '2023-04-18 18:03:04.000', 'dport': 80, 'sport': 50122, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.217', 'time': '2023-04-18 18:03:04.000', 'dport': 80, 'sport': 50120, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.246', 'time': '2023-04-18 18:03:04.000', 'dport': 80, 'sport': 50118, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.91', 'time': '2023-04-18 18:03:04.000', 'dport': 80, 'sport': 50116, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.139', 'time': '2023-04-18 18:03:04.000', 'dport': 80, 'sport': 50114, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.120', 'time': '2023-04-18 18:03:04.000', 'dport': 80, 'sport': 50112, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.208', 'time': '2023-04-18 18:03:04.000', 'dport': 80, 'sport': 50110, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.200', 'time': '2023-04-18 18:03:04.000', 'dport': 80, 'sport': 50108, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.178', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50106, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.162', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50104, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.203', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50102, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.28', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50100, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.254', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50098, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.198', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50096, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.173', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50094, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.67', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50092, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.57', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50090, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.19', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50088, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.43', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50086, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.6', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50084, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.153', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50082, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.67', 'time': '2023-04-18 18:03:03.000', 'dport': 80, 'sport': 50080, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.18', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50078, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.94', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50076, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.54', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50074, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.155', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50072, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.219', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50070, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.33', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50068, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.99', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50066, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.78', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50064, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.85', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50062, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.167', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50060, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.34', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50058, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.212', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50056, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.251', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50054, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.43', 'time': '2023-04-18 18:03:02.000', 'dport': 80, 'sport': 50052, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.60', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50050, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.25', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50048, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.28', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50046, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.172', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50044, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.133', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50042, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.106', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50040, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.92', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50038, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.167', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50036, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.44', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50034, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.82', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50032, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.92', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50030, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.13', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50028, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.172', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50026, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.45', 'time': '2023-04-18 18:03:01.000', 'dport': 80, 'sport': 50024, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.15', 'time': '2023-04-18 18:03:00.000', 'dport': 80, 'sport': 50022, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.124', 'time': '2023-04-18 18:03:00.000', 'dport': 80, 'sport': 50020, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.153', 'time': '2023-04-18 18:03:00.000', 'dport': 80, 'sport': 50018, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.240', 'time': '2023-04-18 18:03:00.000', 'dport': 80, 'sport': 50016, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.74', 'time': '2023-04-18 18:03:00.000', 'dport': 80, 'sport': 50014, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.238', 'time': '2023-04-18 18:03:00.000', 'dport': 80, 'sport': 50012, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.232', 'time': '2023-04-18 18:03:00.000', 'dport': 80, 'sport': 50010, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.123', 'time': '2023-04-18 18:03:00.000', 'dport': 80, 'sport': 50008, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.192', 'time': '2023-04-18 18:03:00.000', 'dport': 80, 'sport': 50006, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.58', 'time': '2023-04-18 18:03:00.000', 'dport': 80, 'sport': 50004, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.84', 'time': '2023-04-18 18:03:00.000', 'dport': 80, 'sport': 50002, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.254', 'time': '2023-04-18 18:02:59', 'dport': 80, 'sport': 50000, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.42', 'time': '2023-04-18 18:02:59', 'dport': 80, 'sport': 49999, 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.170', 'time': '2023-04-18 18:02:50', 'dport': 80, 'sport': 49985, 'guid': '{61a591c8-db48-643e-ce02-000000002200}', 'pid': 5080, 'image': 'C:\\Windows\\SMaster64.exe'}, {'src': '192.168.0.9', 'dst': '192.0.2.80', 'time': '2023-04-18 18:02:49', 'dport': 80, 'sport': 49982, 'guid': '{61a591c8-db48-643e-ce02-000000002200}', 'pid': 5080, 'image': 'C:\\Windows\\SMaster64.exe'}],
            'udp': [{'src': '192.168.0.9', 'sport': 62614, 'dst': '192.168.0.4', 'dport': 53, 'offset': 24, 'time': 1681840971.272848}, {'src': '192.168.0.9', 'sport': 61782, 'dst': '192.168.0.4', 'dport': 53, 'offset': 1520, 'time': 1681840971.881088}, {'src': '192.168.0.9', 'sport': 51158, 'dst': '192.168.0.4', 'dport': 53, 'offset': 3040, 'time': 1681840973.791206}, {'src': '192.168.0.9', 'sport': 54823, 'dst': '192.168.0.4', 'dport': 53, 'offset': 3271, 'time': 1681840973.919662}, {'src': '192.168.0.9', 'sport': 54954, 'dst': '192.168.0.4', 'dport': 53, 'offset': 3371, 'time': 1681840973.919714}, {'src': '192.168.0.9', 'sport': 63254, 'dst': '192.168.0.4', 'dport': 53, 'offset': 3731, 'time': 1681840981.305239}, {'src': '192.168.0.9', 'sport': 61531, 'dst': '192.168.0.4', 'dport': 53, 'offset': 4437, 'time': 1681840981.703215}, {'src': '192.168.0.9', 'sport': 58914, 'dst': '192.168.0.4', 'dport': 53, 'offset': 4524, 'time': 1681840981.703216}, {'src': '192.168.0.9', 'sport': 58760, 'dst': '192.168.0.4', 'dport': 53, 'offset': 4611, 'time': 1681840981.703815}, {'src': '192.168.0.9', 'sport': 55343, 'dst': '192.168.0.4', 'dport': 53, 'offset': 4698, 'time': 1681840981.704679}, {'src': '192.168.0.9', 'sport': 65484, 'dst': '192.168.0.4', 'dport': 53, 'offset': 4785, 'time': 1681840981.705537}, {'src': '192.168.0.9', 'sport': 49512, 'dst': '192.168.0.4', 'dport': 53, 'offset': 4872, 'time': 1681840981.705538}, {'src': '192.168.0.9', 'sport': 60271, 'dst': '192.168.0.4', 'dport': 53, 'offset': 4959, 'time': 1681840981.707336}, {'src': '192.168.0.9', 'sport': 63771, 'dst': '192.168.0.4', 'dport': 53, 'offset': 5046, 'time': 1681840981.710219}, {'src': '192.168.0.9', 'sport': 63231, 'dst': '192.168.0.4', 'dport': 53, 'offset': 5133, 'time': 1681840981.713189}, {'src': '192.168.0.9', 'sport': 52937, 'dst': '192.168.0.4', 'dport': 53, 'offset': 5220, 'time': 1681840981.7367}, {'src': '192.168.0.9', 'sport': 63827, 'dst': '192.168.0.4', 'dport': 53, 'offset': 5307, 'time': 1681840981.736902}, {'src': '192.168.0.9', 'sport': 52326, 'dst': '192.168.0.4', 'dport': 53, 'offset': 5394, 'time': 1681840981.738509}, {'src': '192.168.0.9', 'sport': 50960, 'dst': '192.168.0.4', 'dport': 53, 'offset': 7029, 'time': 1681840981.80475}, {'src': '192.168.0.9', 'sport': 58131, 'dst': '192.168.0.4', 'dport': 53, 'offset': 8278, 'time': 1681840981.888602}, {'src': '192.168.0.9', 'sport': 65193, 'dst': '192.168.0.4', 'dport': 53, 'offset': 8903, 'time': 1681840981.891977}, {'src': '192.168.0.9', 'sport': 58506, 'dst': '192.168.0.4', 'dport': 53, 'offset': 9130, 'time': 1681840981.903441}, {'src': '192.168.0.9', 'sport': 49773, 'dst': '192.168.0.4', 'dport': 53, 'offset': 9217, 'time': 1681840981.90671}, {'src': '192.168.0.9', 'sport': 64872, 'dst': '192.168.0.4', 'dport': 53, 'offset': 9304, 'time': 1681840981.911658}, {'src': '192.168.0.9', 'sport': 52496, 'dst': '192.168.0.4', 'dport': 53, 'offset': 9391, 'time': 1681840981.913604}, {'src': '192.168.0.9', 'sport': 53090, 'dst': '192.168.0.4', 'dport': 53, 'offset': 9478, 'time': 1681840981.916062}, {'src': '192.168.0.9', 'sport': 58466, 'dst': '192.168.0.4', 'dport': 53, 'offset': 9565, 'time': 1681840981.927528}, {'src': '192.168.0.9', 'sport': 58523, 'dst': '192.168.0.4', 'dport': 53, 'offset': 9652, 'time': 1681840981.930664}, {'src': '192.168.0.9', 'sport': 55244, 'dst': '192.168.0.4', 'dport': 53, 'offset': 9739, 'time': 1681840981.932404}, {'src': '192.168.0.9', 'sport': 52242, 'dst': '192.168.0.4', 'dport': 53, 'offset': 9826, 'time': 1681840981.93484}, {'src': '192.168.0.9', 'sport': 53096, 'dst': '192.168.0.4', 'dport': 53, 'offset': 9913, 'time': 1681840981.938375}, {'src': '192.168.0.9', 'sport': 59029, 'dst': '192.168.0.4', 'dport': 53, 'offset': 10000, 'time': 1681840981.940305}, {'src': '192.168.0.9', 'sport': 62110, 'dst': '192.168.0.4', 'dport': 53, 'offset': 10087, 'time': 1681840981.944233}, {'src': '192.168.0.9', 'sport': 61269, 'dst': '192.168.0.4', 'dport': 53, 'offset': 10174, 'time': 1681840981.945584}, {'src': '192.168.0.9', 'sport': 61419, 'dst': '192.168.0.4', 'dport': 53, 'offset': 10364, 'time': 1681840981.949477}, {'src': '192.168.0.9', 'sport': 54741, 'dst': '192.168.0.4', 'dport': 53, 'offset': 10685, 'time': 1681840981.954461}, {'src': '192.168.0.9', 'sport': 64876, 'dst': '192.168.0.4', 'dport': 53, 'offset': 11155, 'time': 1681840981.957387}, {'src': '192.168.0.9', 'sport': 51578, 'dst': '192.168.0.4', 'dport': 53, 'offset': 11242, 'time': 1681840981.957461}, {'src': '192.168.0.9', 'sport': 55939, 'dst': '192.168.0.4', 'dport': 53, 'offset': 11329, 'time': 1681840981.961251}, {'src': '192.168.0.9', 'sport': 61417, 'dst': '192.168.0.4', 'dport': 53, 'offset': 11416, 'time': 1681840981.965027}, {'src': '192.168.0.9', 'sport': 61440, 'dst': '192.168.0.4', 'dport': 53, 'offset': 12471, 'time': 1681840981.987541}, {'src': '192.168.0.9', 'sport': 62284, 'dst': '192.168.0.4', 'dport': 53, 'offset': 12558, 'time': 1681840981.989505}, {'src': '192.168.0.9', 'sport': 49649, 'dst': '192.168.0.4', 'dport': 53, 'offset': 12645, 'time': 1681840981.992738}, {'src': '192.168.0.9', 'sport': 51464, 'dst': '192.168.0.4', 'dport': 53, 'offset': 12732, 'time': 1681840981.999391}, {'src': '192.168.0.9', 'sport': 60777, 'dst': '192.168.0.4', 'dport': 53, 'offset': 12819, 'time': 1681840982.000779}, {'src': '192.168.0.9', 'sport': 62866, 'dst': '192.168.0.4', 'dport': 53, 'offset': 12906, 'time': 1681840982.004548}, {'src': '192.168.0.9', 'sport': 50257, 'dst': '192.168.0.4', 'dport': 53, 'offset': 12993, 'time': 1681840982.006435}, {'src': '192.168.0.9', 'sport': 50883, 'dst': '192.168.0.4', 'dport': 53, 'offset': 13080, 'time': 1681840982.009498}, {'src': '192.168.0.9', 'sport': 57070, 'dst': '192.168.0.4', 'dport': 53, 'offset': 13167, 'time': 1681840982.009796}, {'src': '192.168.0.9', 'sport': 61477, 'dst': '192.168.0.4', 'dport': 53, 'offset': 13254, 'time': 1681840982.012289}, {'src': '192.168.0.9', 'sport': 60012, 'dst': '192.168.0.4', 'dport': 53, 'offset': 13341, 'time': 1681840982.012972}, {'src': '192.168.0.9', 'sport': 55947, 'dst': '192.168.0.4', 'dport': 53, 'offset': 13428, 'time': 1681840982.013522}, {'src': '192.168.0.9', 'sport': 61698, 'dst': '192.168.0.4', 'dport': 53, 'offset': 13515, 'time': 1681840982.014839}, {'src': '192.168.0.9', 'sport': 63390, 'dst': '192.168.0.4', 'dport': 53, 'offset': 13602, 'time': 1681840982.01684}, {'src': '192.168.0.9', 'sport': 59315, 'dst': '192.168.0.4', 'dport': 53, 'offset': 13689, 'time': 1681840982.017159}, {'src': '192.168.0.9', 'sport': 51986, 'dst': '192.168.0.4', 'dport': 53, 'offset': 13879, 'time': 1681840982.021188}, {'src': '192.168.0.9', 'sport': 56363, 'dst': '192.168.0.4', 'dport': 53, 'offset': 14200, 'time': 1681840982.02439}, {'src': '192.168.0.9', 'sport': 52426, 'dst': '192.168.0.4', 'dport': 53, 'offset': 14670, 'time': 1681840982.024702}, {'src': '192.168.0.9', 'sport': 49921, 'dst': '192.168.0.4', 'dport': 53, 'offset': 14757, 'time': 1681840982.025231}, {'src': '192.168.0.9', 'sport': 54761, 'dst': '192.168.0.4', 'dport': 53, 'offset': 14844, 'time': 1681840982.026377}, {'src': '192.168.0.9', 'sport': 57464, 'dst': '192.168.0.4', 'dport': 53, 'offset': 14931, 'time': 1681840982.027369}, {'src': '192.168.0.9', 'sport': 56342, 'dst': '192.168.0.4', 'dport': 53, 'offset': 15018, 'time': 1681840982.029402}, {'src': '192.168.0.9', 'sport': 63936, 'dst': '192.168.0.4', 'dport': 53, 'offset': 15105, 'time': 1681840982.030775}, {'src': '192.168.0.9', 'sport': 62884, 'dst': '192.168.0.4', 'dport': 53, 'offset': 15192, 'time': 1681840982.031394}, {'src': '192.168.0.9', 'sport': 51300, 'dst': '192.168.0.4', 'dport': 53, 'offset': 15279, 'time': 1681840982.032823}, {'src': '192.168.0.9', 'sport': 49828, 'dst': '192.168.0.4', 'dport': 53, 'offset': 15366, 'time': 1681840982.033847}, {'src': '192.168.0.9', 'sport': 57334, 'dst': '192.168.0.4', 'dport': 53, 'offset': 15453, 'time': 1681840982.035035}, {'src': '192.168.0.9', 'sport': 60383, 'dst': '192.168.0.4', 'dport': 53, 'offset': 15540, 'time': 1681840982.038882}, {'src': '192.168.0.9', 'sport': 59284, 'dst': '192.168.0.4', 'dport': 53, 'offset': 15627, 'time': 1681840982.040918}, {'src': '192.168.0.9', 'sport': 63288, 'dst': '192.168.0.4', 'dport': 53, 'offset': 15714, 'time': 1681840982.04092}, {'src': '192.168.0.9', 'sport': 50270, 'dst': '192.168.0.4', 'dport': 53, 'offset': 16489, 'time': 1681840982.042662}, {'src': '192.168.0.9', 'sport': 52773, 'dst': '192.168.0.4', 'dport': 53, 'offset': 30412, 'time': 1681840982.80341}, {'src': '192.168.0.9', 'sport': 56358, 'dst': '192.168.0.4', 'dport': 53, 'offset': 30512, 'time': 1681840982.803411}, {'src': '192.168.0.9', 'sport': 58917, 'dst': '192.168.0.4', 'dport': 53, 'offset': 30612, 'time': 1681840982.803439}, {'src': '192.168.0.9', 'sport': 58942, 'dst': '192.168.0.4', 'dport': 53, 'offset': 30711, 'time': 1681840982.803439}, {'src': '192.168.0.9', 'sport': 53280, 'dst': '192.168.0.4', 'dport': 53, 'offset': 30811, 'time': 1681840982.803481}, {'src': '192.168.0.9', 'sport': 60056, 'dst': '192.168.0.4', 'dport': 53, 'offset': 30911, 'time': 1681840982.803496}, {'src': '192.168.0.9', 'sport': 53128, 'dst': '192.168.0.4', 'dport': 53, 'offset': 31010, 'time': 1681840982.803917}, {'src': '192.168.0.9', 'sport': 49280, 'dst': '192.168.0.4', 'dport': 53, 'offset': 31110, 'time': 1681840982.803985}, {'src': '192.168.0.9', 'sport': 51992, 'dst': '192.168.0.4', 'dport': 53, 'offset': 31209, 'time': 1681840982.80401}, {'src': '192.168.0.9', 'sport': 57850, 'dst': '192.168.0.4', 'dport': 53, 'offset': 31309, 'time': 1681840982.804157}, {'src': '192.168.0.9', 'sport': 60508, 'dst': '192.168.0.4', 'dport': 53, 'offset': 60388, 'time': 1681840983.80299}, {'src': '192.168.0.9', 'sport': 64235, 'dst': '192.168.0.4', 'dport': 53, 'offset': 60487, 'time': 1681840983.804468}, {'src': '192.168.0.9', 'sport': 57623, 'dst': '192.168.0.4', 'dport': 53, 'offset': 60586, 'time': 1681840983.804467}, {'src': '192.168.0.9', 'sport': 64021, 'dst': '192.168.0.4', 'dport': 53, 'offset': 60686, 'time': 1681840983.804602}, {'src': '192.168.0.9', 'sport': 56105, 'dst': '192.168.0.4', 'dport': 53, 'offset': 60786, 'time': 1681840983.804668}, {'src': '192.168.0.9', 'sport': 50570, 'dst': '192.168.0.4', 'dport': 53, 'offset': 60885, 'time': 1681840983.804689}, {'src': '192.168.0.9', 'sport': 55409, 'dst': '192.168.0.4', 'dport': 53, 'offset': 60984, 'time': 1681840983.804817}, {'src': '192.168.0.9', 'sport': 50094, 'dst': '192.168.0.4', 'dport': 53, 'offset': 61083, 'time': 1681840983.805246}, {'src': '192.168.0.9', 'sport': 55234, 'dst': '192.168.0.4', 'dport': 53, 'offset': 61183, 'time': 1681840983.805247}, {'src': '192.168.0.9', 'sport': 59986, 'dst': '192.168.0.4', 'dport': 53, 'offset': 61282, 'time': 1681840983.805246}, {'src': '192.168.0.9', 'sport': 57552, 'dst': '192.168.0.4', 'dport': 53, 'offset': 61382, 'time': 1681840983.805256}, {'src': '192.168.0.9', 'sport': 61578, 'dst': '192.168.0.4', 'dport': 53, 'offset': 61482, 'time': 1681840983.805321}, {'src': '192.168.0.9', 'sport': 59635, 'dst': '192.168.0.4', 'dport': 53, 'offset': 61581, 'time': 1681840983.805381}, {'src': '192.168.0.9', 'sport': 63389, 'dst': '192.168.0.4', 'dport': 53, 'offset': 91673, 'time': 1681840984.819302}, {'src': '192.168.0.9', 'sport': 58576, 'dst': '192.168.0.4', 'dport': 53, 'offset': 91872, 'time': 1681840984.819441}, {'src': '192.168.0.9', 'sport': 58130, 'dst': '192.168.0.4', 'dport': 53, 'offset': 92170, 'time': 1681840984.819445}, {'src': '192.168.0.9', 'sport': 52241, 'dst': '192.168.0.4', 'dport': 53, 'offset': 92270, 'time': 1681840984.819477}, {'src': '192.168.0.9', 'sport': 52373, 'dst': '192.168.0.4', 'dport': 53, 'offset': 92369, 'time': 1681840984.820488}, {'src': '192.168.0.9', 'sport': 49698, 'dst': '192.168.0.4', 'dport': 53, 'offset': 92468, 'time': 1681840984.820489}, {'src': '192.168.0.9', 'sport': 58916, 'dst': '192.168.0.4', 'dport': 53, 'offset': 92567, 'time': 1681840984.820519}, {'src': '192.168.0.9', 'sport': 56022, 'dst': '192.168.0.4', 'dport': 53, 'offset': 92667, 'time': 1681840984.820523}, {'src': '192.168.0.9', 'sport': 61543, 'dst': '192.168.0.4', 'dport': 53, 'offset': 92766, 'time': 1681840984.820551}, {'src': '192.168.0.9', 'sport': 55814, 'dst': '192.168.0.4', 'dport': 53, 'offset': 92865, 'time': 1681840984.820552}, {'src': '192.168.0.9', 'sport': 62089, 'dst': '192.168.0.4', 'dport': 53, 'offset': 92965, 'time': 1681840984.820686}, {'src': '192.168.0.9', 'sport': 64777, 'dst': '192.168.0.4', 'dport': 53, 'offset': 93064, 'time': 1681840984.820992}, {'src': '192.168.0.9', 'sport': 51617, 'dst': '192.168.0.4', 'dport': 53, 'offset': 93163, 'time': 1681840984.821187}, {'src': '192.168.0.9', 'sport': 60348, 'dst': '192.168.0.4', 'dport': 53, 'offset': 93362, 'time': 1681840984.821187}, {'src': '192.168.0.9', 'sport': 61365, 'dst': '192.168.0.4', 'dport': 53, 'offset': 117947, 'time': 1681840985.818664}, {'src': '192.168.0.9', 'sport': 64422, 'dst': '192.168.0.4', 'dport': 53, 'offset': 118046, 'time': 1681840985.818723}, {'src': '192.168.0.9', 'sport': 50273, 'dst': '192.168.0.4', 'dport': 53, 'offset': 118144, 'time': 1681840985.819114}, {'src': '192.168.0.9', 'sport': 62038, 'dst': '192.168.0.4', 'dport': 53, 'offset': 118244, 'time': 1681840985.819259}, {'src': '192.168.0.9', 'sport': 57458, 'dst': '192.168.0.4', 'dport': 53, 'offset': 118344, 'time': 1681840985.819265}, {'src': '192.168.0.9', 'sport': 59526, 'dst': '192.168.0.4', 'dport': 53, 'offset': 118443, 'time': 1681840985.819265}, {'src': '192.168.0.9', 'sport': 50889, 'dst': '192.168.0.4', 'dport': 53, 'offset': 118542, 'time': 1681840985.819556}, {'src': '192.168.0.9', 'sport': 63291, 'dst': '192.168.0.4', 'dport': 53, 'offset': 118642, 'time': 1681840985.81958}, {'src': '192.168.0.9', 'sport': 61288, 'dst': '192.168.0.4', 'dport': 53, 'offset': 136359, 'time': 1681840986.612552}, {'src': '192.168.0.9', 'sport': 51846, 'dst': '192.168.0.4', 'dport': 53, 'offset': 136577, 'time': 1681840986.720197}, {'src': '192.168.0.9', 'sport': 57068, 'dst': '192.168.0.4', 'dport': 53, 'offset': 139714, 'time': 1681840986.834687}, {'src': '192.168.0.9', 'sport': 59935, 'dst': '192.168.0.4', 'dport': 53, 'offset': 139814, 'time': 1681840986.834715}, {'src': '192.168.0.9', 'sport': 50449, 'dst': '192.168.0.4', 'dport': 53, 'offset': 139914, 'time': 1681840986.834735}, {'src': '192.168.0.9', 'sport': 49197, 'dst': '192.168.0.4', 'dport': 53, 'offset': 140014, 'time': 1681840986.834945}, {'src': '192.168.0.9', 'sport': 53565, 'dst': '192.168.0.4', 'dport': 53, 'offset': 140114, 'time': 1681840986.834964}, {'src': '192.168.0.9', 'sport': 61396, 'dst': '192.168.0.4', 'dport': 53, 'offset': 140214, 'time': 1681840986.835086}, {'src': '192.168.0.9', 'sport': 54227, 'dst': '192.168.0.4', 'dport': 53, 'offset': 140313, 'time': 1681840986.835484}, {'src': '192.168.0.9', 'sport': 52064, 'dst': '192.168.0.4', 'dport': 53, 'offset': 140413, 'time': 1681840986.835646}, {'src': '192.168.0.9', 'sport': 52297, 'dst': '192.168.0.4', 'dport': 53, 'offset': 140513, 'time': 1681840986.835892}, {'src': '192.168.0.9', 'sport': 52196, 'dst': '192.168.0.4', 'dport': 53, 'offset': 140613, 'time': 1681840986.912051}, {'src': '192.168.0.9', 'sport': 53674, 'dst': '192.168.0.4', 'dport': 53, 'offset': 140839, 'time': 1681840986.914142}, {'src': '192.168.0.9', 'sport': 58413, 'dst': '192.168.0.4', 'dport': 53, 'offset': 140939, 'time': 1681840986.914783}, {'src': '192.168.0.9', 'sport': 53417, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141026, 'time': 1681840986.915326}, {'src': '192.168.0.9', 'sport': 50429, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141113, 'time': 1681840986.916211}, {'src': '192.168.0.9', 'sport': 58061, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141200, 'time': 1681840986.917047}, {'src': '192.168.0.9', 'sport': 63056, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141287, 'time': 1681840986.917979}, {'src': '192.168.0.9', 'sport': 62953, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141374, 'time': 1681840986.918773}, {'src': '192.168.0.9', 'sport': 62131, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141461, 'time': 1681840986.919434}, {'src': '192.168.0.9', 'sport': 56853, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141548, 'time': 1681840986.920112}, {'src': '192.168.0.9', 'sport': 64784, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141635, 'time': 1681840986.921385}, {'src': '192.168.0.9', 'sport': 64935, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141722, 'time': 1681840986.921753}, {'src': '192.168.0.9', 'sport': 50367, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141809, 'time': 1681840986.922935}, {'src': '192.168.0.9', 'sport': 65444, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141896, 'time': 1681840986.923442}, {'src': '192.168.0.9', 'sport': 59347, 'dst': '192.168.0.4', 'dport': 53, 'offset': 141983, 'time': 1681840986.924973}, {'src': '192.168.0.9', 'sport': 51238, 'dst': '192.168.0.4', 'dport': 53, 'offset': 142070, 'time': 1681840986.925143}, {'src': '192.168.0.9', 'sport': 64572, 'dst': '192.168.0.4', 'dport': 53, 'offset': 142157, 'time': 1681840986.925786}, {'src': '192.168.0.9', 'sport': 62897, 'dst': '192.168.0.4', 'dport': 53, 'offset': 142244, 'time': 1681840986.926578}, {'src': '192.168.0.9', 'sport': 55257, 'dst': '192.168.0.4', 'dport': 53, 'offset': 142331, 'time': 1681840986.928041}, {'src': '192.168.0.9', 'sport': 63733, 'dst': '192.168.0.4', 'dport': 53, 'offset': 142418, 'time': 1681840986.928497}, {'src': '192.168.0.9', 'sport': 57740, 'dst': '192.168.0.4', 'dport': 53, 'offset': 142505, 'time': 1681840986.92879}, {'src': '192.168.0.9', 'sport': 58251, 'dst': '192.168.0.4', 'dport': 53, 'offset': 142592, 'time': 1681840986.929803}, {'src': '192.168.0.9', 'sport': 65384, 'dst': '192.168.0.4', 'dport': 53, 'offset': 142679, 'time': 1681840986.93093}, {'src': '192.168.0.9', 'sport': 53844, 'dst': '192.168.0.4', 'dport': 53, 'offset': 142766, 'time': 1681840986.931344}, {'src': '192.168.0.9', 'sport': 62229, 'dst': '192.168.0.4', 'dport': 53, 'offset': 142853, 'time': 1681840986.932911}, {'src': '192.168.0.9', 'sport': 55000, 'dst': '192.168.0.4', 'dport': 53, 'offset': 142940, 'time': 1681840986.933936}, {'src': '192.168.0.9', 'sport': 63664, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143027, 'time': 1681840986.934602}, {'src': '192.168.0.9', 'sport': 49541, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143114, 'time': 1681840986.93516}, {'src': '192.168.0.9', 'sport': 56090, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143201, 'time': 1681840986.936942}, {'src': '192.168.0.9', 'sport': 65239, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143288, 'time': 1681840986.936953}, {'src': '192.168.0.9', 'sport': 62588, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143375, 'time': 1681840986.937497}, {'src': '192.168.0.9', 'sport': 63914, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143462, 'time': 1681840986.938728}, {'src': '192.168.0.9', 'sport': 52853, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143549, 'time': 1681840986.93913}, {'src': '192.168.0.9', 'sport': 52336, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143636, 'time': 1681840986.939799}, {'src': '192.168.0.9', 'sport': 55229, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143723, 'time': 1681840986.940051}, {'src': '192.168.0.9', 'sport': 52192, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143810, 'time': 1681840986.940548}, {'src': '192.168.0.9', 'sport': 58498, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143897, 'time': 1681840986.941642}, {'src': '192.168.0.9', 'sport': 60477, 'dst': '192.168.0.4', 'dport': 53, 'offset': 143984, 'time': 1681840986.942064}, {'src': '192.168.0.9', 'sport': 62722, 'dst': '192.168.0.4', 'dport': 53, 'offset': 144071, 'time': 1681840986.942911}, {'src': '192.168.0.9', 'sport': 62312, 'dst': '192.168.0.4', 'dport': 53, 'offset': 144158, 'time': 1681840986.943519}, {'src': '192.168.0.9', 'sport': 58729, 'dst': '192.168.0.4', 'dport': 53, 'offset': 144245, 'time': 1681840986.944111}, {'src': '192.168.0.9', 'sport': 51810, 'dst': '192.168.0.4', 'dport': 53, 'offset': 144332, 'time': 1681840986.945055}, {'src': '192.168.0.9', 'sport': 49513, 'dst': '192.168.0.4', 'dport': 53, 'offset': 144419, 'time': 1681840986.945847}, {'src': '192.168.0.9', 'sport': 62453, 'dst': '192.168.0.4', 'dport': 53, 'offset': 144506, 'time': 1681840986.946211}, {'src': '192.168.0.9', 'sport': 56189, 'dst': '192.168.0.4', 'dport': 53, 'offset': 144593, 'time': 1681840986.946883}, {'src': '192.168.0.9', 'sport': 55364, 'dst': '192.168.0.4', 'dport': 53, 'offset': 144680, 'time': 1681840986.947869}, {'src': '192.168.0.9', 'sport': 62565, 'dst': '192.168.0.4', 'dport': 53, 'offset': 144767, 'time': 1681840986.948026}, {'src': '192.168.0.9', 'sport': 63227, 'dst': '192.168.0.4', 'dport': 53, 'offset': 144854, 'time': 1681840986.948667}, {'src': '192.168.0.9', 'sport': 55375, 'dst': '192.168.0.4', 'dport': 53, 'offset': 144941, 'time': 1681840986.949042}, {'src': '192.168.0.9', 'sport': 59425, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145028, 'time': 1681840986.950475}, {'src': '192.168.0.9', 'sport': 56632, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145115, 'time': 1681840986.951155}, {'src': '192.168.0.9', 'sport': 53381, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145202, 'time': 1681840986.951175}, {'src': '192.168.0.9', 'sport': 57744, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145289, 'time': 1681840986.952228}, {'src': '192.168.0.9', 'sport': 62362, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145376, 'time': 1681840986.952786}, {'src': '192.168.0.9', 'sport': 49397, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145463, 'time': 1681840986.953088}, {'src': '192.168.0.9', 'sport': 49189, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145550, 'time': 1681840986.953715}, {'src': '192.168.0.9', 'sport': 55551, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145637, 'time': 1681840986.954493}, {'src': '192.168.0.9', 'sport': 52429, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145724, 'time': 1681840986.95519}, {'src': '192.168.0.9', 'sport': 57362, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145811, 'time': 1681840986.955645}, {'src': '192.168.0.9', 'sport': 57475, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145898, 'time': 1681840986.956272}, {'src': '192.168.0.9', 'sport': 50475, 'dst': '192.168.0.4', 'dport': 53, 'offset': 145985, 'time': 1681840986.957022}, {'src': '192.168.0.9', 'sport': 62290, 'dst': '192.168.0.4', 'dport': 53, 'offset': 146072, 'time': 1681840986.957462}, {'src': '192.168.0.9', 'sport': 58800, 'dst': '192.168.0.4', 'dport': 53, 'offset': 146159, 'time': 1681840986.958311}, {'src': '192.168.0.9', 'sport': 49901, 'dst': '192.168.0.4', 'dport': 53, 'offset': 199741, 'time': 1681840998.615682}, {'src': '192.168.0.9', 'sport': 61342, 'dst': '192.168.0.4', 'dport': 53, 'offset': 199828, 'time': 1681840998.623915}, {'src': '192.168.0.9', 'sport': 52900, 'dst': '192.168.0.4', 'dport': 53, 'offset': 200188, 'time': 1681840998.779519}, {'src': '192.168.0.9', 'sport': 55285, 'dst': '192.168.0.4', 'dport': 53, 'offset': 200847, 'time': 1681840998.977337}, {'src': '192.168.0.9', 'sport': 63952, 'dst': '192.168.0.4', 'dport': 53, 'offset': 200934, 'time': 1681840998.978279}, {'src': '192.168.0.9', 'sport': 63640, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201021, 'time': 1681840998.979347}, {'src': '192.168.0.9', 'sport': 59429, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201108, 'time': 1681840998.982031}, {'src': '192.168.0.9', 'sport': 58313, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201195, 'time': 1681840998.988814}, {'src': '192.168.0.9', 'sport': 64831, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201282, 'time': 1681840998.988971}, {'src': '192.168.0.9', 'sport': 51783, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201369, 'time': 1681840998.99273}, {'src': '192.168.0.9', 'sport': 60892, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201456, 'time': 1681840999.012185}, {'src': '192.168.0.9', 'sport': 63427, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201543, 'time': 1681840999.018374}, {'src': '192.168.0.9', 'sport': 65496, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201630, 'time': 1681840999.022958}, {'src': '192.168.0.9', 'sport': 63995, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201717, 'time': 1681840999.031336}, {'src': '192.168.0.9', 'sport': 52366, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201804, 'time': 1681840999.038939}, {'src': '192.168.0.9', 'sport': 59696, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201891, 'time': 1681840999.038946}, {'src': '192.168.0.9', 'sport': 51918, 'dst': '192.168.0.4', 'dport': 53, 'offset': 201978, 'time': 1681840999.039346}, {'src': '192.168.0.9', 'sport': 54421, 'dst': '192.168.0.4', 'dport': 53, 'offset': 202065, 'time': 1681840999.040538}, {'src': '192.168.0.9', 'sport': 60581, 'dst': '192.168.0.4', 'dport': 53, 'offset': 202152, 'time': 1681840999.041074}, {'src': '192.168.0.9', 'sport': 54968, 'dst': '192.168.0.4', 'dport': 53, 'offset': 202239, 'time': 1681840999.041751}, {'src': '192.168.0.9', 'sport': 61438, 'dst': '192.168.0.4', 'dport': 53, 'offset': 202458, 'time': 1681840999.071811}, {'src': '192.168.0.9', 'sport': 57250, 'dst': '192.168.0.4', 'dport': 53, 'offset': 202545, 'time': 1681840999.071811}, {'src': '192.168.0.9', 'sport': 62197, 'dst': '192.168.0.4', 'dport': 53, 'offset': 202632, 'time': 1681840999.07327}, {'src': '192.168.0.9', 'sport': 53812, 'dst': '192.168.0.4', 'dport': 53, 'offset': 202719, 'time': 1681840999.075188}, {'src': '192.168.0.9', 'sport': 53394, 'dst': '192.168.0.4', 'dport': 53, 'offset': 202806, 'time': 1681840999.077078}, {'src': '192.168.0.9', 'sport': 50742, 'dst': '192.168.0.4', 'dport': 53, 'offset': 202893, 'time': 1681840999.080557}, {'src': '192.168.0.9', 'sport': 56822, 'dst': '192.168.0.4', 'dport': 53, 'offset': 202980, 'time': 1681840999.082757}, {'src': '192.168.0.9', 'sport': 58017, 'dst': '192.168.0.4', 'dport': 53, 'offset': 203067, 'time': 1681840999.083536}, {'src': '192.168.0.9', 'sport': 53823, 'dst': '192.168.0.4', 'dport': 53, 'offset': 203154, 'time': 1681840999.08477}, {'src': '192.168.0.9', 'sport': 53079, 'dst': '192.168.0.4', 'dport': 53, 'offset': 203241, 'time': 1681840999.085487}, {'src': '192.168.0.9', 'sport': 65376, 'dst': '192.168.0.4', 'dport': 53, 'offset': 203328, 'time': 1681840999.086559}, {'src': '192.168.0.9', 'sport': 51956, 'dst': '192.168.0.4', 'dport': 53, 'offset': 203502, 'time': 1681840999.087068}, {'src': '192.168.0.9', 'sport': 63168, 'dst': '192.168.0.4', 'dport': 53, 'offset': 203589, 'time': 1681840999.087508}, {'src': '192.168.0.9', 'sport': 64195, 'dst': '192.168.0.4', 'dport': 53, 'offset': 203676, 'time': 1681840999.088133}, {'src': '192.168.0.9', 'sport': 59493, 'dst': '192.168.0.4', 'dport': 53, 'offset': 203763, 'time': 1681840999.088793}, {'src': '192.168.0.9', 'sport': 51740, 'dst': '192.168.0.4', 'dport': 53, 'offset': 203850, 'time': 1681840999.088793}, {'src': '192.168.0.9', 'sport': 55690, 'dst': '192.168.0.4', 'dport': 53, 'offset': 203937, 'time': 1681840999.088928}, {'src': '192.168.0.9', 'sport': 62306, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204024, 'time': 1681840999.089342}, {'src': '192.168.0.9', 'sport': 62936, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204111, 'time': 1681840999.08984}, {'src': '192.168.0.9', 'sport': 49934, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204198, 'time': 1681840999.090594}, {'src': '192.168.0.9', 'sport': 50254, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204285, 'time': 1681840999.090782}, {'src': '192.168.0.9', 'sport': 58527, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204372, 'time': 1681840999.090889}, {'src': '192.168.0.9', 'sport': 52112, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204459, 'time': 1681840999.091561}, {'src': '192.168.0.9', 'sport': 55945, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204546, 'time': 1681840999.091627}, {'src': '192.168.0.9', 'sport': 51965, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204633, 'time': 1681840999.092212}, {'src': '192.168.0.9', 'sport': 63157, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204720, 'time': 1681840999.092256}, {'src': '192.168.0.9', 'sport': 56311, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204807, 'time': 1681840999.093142}, {'src': '192.168.0.9', 'sport': 49176, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204894, 'time': 1681840999.093615}, {'src': '192.168.0.9', 'sport': 58625, 'dst': '192.168.0.4', 'dport': 53, 'offset': 204981, 'time': 1681840999.093974}, {'src': '192.168.0.9', 'sport': 58609, 'dst': '192.168.0.4', 'dport': 53, 'offset': 205068, 'time': 1681840999.094106}, {'src': '192.168.0.9', 'sport': 52421, 'dst': '192.168.0.4', 'dport': 53, 'offset': 205155, 'time': 1681840999.095086}, {'src': '192.168.0.9', 'sport': 59689, 'dst': '192.168.0.4', 'dport': 53, 'offset': 205242, 'time': 1681840999.095236}, {'src': '192.168.0.9', 'sport': 65269, 'dst': '192.168.0.4', 'dport': 53, 'offset': 205329, 'time': 1681840999.095469}, {'src': '192.168.0.9', 'sport': 65118, 'dst': '192.168.0.4', 'dport': 53, 'offset': 205416, 'time': 1681840999.096294}, {'src': '192.168.0.9', 'sport': 51285, 'dst': '192.168.0.4', 'dport': 53, 'offset': 205503, 'time': 1681840999.09665}, {'src': '192.168.0.9', 'sport': 53160, 'dst': '192.168.0.4', 'dport': 53, 'offset': 205590, 'time': 1681840999.096706}, {'src': '192.168.0.9', 'sport': 54660, 'dst': '192.168.0.4', 'dport': 53, 'offset': 205677, 'time': 1681840999.097128}, {'src': '192.168.0.9', 'sport': 61317, 'dst': '192.168.0.4', 'dport': 53, 'offset': 205764, 'time': 1681840999.097499}, {'src': '192.168.0.9', 'sport': 50146, 'dst': '192.168.0.4', 'dport': 53, 'offset': 205851, 'time': 1681840999.098088}, {'src': '192.168.0.9', 'sport': 54026, 'dst': '192.168.0.4', 'dport': 53, 'offset': 205938, 'time': 1681840999.098185}, {'src': '192.168.0.9', 'sport': 59061, 'dst': '192.168.0.4', 'dport': 53, 'offset': 206025, 'time': 1681840999.099481}, {'src': '192.168.0.9', 'sport': 49627, 'dst': '192.168.0.4', 'dport': 53, 'offset': 206112, 'time': 1681840999.099921}, {'src': '192.168.0.9', 'sport': 49854, 'dst': '192.168.0.4', 'dport': 53, 'offset': 206199, 'time': 1681840999.100122}, {'src': '192.168.0.9', 'sport': 49451, 'dst': '192.168.0.4', 'dport': 53, 'offset': 206286, 'time': 1681840999.100514}, {'src': '192.168.0.9', 'sport': 51739, 'dst': '192.168.0.4', 'dport': 53, 'offset': 250407, 'time': 1681841010.663058}, {'src': '192.168.0.9', 'sport': 57298, 'dst': '192.168.0.4', 'dport': 53, 'offset': 251458, 'time': 1681841011.207822}, {'src': '192.168.0.9', 'sport': 62190, 'dst': '192.168.0.4', 'dport': 53, 'offset': 257892, 'time': 1681841014.034914}, {'src': '192.168.0.9', 'sport': 63398, 'dst': '192.168.0.4', 'dport': 53, 'offset': 258368, 'time': 1681841014.105693}, {'src': '192.168.0.9', 'sport': 54269, 'dst': '192.168.0.4', 'dport': 53, 'offset': 258455, 'time': 1681841014.106437}, {'src': '192.168.0.9', 'sport': 63719, 'dst': '192.168.0.4', 'dport': 53, 'offset': 258542, 'time': 1681841014.108048}, {'src': '192.168.0.9', 'sport': 62683, 'dst': '192.168.0.4', 'dport': 53, 'offset': 258629, 'time': 1681841014.11078}, {'src': '192.168.0.9', 'sport': 50021, 'dst': '192.168.0.4', 'dport': 53, 'offset': 258716, 'time': 1681841014.111211}, {'src': '192.168.0.9', 'sport': 61802, 'dst': '192.168.0.4', 'dport': 53, 'offset': 258803, 'time': 1681841014.111974}, {'src': '192.168.0.9', 'sport': 50904, 'dst': '192.168.0.4', 'dport': 53, 'offset': 258890, 'time': 1681841014.112435}, {'src': '192.168.0.9', 'sport': 63642, 'dst': '192.168.0.4', 'dport': 53, 'offset': 258977, 'time': 1681841014.114053}, {'src': '192.168.0.9', 'sport': 55599, 'dst': '192.168.0.4', 'dport': 53, 'offset': 259064, 'time': 1681841014.114092}, {'src': '192.168.0.9', 'sport': 63384, 'dst': '192.168.0.4', 'dport': 53, 'offset': 259151, 'time': 1681841014.114526}, {'src': '192.168.0.9', 'sport': 63868, 'dst': '192.168.0.4', 'dport': 53, 'offset': 259238, 'time': 1681841014.116248}, {'src': '192.168.0.9', 'sport': 57409, 'dst': '192.168.0.4', 'dport': 53, 'offset': 259325, 'time': 1681841014.117045}, {'src': '192.168.0.9', 'sport': 65387, 'dst': '192.168.0.4', 'dport': 53, 'offset': 259412, 'time': 1681841014.117701}, {'src': '192.168.0.9', 'sport': 58145, 'dst': '192.168.0.4', 'dport': 53, 'offset': 259499, 'time': 1681841014.118469}, {'src': '192.168.0.9', 'sport': 63004, 'dst': '192.168.0.4', 'dport': 53, 'offset': 259586, 'time': 1681841014.12079}, {'src': '192.168.0.9', 'sport': 60473, 'dst': '192.168.0.4', 'dport': 53, 'offset': 259673, 'time': 1681841014.120858}, {'src': '192.168.0.9', 'sport': 55558, 'dst': '192.168.0.4', 'dport': 53, 'offset': 259760, 'time': 1681841014.122452}, {'src': '192.168.0.9', 'sport': 53593, 'dst': '192.168.0.4', 'dport': 53, 'offset': 259847, 'time': 1681841014.124495}, {'src': '192.168.0.9', 'sport': 59732, 'dst': '192.168.0.4', 'dport': 53, 'offset': 259934, 'time': 1681841014.124547}, {'src': '192.168.0.9', 'sport': 50100, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260021, 'time': 1681841014.125168}, {'src': '192.168.0.9', 'sport': 52030, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260108, 'time': 1681841014.125671}, {'src': '192.168.0.9', 'sport': 63353, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260195, 'time': 1681841014.1259}, {'src': '192.168.0.9', 'sport': 61653, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260282, 'time': 1681841014.127735}, {'src': '192.168.0.9', 'sport': 52514, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260369, 'time': 1681841014.128167}, {'src': '192.168.0.9', 'sport': 60351, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260456, 'time': 1681841014.129236}, {'src': '192.168.0.9', 'sport': 49676, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260543, 'time': 1681841014.129641}, {'src': '192.168.0.9', 'sport': 56718, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260630, 'time': 1681841014.130783}, {'src': '192.168.0.9', 'sport': 59869, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260717, 'time': 1681841014.131319}, {'src': '192.168.0.9', 'sport': 50133, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260804, 'time': 1681841014.13139}, {'src': '192.168.0.9', 'sport': 55550, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260891, 'time': 1681841014.133695}, {'src': '192.168.0.9', 'sport': 60648, 'dst': '192.168.0.4', 'dport': 53, 'offset': 260978, 'time': 1681841014.134227}, {'src': '192.168.0.9', 'sport': 61149, 'dst': '192.168.0.4', 'dport': 53, 'offset': 261065, 'time': 1681841014.134753}, {'src': '192.168.0.9', 'sport': 49917, 'dst': '192.168.0.4', 'dport': 53, 'offset': 261152, 'time': 1681841014.136633}, {'src': '192.168.0.9', 'sport': 58345, 'dst': '192.168.0.4', 'dport': 53, 'offset': 261239, 'time': 1681841014.139899}, {'src': '192.168.0.9', 'sport': 61556, 'dst': '192.168.0.4', 'dport': 53, 'offset': 261326, 'time': 1681841014.139954}, {'src': '192.168.0.9', 'sport': 58319, 'dst': '192.168.0.4', 'dport': 53, 'offset': 261413, 'time': 1681841014.140179}, {'src': '192.168.0.9', 'sport': 61464, 'dst': '192.168.0.4', 'dport': 53, 'offset': 261500, 'time': 1681841014.140809}, {'src': '192.168.0.9', 'sport': 49171, 'dst': '192.168.0.4', 'dport': 53, 'offset': 261587, 'time': 1681841014.140809}, {'src': '192.168.0.9', 'sport': 58005, 'dst': '192.168.0.4', 'dport': 53, 'offset': 261674, 'time': 1681841014.141726}, {'src': '192.168.0.9', 'sport': 52952, 'dst': '192.168.0.4', 'dport': 53, 'offset': 262173, 'time': 1681841014.420841}, {'src': '192.168.0.9', 'sport': 59520, 'dst': '192.168.0.4', 'dport': 53, 'offset': 262260, 'time': 1681841014.423854}, {'src': '192.168.0.9', 'sport': 54879, 'dst': '192.168.0.4', 'dport': 53, 'offset': 262450, 'time': 1681841014.469767}, {'src': '192.168.0.9', 'sport': 63021, 'dst': '192.168.0.4', 'dport': 53, 'offset': 262640, 'time': 1681841014.588807}, {'src': '192.168.0.9', 'sport': 53542, 'dst': '192.168.0.4', 'dport': 53, 'offset': 262727, 'time': 1681841014.589004}, {'src': '192.168.0.9', 'sport': 50158, 'dst': '192.168.0.4', 'dport': 53, 'offset': 262814, 'time': 1681841014.590422}, {'src': '192.168.0.9', 'sport': 57847, 'dst': '192.168.0.4', 'dport': 53, 'offset': 262901, 'time': 1681841014.590468}, {'src': '192.168.0.9', 'sport': 58114, 'dst': '192.168.0.4', 'dport': 53, 'offset': 262988, 'time': 1681841014.591467}, {'src': '192.168.0.9', 'sport': 51725, 'dst': '192.168.0.4', 'dport': 53, 'offset': 263075, 'time': 1681841014.592095}, {'src': '192.168.0.9', 'sport': 61914, 'dst': '192.168.0.4', 'dport': 53, 'offset': 263162, 'time': 1681841014.592181}, {'src': '192.168.0.9', 'sport': 56155, 'dst': '192.168.0.4', 'dport': 53, 'offset': 263249, 'time': 1681841014.592309}, {'src': '192.168.0.9', 'sport': 62521, 'dst': '192.168.0.4', 'dport': 53, 'offset': 263336, 'time': 1681841014.592493}, {'src': '192.168.0.9', 'sport': 53899, 'dst': '192.168.0.4', 'dport': 53, 'offset': 263423, 'time': 1681841014.594057}, {'src': '192.168.0.9', 'sport': 60890, 'dst': '192.168.0.4', 'dport': 53, 'offset': 263510, 'time': 1681841014.595395}, {'src': '192.168.0.9', 'sport': 49466, 'dst': '192.168.0.4', 'dport': 53, 'offset': 263684, 'time': 1681841014.596649}, {'src': '192.168.0.9', 'sport': 57936, 'dst': '192.168.0.4', 'dport': 53, 'offset': 263771, 'time': 1681841014.596674}, {'src': '192.168.0.9', 'sport': 56505, 'dst': '192.168.0.4', 'dport': 53, 'offset': 263858, 'time': 1681841014.597621}, {'src': '192.168.0.9', 'sport': 50056, 'dst': '192.168.0.4', 'dport': 53, 'offset': 263945, 'time': 1681841014.598015}, {'src': '192.168.0.9', 'sport': 53105, 'dst': '192.168.0.4', 'dport': 53, 'offset': 264135, 'time': 1681841014.598887}, {'src': '192.168.0.9', 'sport': 61403, 'dst': '192.168.0.4', 'dport': 53, 'offset': 264222, 'time': 1681841014.598999}, {'src': '192.168.0.9', 'sport': 62402, 'dst': '192.168.0.4', 'dport': 53, 'offset': 264309, 'time': 1681841014.599663}, {'src': '192.168.0.9', 'sport': 57451, 'dst': '192.168.0.4', 'dport': 53, 'offset': 264396, 'time': 1681841014.599685}, {'src': '192.168.0.9', 'sport': 50694, 'dst': '192.168.0.4', 'dport': 53, 'offset': 264483, 'time': 1681841014.600713}, {'src': '192.168.0.9', 'sport': 49217, 'dst': '192.168.0.4', 'dport': 53, 'offset': 264570, 'time': 1681841014.60116}, {'src': '192.168.0.9', 'sport': 59028, 'dst': '192.168.0.4', 'dport': 53, 'offset': 264657, 'time': 1681841014.601708}, {'src': '192.168.0.9', 'sport': 62726, 'dst': '192.168.0.4', 'dport': 53, 'offset': 264744, 'time': 1681841014.602234}, {'src': '192.168.0.9', 'sport': 61532, 'dst': '192.168.0.4', 'dport': 53, 'offset': 264831, 'time': 1681841014.602996}, {'src': '192.168.0.9', 'sport': 58491, 'dst': '192.168.0.4', 'dport': 53, 'offset': 264918, 'time': 1681841014.603737}, {'src': '192.168.0.9', 'sport': 50877, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265005, 'time': 1681841014.60442}, {'src': '192.168.0.9', 'sport': 63729, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265092, 'time': 1681841014.604443}, {'src': '192.168.0.9', 'sport': 49335, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265179, 'time': 1681841014.604448}, {'src': '192.168.0.9', 'sport': 63349, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265266, 'time': 1681841014.60445}, {'src': '192.168.0.9', 'sport': 55546, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265353, 'time': 1681841014.605888}, {'src': '192.168.0.9', 'sport': 61145, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265440, 'time': 1681841014.606499}, {'src': '192.168.0.9', 'sport': 64106, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265527, 'time': 1681841014.608296}, {'src': '192.168.0.9', 'sport': 53066, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265614, 'time': 1681841014.608312}, {'src': '192.168.0.9', 'sport': 52616, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265701, 'time': 1681841014.608913}, {'src': '192.168.0.9', 'sport': 57304, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265788, 'time': 1681841014.609241}, {'src': '192.168.0.9', 'sport': 52566, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265875, 'time': 1681841014.609651}, {'src': '192.168.0.9', 'sport': 58173, 'dst': '192.168.0.4', 'dport': 53, 'offset': 265962, 'time': 1681841014.609761}, {'src': '192.168.0.9', 'sport': 56158, 'dst': '192.168.0.4', 'dport': 53, 'offset': 266049, 'time': 1681841014.610246}, {'src': '192.168.0.9', 'sport': 52083, 'dst': '192.168.0.4', 'dport': 53, 'offset': 266136, 'time': 1681841014.610873}, {'src': '192.168.0.9', 'sport': 61469, 'dst': '192.168.0.4', 'dport': 53, 'offset': 266223, 'time': 1681841014.61088}, {'src': '192.168.0.9', 'sport': 61361, 'dst': '192.168.0.4', 'dport': 53, 'offset': 266310, 'time': 1681841014.612418}, {'src': '192.168.0.9', 'sport': 55164, 'dst': '192.168.0.4', 'dport': 53, 'offset': 266397, 'time': 1681841014.612418}, {'src': '192.168.0.9', 'sport': 54981, 'dst': '192.168.0.4', 'dport': 53, 'offset': 266484, 'time': 1681841014.612491}, {'src': '192.168.0.9', 'sport': 54608, 'dst': '192.168.0.4', 'dport': 53, 'offset': 266571, 'time': 1681841014.612545}, {'src': '192.168.0.9', 'sport': 50087, 'dst': '192.168.0.4', 'dport': 53, 'offset': 266658, 'time': 1681841014.61332}, {'src': '192.168.0.9', 'sport': 56464, 'dst': '192.168.0.4', 'dport': 53, 'offset': 266745, 'time': 1681841014.613328}, {'src': '192.168.0.9', 'sport': 63232, 'dst': '192.168.0.4', 'dport': 53, 'offset': 266832, 'time': 1681841014.613328}, {'src': '192.168.0.9', 'sport': 58628, 'dst': '192.168.0.4', 'dport': 53, 'offset': 266919, 'time': 1681841014.614479}, {'src': '192.168.0.9', 'sport': 56060, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267006, 'time': 1681841014.615184}, {'src': '192.168.0.9', 'sport': 51880, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267093, 'time': 1681841014.616609}, {'src': '192.168.0.9', 'sport': 57758, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267180, 'time': 1681841014.618255}, {'src': '192.168.0.9', 'sport': 57943, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267267, 'time': 1681841014.61843}, {'src': '192.168.0.9', 'sport': 57935, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267354, 'time': 1681841014.619042}, {'src': '192.168.0.9', 'sport': 60792, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267441, 'time': 1681841014.619324}, {'src': '192.168.0.9', 'sport': 50928, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267528, 'time': 1681841014.621273}, {'src': '192.168.0.9', 'sport': 53713, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267615, 'time': 1681841014.624246}, {'src': '192.168.0.9', 'sport': 53338, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267702, 'time': 1681841014.624325}, {'src': '192.168.0.9', 'sport': 54925, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267789, 'time': 1681841014.62473}, {'src': '192.168.0.9', 'sport': 57820, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267876, 'time': 1681841014.625021}, {'src': '192.168.0.9', 'sport': 62415, 'dst': '192.168.0.4', 'dport': 53, 'offset': 267963, 'time': 1681841014.625823}, {'src': '192.168.0.9', 'sport': 49582, 'dst': '192.168.0.4', 'dport': 53, 'offset': 325341, 'time': 1681841026.139348}, {'src': '192.168.0.9', 'sport': 64174, 'dst': '192.168.0.4', 'dport': 53, 'offset': 325428, 'time': 1681841026.139994}, {'src': '192.168.0.9', 'sport': 53349, 'dst': '192.168.0.4', 'dport': 53, 'offset': 325515, 'time': 1681841026.140297}, {'src': '192.168.0.9', 'sport': 61295, 'dst': '192.168.0.4', 'dport': 53, 'offset': 325602, 'time': 1681841026.140371}, {'src': '192.168.0.9', 'sport': 49262, 'dst': '192.168.0.4', 'dport': 53, 'offset': 325689, 'time': 1681841026.140377}, {'src': '192.168.0.9', 'sport': 50356, 'dst': '192.168.0.4', 'dport': 53, 'offset': 325776, 'time': 1681841026.140592}, {'src': '192.168.0.9', 'sport': 58554, 'dst': '192.168.0.4', 'dport': 53, 'offset': 325863, 'time': 1681841026.142541}, {'src': '192.168.0.9', 'sport': 54839, 'dst': '192.168.0.4', 'dport': 53, 'offset': 326918, 'time': 1681841026.159828}, {'src': '192.168.0.9', 'sport': 63167, 'dst': '192.168.0.4', 'dport': 53, 'offset': 327005, 'time': 1681841026.16218}, {'src': '192.168.0.9', 'sport': 58685, 'dst': '192.168.0.4', 'dport': 53, 'offset': 327092, 'time': 1681841026.162644}, {'src': '192.168.0.9', 'sport': 65533, 'dst': '192.168.0.4', 'dport': 53, 'offset': 327179, 'time': 1681841026.163281}, {'src': '192.168.0.9', 'sport': 59851, 'dst': '192.168.0.4', 'dport': 53, 'offset': 327266, 'time': 1681841026.164874}, {'src': '192.168.0.9', 'sport': 58603, 'dst': '192.168.0.4', 'dport': 53, 'offset': 327353, 'time': 1681841026.165553}, {'src': '192.168.0.9', 'sport': 64056, 'dst': '192.168.0.4', 'dport': 53, 'offset': 327527, 'time': 1681841026.165945}, {'src': '192.168.0.9', 'sport': 54071, 'dst': '192.168.0.4', 'dport': 53, 'offset': 327614, 'time': 1681841026.166571}, {'src': '192.168.0.9', 'sport': 61249, 'dst': '192.168.0.4', 'dport': 53, 'offset': 327701, 'time': 1681841026.166775}, {'src': '192.168.0.9', 'sport': 49377, 'dst': '192.168.0.4', 'dport': 53, 'offset': 327788, 'time': 1681841026.168816}, {'src': '192.168.0.9', 'sport': 61470, 'dst': '192.168.0.4', 'dport': 53, 'offset': 327875, 'time': 1681841026.169191}, {'src': '192.168.0.9', 'sport': 59895, 'dst': '192.168.0.4', 'dport': 53, 'offset': 327962, 'time': 1681841026.16985}, {'src': '192.168.0.9', 'sport': 62661, 'dst': '192.168.0.4', 'dport': 53, 'offset': 328049, 'time': 1681841026.180672}, {'src': '192.168.0.9', 'sport': 60903, 'dst': '192.168.0.4', 'dport': 53, 'offset': 328149, 'time': 1681841026.183521}, {'src': '192.168.0.9', 'sport': 55412, 'dst': '192.168.0.4', 'dport': 53, 'offset': 328236, 'time': 1681841026.187608}, {'src': '192.168.0.9', 'sport': 62607, 'dst': '192.168.0.4', 'dport': 53, 'offset': 328323, 'time': 1681841026.188275}, {'src': '192.168.0.9', 'sport': 49282, 'dst': '192.168.0.4', 'dport': 53, 'offset': 328410, 'time': 1681841026.188872}, {'src': '192.168.0.9', 'sport': 60632, 'dst': '192.168.0.4', 'dport': 53, 'offset': 328497, 'time': 1681841026.189206}, {'src': '192.168.0.9', 'sport': 57326, 'dst': '192.168.0.4', 'dport': 53, 'offset': 328584, 'time': 1681841026.189374}, {'src': '192.168.0.9', 'sport': 64937, 'dst': '192.168.0.4', 'dport': 53, 'offset': 329083, 'time': 1681841026.447751}, {'src': '192.168.0.9', 'sport': 62446, 'dst': '192.168.0.4', 'dport': 53, 'offset': 329170, 'time': 1681841026.447917}, {'src': '192.168.0.9', 'sport': 59928, 'dst': '192.168.0.4', 'dport': 53, 'offset': 329360, 'time': 1681841026.494642}, {'src': '192.168.0.9', 'sport': 53470, 'dst': '192.168.0.4', 'dport': 53, 'offset': 329653, 'time': 1681841026.663534}, {'src': '192.168.0.9', 'sport': 61568, 'dst': '192.168.0.4', 'dport': 53, 'offset': 329740, 'time': 1681841026.664521}, {'src': '192.168.0.9', 'sport': 55812, 'dst': '192.168.0.4', 'dport': 53, 'offset': 329827, 'time': 1681841026.664521}, {'src': '192.168.0.9', 'sport': 53174, 'dst': '192.168.0.4', 'dport': 53, 'offset': 329914, 'time': 1681841026.665395}, {'src': '192.168.0.9', 'sport': 51915, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330001, 'time': 1681841026.670666}, {'src': '192.168.0.9', 'sport': 50635, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330088, 'time': 1681841026.671355}, {'src': '192.168.0.9', 'sport': 52275, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330175, 'time': 1681841026.673063}, {'src': '192.168.0.9', 'sport': 50933, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330262, 'time': 1681841026.673288}, {'src': '192.168.0.9', 'sport': 63935, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330349, 'time': 1681841026.673324}, {'src': '192.168.0.9', 'sport': 50970, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330436, 'time': 1681841026.673622}, {'src': '192.168.0.9', 'sport': 59632, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330523, 'time': 1681841026.673984}, {'src': '192.168.0.9', 'sport': 60478, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330610, 'time': 1681841026.674213}, {'src': '192.168.0.9', 'sport': 52418, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330697, 'time': 1681841026.674538}, {'src': '192.168.0.9', 'sport': 62654, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330784, 'time': 1681841026.674691}, {'src': '192.168.0.9', 'sport': 49537, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330871, 'time': 1681841026.675077}, {'src': '192.168.0.9', 'sport': 49883, 'dst': '192.168.0.4', 'dport': 53, 'offset': 330958, 'time': 1681841026.675629}, {'src': '192.168.0.9', 'sport': 63069, 'dst': '192.168.0.4', 'dport': 53, 'offset': 331045, 'time': 1681841026.676849}, {'src': '192.168.0.9', 'sport': 50985, 'dst': '192.168.0.4', 'dport': 53, 'offset': 331132, 'time': 1681841026.680952}, {'src': '192.168.0.9', 'sport': 64987, 'dst': '192.168.0.4', 'dport': 53, 'offset': 331219, 'time': 1681841026.686983}, {'src': '192.168.0.9', 'sport': 55261, 'dst': '192.168.0.4', 'dport': 53, 'offset': 331306, 'time': 1681841026.687381}, {'src': '192.168.0.9', 'sport': 62673, 'dst': '192.168.0.4', 'dport': 53, 'offset': 331496, 'time': 1681841026.691383}, {'src': '192.168.0.9', 'sport': 53098, 'dst': '192.168.0.4', 'dport': 53, 'offset': 331583, 'time': 1681841026.691685}, {'src': '192.168.0.9', 'sport': 63444, 'dst': '192.168.0.4', 'dport': 53, 'offset': 331670, 'time': 1681841026.691781}, {'src': '192.168.0.9', 'sport': 54575, 'dst': '192.168.0.4', 'dport': 53, 'offset': 331757, 'time': 1681841026.692873}, {'src': '192.168.0.9', 'sport': 54604, 'dst': '192.168.0.4', 'dport': 53, 'offset': 331844, 'time': 1681841026.692873}, {'src': '192.168.0.9', 'sport': 62529, 'dst': '192.168.0.4', 'dport': 53, 'offset': 331931, 'time': 1681841026.693569}, {'src': '192.168.0.9', 'sport': 62136, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332018, 'time': 1681841026.693956}, {'src': '192.168.0.9', 'sport': 55175, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332105, 'time': 1681841026.694316}, {'src': '192.168.0.9', 'sport': 50677, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332192, 'time': 1681841026.694371}, {'src': '192.168.0.9', 'sport': 56582, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332279, 'time': 1681841026.694893}, {'src': '192.168.0.9', 'sport': 60744, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332366, 'time': 1681841026.698139}, {'src': '192.168.0.9', 'sport': 54574, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332453, 'time': 1681841026.698275}, {'src': '192.168.0.9', 'sport': 49542, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332540, 'time': 1681841026.698451}, {'src': '192.168.0.9', 'sport': 59969, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332627, 'time': 1681841026.698877}, {'src': '192.168.0.9', 'sport': 64769, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332714, 'time': 1681841026.699074}, {'src': '192.168.0.9', 'sport': 59142, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332801, 'time': 1681841026.699134}, {'src': '192.168.0.9', 'sport': 55266, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332888, 'time': 1681841026.699585}, {'src': '192.168.0.9', 'sport': 61250, 'dst': '192.168.0.4', 'dport': 53, 'offset': 332975, 'time': 1681841026.700159}, {'src': '192.168.0.9', 'sport': 50065, 'dst': '192.168.0.4', 'dport': 53, 'offset': 333062, 'time': 1681841026.700189}, {'src': '192.168.0.9', 'sport': 49651, 'dst': '192.168.0.4', 'dport': 53, 'offset': 333149, 'time': 1681841026.70052}, {'src': '192.168.0.9', 'sport': 56763, 'dst': '192.168.0.4', 'dport': 53, 'offset': 333236, 'time': 1681841026.700894}, {'src': '192.168.0.9', 'sport': 50244, 'dst': '192.168.0.4', 'dport': 53, 'offset': 333323, 'time': 1681841026.701011}, {'src': '192.168.0.9', 'sport': 50386, 'dst': '192.168.0.4', 'dport': 53, 'offset': 333410, 'time': 1681841026.701535}, {'src': '192.168.0.9', 'sport': 64557, 'dst': '192.168.0.4', 'dport': 53, 'offset': 333497, 'time': 1681841026.702312}, {'src': '192.168.0.9', 'sport': 55200, 'dst': '192.168.0.4', 'dport': 53, 'offset': 333584, 'time': 1681841026.702391}, {'src': '192.168.0.9', 'sport': 61784, 'dst': '192.168.0.4', 'dport': 53, 'offset': 333671, 'time': 1681841026.702396}, {'src': '192.168.0.9', 'sport': 64038, 'dst': '192.168.0.4', 'dport': 53, 'offset': 333758, 'time': 1681841026.702605}, {'src': '192.168.0.9', 'sport': 54693, 'dst': '192.168.0.4', 'dport': 53, 'offset': 333845, 'time': 1681841026.703035}, {'src': '192.168.0.9', 'sport': 54909, 'dst': '192.168.0.4', 'dport': 53, 'offset': 333932, 'time': 1681841026.703247}, {'src': '192.168.0.9', 'sport': 57792, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334019, 'time': 1681841026.703494}, {'src': '192.168.0.9', 'sport': 60025, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334106, 'time': 1681841026.70585}, {'src': '192.168.0.9', 'sport': 58824, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334193, 'time': 1681841026.707237}, {'src': '192.168.0.9', 'sport': 58737, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334280, 'time': 1681841026.707463}, {'src': '192.168.0.9', 'sport': 49244, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334367, 'time': 1681841026.707619}, {'src': '192.168.0.9', 'sport': 62187, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334454, 'time': 1681841026.708103}, {'src': '192.168.0.9', 'sport': 51841, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334541, 'time': 1681841026.708203}, {'src': '192.168.0.9', 'sport': 50961, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334628, 'time': 1681841026.70845}, {'src': '192.168.0.9', 'sport': 64766, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334715, 'time': 1681841026.70857}, {'src': '192.168.0.9', 'sport': 60503, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334802, 'time': 1681841026.709438}, {'src': '192.168.0.9', 'sport': 59615, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334889, 'time': 1681841026.71061}, {'src': '192.168.0.9', 'sport': 52808, 'dst': '192.168.0.4', 'dport': 53, 'offset': 334976, 'time': 1681841026.71061}, {'src': '192.168.0.9', 'sport': 54854, 'dst': '192.168.0.4', 'dport': 53, 'offset': 385259, 'time': 1681841038.180134}, {'src': '192.168.0.9', 'sport': 64347, 'dst': '192.168.0.4', 'dport': 53, 'offset': 385449, 'time': 1681841038.226908}, {'src': '192.168.0.9', 'sport': 64840, 'dst': '192.168.0.4', 'dport': 53, 'offset': 386266, 'time': 1681841038.749782}, {'src': '192.168.0.9', 'sport': 51872, 'dst': '192.168.0.4', 'dport': 53, 'offset': 386353, 'time': 1681841038.757655}, {'src': '192.168.0.9', 'sport': 53890, 'dst': '192.168.0.4', 'dport': 53, 'offset': 386440, 'time': 1681841038.757661}, {'src': '192.168.0.9', 'sport': 49522, 'dst': '192.168.0.4', 'dport': 53, 'offset': 386527, 'time': 1681841038.759211}, {'src': '192.168.0.9', 'sport': 63219, 'dst': '192.168.0.4', 'dport': 53, 'offset': 386614, 'time': 1681841038.763178}, {'src': '192.168.0.9', 'sport': 64348, 'dst': '192.168.0.4', 'dport': 53, 'offset': 386701, 'time': 1681841038.763934}, {'src': '192.168.0.9', 'sport': 55076, 'dst': '192.168.0.4', 'dport': 53, 'offset': 386891, 'time': 1681841038.788235}, {'src': '192.168.0.9', 'sport': 58525, 'dst': '192.168.0.4', 'dport': 53, 'offset': 386978, 'time': 1681841038.790291}, {'src': '192.168.0.9', 'sport': 53830, 'dst': '192.168.0.4', 'dport': 53, 'offset': 387065, 'time': 1681841038.790667}, {'src': '192.168.0.9', 'sport': 52115, 'dst': '192.168.0.4', 'dport': 53, 'offset': 387152, 'time': 1681841038.79095}, {'src': '192.168.0.9', 'sport': 57819, 'dst': '192.168.0.4', 'dport': 53, 'offset': 387239, 'time': 1681841038.792482}, {'src': '192.168.0.9', 'sport': 56107, 'dst': '192.168.0.4', 'dport': 53, 'offset': 387326, 'time': 1681841038.79448}, {'src': '192.168.0.9', 'sport': 49382, 'dst': '192.168.0.4', 'dport': 53, 'offset': 387413, 'time': 1681841038.79448}, {'src': '192.168.0.9', 'sport': 59178, 'dst': '192.168.0.4', 'dport': 53, 'offset': 387500, 'time': 1681841038.795025}, {'src': '192.168.0.9', 'sport': 61187, 'dst': '192.168.0.4', 'dport': 53, 'offset': 387587, 'time': 1681841038.810367}, {'src': '192.168.0.9', 'sport': 59766, 'dst': '192.168.0.4', 'dport': 53, 'offset': 387674, 'time': 1681841038.810499}, {'src': '192.168.0.9', 'sport': 55282, 'dst': '192.168.0.4', 'dport': 53, 'offset': 387761, 'time': 1681841038.810529}, {'src': '192.168.0.9', 'sport': 64134, 'dst': '192.168.0.4', 'dport': 53, 'offset': 387848, 'time': 1681841038.810555}, {'src': '192.168.0.9', 'sport': 61418, 'dst': '192.168.0.4', 'dport': 53, 'offset': 387935, 'time': 1681841038.810821}, {'src': '192.168.0.9', 'sport': 54867, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388022, 'time': 1681841038.811447}, {'src': '192.168.0.9', 'sport': 63284, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388109, 'time': 1681841038.811705}, {'src': '192.168.0.9', 'sport': 53770, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388196, 'time': 1681841038.811799}, {'src': '192.168.0.9', 'sport': 53087, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388283, 'time': 1681841038.812125}, {'src': '192.168.0.9', 'sport': 55099, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388370, 'time': 1681841038.812684}, {'src': '192.168.0.9', 'sport': 61030, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388457, 'time': 1681841038.812969}, {'src': '192.168.0.9', 'sport': 57455, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388544, 'time': 1681841038.813952}, {'src': '192.168.0.9', 'sport': 60789, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388631, 'time': 1681841038.814011}, {'src': '192.168.0.9', 'sport': 60918, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388718, 'time': 1681841038.814341}, {'src': '192.168.0.9', 'sport': 50732, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388805, 'time': 1681841038.814341}, {'src': '192.168.0.9', 'sport': 61406, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388892, 'time': 1681841038.816333}, {'src': '192.168.0.9', 'sport': 57567, 'dst': '192.168.0.4', 'dport': 53, 'offset': 388979, 'time': 1681841038.821714}, {'src': '192.168.0.9', 'sport': 58138, 'dst': '192.168.0.4', 'dport': 53, 'offset': 389066, 'time': 1681841038.827318}, {'src': '192.168.0.9', 'sport': 53867, 'dst': '192.168.0.4', 'dport': 53, 'offset': 389153, 'time': 1681841038.827333}, {'src': '192.168.0.9', 'sport': 58351, 'dst': '192.168.0.4', 'dport': 53, 'offset': 389240, 'time': 1681841038.827333}, {'src': '192.168.0.9', 'sport': 58304, 'dst': '192.168.0.4', 'dport': 53, 'offset': 389414, 'time': 1681841038.827706}, {'src': '192.168.0.9', 'sport': 51402, 'dst': '192.168.0.4', 'dport': 53, 'offset': 389501, 'time': 1681841038.827867}, {'src': '192.168.0.9', 'sport': 64398, 'dst': '192.168.0.4', 'dport': 53, 'offset': 389588, 'time': 1681841038.828369}, {'src': '192.168.0.9', 'sport': 52480, 'dst': '192.168.0.4', 'dport': 53, 'offset': 389675, 'time': 1681841038.828671}, {'src': '192.168.0.9', 'sport': 57976, 'dst': '192.168.0.4', 'dport': 53, 'offset': 389762, 'time': 1681841038.828795}, {'src': '192.168.0.9', 'sport': 55258, 'dst': '192.168.0.4', 'dport': 53, 'offset': 389849, 'time': 1681841038.829088}, {'src': '192.168.0.9', 'sport': 52219, 'dst': '192.168.0.4', 'dport': 53, 'offset': 389936, 'time': 1681841038.829903}, {'src': '192.168.0.9', 'sport': 60514, 'dst': '192.168.0.4', 'dport': 53, 'offset': 390023, 'time': 1681841038.83014}, {'src': '192.168.0.9', 'sport': 64243, 'dst': '192.168.0.4', 'dport': 53, 'offset': 390197, 'time': 1681841038.83061}, {'src': '192.168.0.9', 'sport': 52528, 'dst': '192.168.0.4', 'dport': 53, 'offset': 390284, 'time': 1681841038.830917}, {'src': '192.168.0.9', 'sport': 60277, 'dst': '192.168.0.4', 'dport': 53, 'offset': 390371, 'time': 1681841038.831132}, {'src': '192.168.0.9', 'sport': 56706, 'dst': '192.168.0.4', 'dport': 53, 'offset': 390458, 'time': 1681841038.831412}, {'src': '192.168.0.9', 'sport': 55726, 'dst': '192.168.0.4', 'dport': 53, 'offset': 390545, 'time': 1681841038.832062}, {'src': '192.168.0.9', 'sport': 58570, 'dst': '192.168.0.4', 'dport': 53, 'offset': 390632, 'time': 1681841038.832379}, {'src': '192.168.0.9', 'sport': 55583, 'dst': '192.168.0.4', 'dport': 53, 'offset': 390719, 'time': 1681841038.832379}, {'src': '192.168.0.9', 'sport': 61095, 'dst': '192.168.0.4', 'dport': 53, 'offset': 390806, 'time': 1681841038.833037}, {'src': '192.168.0.9', 'sport': 59703, 'dst': '192.168.0.4', 'dport': 53, 'offset': 390893, 'time': 1681841038.833094}, {'src': '192.168.0.9', 'sport': 62819, 'dst': '192.168.0.4', 'dport': 53, 'offset': 390980, 'time': 1681841038.833256}, {'src': '192.168.0.9', 'sport': 62339, 'dst': '192.168.0.4', 'dport': 53, 'offset': 391067, 'time': 1681841038.834103}, {'src': '192.168.0.9', 'sport': 63743, 'dst': '192.168.0.4', 'dport': 53, 'offset': 391154, 'time': 1681841038.834419}, {'src': '192.168.0.9', 'sport': 52919, 'dst': '192.168.0.4', 'dport': 53, 'offset': 391241, 'time': 1681841038.834574}, {'src': '192.168.0.9', 'sport': 54751, 'dst': '192.168.0.4', 'dport': 53, 'offset': 391328, 'time': 1681841038.834719}, {'src': '192.168.0.9', 'sport': 62558, 'dst': '192.168.0.4', 'dport': 53, 'offset': 391415, 'time': 1681841038.834901}, {'src': '192.168.0.9', 'sport': 63465, 'dst': '192.168.0.4', 'dport': 53, 'offset': 391502, 'time': 1681841038.835142}, {'src': '192.168.0.9', 'sport': 51668, 'dst': '192.168.0.4', 'dport': 53, 'offset': 391589, 'time': 1681841038.835761}, {'src': '192.168.0.9', 'sport': 64767, 'dst': '192.168.0.4', 'dport': 53, 'offset': 391676, 'time': 1681841038.835826}, {'src': '192.168.0.9', 'sport': 54320, 'dst': '192.168.0.4', 'dport': 53, 'offset': 391763, 'time': 1681841038.836049}, {'src': '192.168.0.9', 'sport': 52692, 'dst': '192.168.0.4', 'dport': 53, 'offset': 391850, 'time': 1681841038.836424}, {'src': '192.168.0.9', 'sport': 59133, 'dst': '192.168.0.4', 'dport': 53, 'offset': 432093, 'time': 1681841050.194594}, {'src': '192.168.0.9', 'sport': 60684, 'dst': '192.168.0.4', 'dport': 53, 'offset': 433006, 'time': 1681841050.636039}, {'src': '192.168.0.9', 'sport': 65002, 'dst': '192.168.0.4', 'dport': 53, 'offset': 454718, 'time': 1681841099.961263}],
            'icmp': [{'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}, {'src': '192.168.0.9', 'dst': '192.168.0.4', 'type': 3, 'data': ''}],
            'http': [{'count': 1, 'host': 'pumyxiv.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pumyxiv.com\r\n\r\n', 'uri': 'http://pumyxiv.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lysyfyj.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lysyfyj.com\r\n\r\n', 'uri': 'http://lysyfyj.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'galyqaz.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: galyqaz.com\r\n\r\n', 'uri': 'http://galyqaz.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'vonyzuf.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vonyzuf.com\r\n\r\n', 'uri': 'http://vonyzuf.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qedyfyq.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qedyfyq.com\r\n\r\n', 'uri': 'http://qedyfyq.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qekyqop.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qekyqop.com\r\n\r\n', 'uri': 'http://qekyqop.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lymyxid.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lymyxid.com\r\n\r\n', 'uri': 'http://lymyxid.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lyryvex.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyryvex.com\r\n\r\n', 'uri': 'http://lyryvex.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'gadyfuh.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gadyfuh.com\r\n\r\n', 'uri': 'http://gadyfuh.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'vopybyt.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vopybyt.com\r\n\r\n', 'uri': 'http://vopybyt.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'puvytuq.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puvytuq.com\r\n\r\n', 'uri': 'http://puvytuq.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'volyqat.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: volyqat.com\r\n\r\n', 'uri': 'http://volyqat.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'vofygum.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vofygum.com\r\n\r\n', 'uri': 'http://vofygum.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qeqyxov.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qeqyxov.com\r\n\r\n', 'uri': 'http://qeqyxov.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'vowycac.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vowycac.com\r\n\r\n', 'uri': 'http://vowycac.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lyxywer.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyxywer.com\r\n\r\n', 'uri': 'http://lyxywer.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lygygin.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lygygin.com\r\n\r\n', 'uri': 'http://lygygin.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'gaqycos.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gaqycos.com\r\n\r\n', 'uri': 'http://gaqycos.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qexyryl.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qexyryl.com\r\n\r\n', 'uri': 'http://qexyryl.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'vojyjof.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vojyjof.com\r\n\r\n', 'uri': 'http://vojyjof.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'gahyhob.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gahyhob.com\r\n\r\n', 'uri': 'http://gahyhob.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qetyvep.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qetyvep.com\r\n\r\n', 'uri': 'http://qetyvep.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qegyhig.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qegyhig.com\r\n\r\n', 'uri': 'http://qegyhig.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'vocyruk.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vocyruk.com\r\n\r\n', 'uri': 'http://vocyruk.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qegyqaq.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qegyqaq.com\r\n\r\n', 'uri': 'http://qegyqaq.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'purydyv.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: purydyv.com\r\n\r\n', 'uri': 'http://purydyv.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lyvytuj.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyvytuj.com\r\n\r\n', 'uri': 'http://lyvytuj.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qeqysag.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qeqysag.com\r\n\r\n', 'uri': 'http://qeqysag.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lyxylux.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyxylux.com\r\n\r\n', 'uri': 'http://lyxylux.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'puzywel.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puzywel.com\r\n\r\n', 'uri': 'http://puzywel.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'gaqydeb.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gaqydeb.com\r\n\r\n', 'uri': 'http://gaqydeb.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lysynur.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lysynur.com\r\n\r\n', 'uri': 'http://lysynur.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'vofymik.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vofymik.com\r\n\r\n', 'uri': 'http://vofymik.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'pufygug.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pufygug.com\r\n\r\n', 'uri': 'http://pufygug.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'puvyxil.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puvyxil.com\r\n\r\n', 'uri': 'http://puvyxil.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'volykyc.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: volykyc.com\r\n\r\n', 'uri': 'http://volykyc.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'pujyjav.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pujyjav.com\r\n\r\n', 'uri': 'http://pujyjav.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qexylup.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qexylup.com\r\n\r\n', 'uri': 'http://qexylup.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'pufymoq.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pufymoq.com\r\n\r\n', 'uri': 'http://pufymoq.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qebytiq.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qebytiq.com\r\n\r\n', 'uri': 'http://qebytiq.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'vowydef.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vowydef.com\r\n\r\n', 'uri': 'http://vowydef.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lykyjad.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lykyjad.com\r\n\r\n', 'uri': 'http://lykyjad.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'gacyryw.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gacyryw.com\r\n\r\n', 'uri': 'http://gacyryw.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'ganypih.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: ganypih.com\r\n\r\n', 'uri': 'http://ganypih.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'pupybul.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pupybul.com\r\n\r\n', 'uri': 'http://pupybul.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'galykes.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: galykes.com\r\n\r\n', 'uri': 'http://galykes.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qekykev.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qekykev.com\r\n\r\n', 'uri': 'http://qekykev.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'pumypog.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pumypog.com\r\n\r\n', 'uri': 'http://pumypog.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lygymoj.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lygymoj.com\r\n\r\n', 'uri': 'http://lygymoj.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'gatyvyz.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gatyvyz.com\r\n\r\n', 'uri': 'http://gatyvyz.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'gacyzuz.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gacyzuz.com\r\n\r\n', 'uri': 'http://gacyzuz.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'vonypom.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vonypom.com\r\n\r\n', 'uri': 'http://vonypom.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lyryfyd.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyryfyd.com\r\n\r\n', 'uri': 'http://lyryfyd.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'vocyzit.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vocyzit.com\r\n\r\n', 'uri': 'http://vocyzit.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'purycap.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: purycap.com\r\n\r\n', 'uri': 'http://purycap.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'gadyniw.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gadyniw.com\r\n\r\n', 'uri': 'http://gadyniw.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qedynul.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qedynul.com\r\n\r\n', 'uri': 'http://qedynul.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lymysan.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lymysan.com\r\n\r\n', 'uri': 'http://lymysan.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'gahyqah.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gahyqah.com\r\n\r\n', 'uri': 'http://gahyqah.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'puzylyp.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puzylyp.com\r\n\r\n', 'uri': 'http://puzylyp.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'vojyqem.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vojyqem.com\r\n\r\n', 'uri': 'http://vojyqem.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qetyfuv.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qetyfuv.com\r\n\r\n', 'uri': 'http://qetyfuv.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'gatyfus.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gatyfus.com\r\n\r\n', 'uri': 'http://gatyfus.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'lyvyxor.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyvyxor.com\r\n\r\n', 'uri': 'http://lyvyxor.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'ganyhus.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: ganyhus.com\r\n\r\n', 'uri': 'http://ganyhus.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}, {'count': 1, 'host': 'qetyraq.com', 'port': 80, 'data': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qetyraq.com\r\n\r\n', 'uri': 'http://qetyraq.com/login.php', 'body': '', 'path': '/login.php', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'version': '1.1', 'method': 'GET'}],
            'dns': [{'request': '4.100.163.10.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.inetsim.org'}]}, {'request': '170.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.microsoft.com'}]}, {'request': '80.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'crl.microsoft.com'}]}, {'request': '42.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'xisac.com'}]}, {'request': '254.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.binomopro.com'}]}, {'request': '192.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.hongfei8888.com'}]}, {'request': '84.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.generto.com'}]}, {'request': '123.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.cuetechkorea.com'}]}, {'request': '232.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.billiejeansaustin.com'}]}, {'request': '58.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.budgetslacker.com'}]}, {'request': '238.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'cacerts.digicert.com'}]}, {'request': '74.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.thediplomatrealty.com'}]}, {'request': '240.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'host-host-file8.com'}]}, {'request': '153.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'mail.metahan.com'}]}, {'request': '15.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'piratia.su'}]}, {'request': '45.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.lawrencecountyfirechiefs.com'}]}, {'request': '124.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.lateliergc.com'}]}, {'request': '172.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'sw.symcd.com'}]}, {'request': '82.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'does-not-exist.example.com'}]}, {'request': '13.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'go.microsoft.com'}]}, {'request': '92.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.tokendownload.space'}]}, {'request': '106.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'apexhometutors.com'}]}, {'request': '44.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.sqlite.org'}]}, {'request': '167.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'smartbubox.com'}]}, {'request': '133.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.debbiepatrickdesigns.com'}]}, {'request': '28.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.businessminds.click'}]}, {'request': '25.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.aurabrewing.com'}]}, {'request': '43.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.tarmac.one'}]}, {'request': '212.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'xfinity.com'}]}, {'request': '251.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.berkellandschap.online'}]}, {'request': '34.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'ff73a3y6qy75djp8.8rh3omqgx3ldiielje'}]}, {'request': '99.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.yildizcammozaik.com'}]}, {'request': '54.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.gaoguiclub.com'}]}, {'request': '219.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.eventualstudios.com'}]}, {'request': '94.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.crusadia.net'}]}, {'request': '33.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'december2n.duckdns.org'}]}, {'request': '155.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.fyifamilies.co.uk'}]}, {'request': '78.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'api.telegram.org'}]}, {'request': '85.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.digitalpro.africa'}]}, {'request': '18.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'dowe.at'}]}, {'request': '60.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'hamzzagolozar.loseyourip.com'}]}, {'request': '67.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.mcarmen.info'}]}, {'request': '6.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'crl4.digicert.com'}]}, {'request': '173.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.vatsalpr.buzz'}]}, {'request': '198.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 's.symcb.com'}]}, {'request': '19.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'fyyhgnqeknid5wan.vxsq2hxc5q61qlncqtwrwsv06'}]}, {'request': '57.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'blockchain.info'}]}, {'request': '203.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.mctier.store'}]}, {'request': '162.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.foodmarty.online'}]}, {'request': '200.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'settings-win.data.microsoft.com'}]}, {'request': '208.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'smtpjs.com'}]}, {'request': '120.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.dersameh.com'}]}, {'request': '178.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.debrafalzoi.com'}]}, {'request': '139.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.store1995.store'}]}, {'request': '91.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.sjcamden.church'}]}, {'request': '217.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'trictomm.duckdns.org'}]}, {'request': '246.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'metazone1.com'}]}, {'request': '131.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.sinymp.com'}]}, {'request': '125.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'jmesk5cqf.lfa8zx7twe1cx9a5cndt'}]}, {'request': '181.2.0.192.in-addr.arpa', 'type': 'PTR', 'answers': [{'type': 'PTR', 'data': 'www.movrapid.com'}]}, {'type': 'A', 'request': 'lykyvor.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyrem.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyjuc.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzydog.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyfeb.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyqiw.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrywoj.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupyteg.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojycit.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxyfan.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyfag.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyxup.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvygyd.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvygyv.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofyzyc.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocygef.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysytyn.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyrah.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volybak.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujycil.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyqul.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahycuz.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purywoq.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyxux.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyhuv.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymyjix.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufyxyp.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyqik.com', 'answers': [], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyraq.com', 'answers': [{'data': '192.0.2.85', 'type': 'A'}], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyhus.com', 'answers': [{'data': '192.0.2.181', 'type': 'A'}], 'time': '2023-04-18 18:03:44.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'DESKTOP-LG3F6GA', 'answers': [{'data': '192.168.0.9', 'type': 'A'}], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyvol.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumyjip.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyvaw.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedytyg.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzybeq.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadypub.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqykop.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofypuf.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxynej.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqykoz.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexynyq.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujydap.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyzyw.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvymug.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahydos.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purylal.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufypuv.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryler.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacynyh.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatypuz.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvyjoj.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvyjiq.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetytup.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyvab.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebykoq.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowykat.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygysid.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocymum.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegysiv.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojydoc.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyput.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykyfax.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojybef.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purytyp.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvymun.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetylel.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyqig.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyres.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxygur.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufycog.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyvon.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyqib.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysysir.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonykam.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykynyd.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganykah.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyzyk.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupypil.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volygyt.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupyxuq.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyxuq.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyfep.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymywad.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzygyl.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyqof.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyrav.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofycim.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyvag.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyfez.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadycih.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumywov.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyxuj.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyhul.com', 'answers': [], 'time': '2023-04-18 18:03:32', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyrec.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyhuw.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyjik.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrytyx.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujybev.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekynyv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumyleg.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galynus.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedysol.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volymuc.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymylen.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowypim.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufybyl.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyfej.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahynuw.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzymup.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetysog.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatydab.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebylyp.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujymiq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygynyr.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacykas.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puryxuv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegynul.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryson.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqypuh.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofybet.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyvez.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyvax.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykygun.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyhib.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufydaq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofydak.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadydow.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyqip.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyzuf.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyrel.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqylyg.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyzyb.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyqoz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocykec.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatycis.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyfeq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryxud.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvywal.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyfyh.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxymix.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyqot.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyxiv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopydaf.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvylyx.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvylep.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purypig.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyvap.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopycoc.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvywar.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojygym.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujygug.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyhug.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexykav.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzyjov.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymytuj.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyrew.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupycop.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyryk.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumytyq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqytuq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volyjif.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxyjod.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojymuk.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyzuz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykymij.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupydev.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyqoq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyzut.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadynub.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyzuh.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujyjol.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojyjot.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganypis.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzylyq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqysap.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofymif.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxylyj.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygymod.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purydel.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volyqam.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumyxul.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyhiz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvytuv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyhip.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyveq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyryb.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyreg.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyfys.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygygux.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowycok.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzywag.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqydaz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyfyv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyxil.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyqas.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedynug.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofyguc.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyqoh.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purycaq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyveh.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymyxir.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyfed.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxywen.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykyjar.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupybyg.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysynun.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyqov.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvyxig.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galykew.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqycow.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekykal.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymysox.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowydet.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volykek.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvytud.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopybym.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebytuv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufygup.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyfuw.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumypop.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyluq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyryf.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryvaj.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufymiv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonypic.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyzum.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryfyr.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyfyl.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojyqac.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujywep.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyxog.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvyxin.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganycob.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupymol.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykylud.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyvys.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopymit.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujylyv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebysaq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyniz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojykyf.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegykeg.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacypiw.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyguk.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykywex.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexytil.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxytur.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofyjom.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupyguq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzytul.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyryp.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyhoh.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonycaf.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysygij.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volyrut.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyhiq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumycav.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyryz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymyved.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyvev.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufyjag.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyjan.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowybyc.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purybup.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonydem.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahykeb.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocypok.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrynux.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvypoq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyqaw.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofyqek.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvysaj.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxyxox.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysymor.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganydeh.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyluv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyzus.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumydyg.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymyfyn.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufyweq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyqal.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetynup.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyfug.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzyxip.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volyzic.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyfub.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyguf.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyxop.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygywyj.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacycaz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purygiv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyryq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvycel.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrygid.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyruh.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocycat.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupyjap.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volypof.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymynuj.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadykyz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyrus.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzyceg.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymygor.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyniq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyqag.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purymog.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojyzik.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvydyp.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryman.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocydyc.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyhov.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojyrum.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygylur.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedykep.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galypob.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujytug.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvyver.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyhos.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyjex.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonybuk.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyvyl.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyjac.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekytig.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyvyw.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykytin.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxysad.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofyruc.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacydes.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufylul.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvyfux.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujyxoq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyqef.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumybuq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzypav.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexysev.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofykyt.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowymom.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegylul.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyziw.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxyvyn.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volycem.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyruv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykyxoj.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyfup.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqynih.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyxaq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupywyv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyqeb.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyfuz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysywyd.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galycah.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumygil.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonygit.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyhol.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyhaw.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufytip.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyjak.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyvyg.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygytix.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyvub.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufyxov.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvybuv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocybuf.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahypoz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryjej.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetykyq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojypat.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegytop.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puryjeq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyniv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopykum.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykyser.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofyzof.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyqep.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganynos.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxyfuj.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyqez.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyfuq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyqyt.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyfih.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujypal.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volydyk.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyxad.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatykyh.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymymax.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupylug.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyzib.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzyduq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonymoc.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvynid.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumyjev.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyces.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyxav.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrywur.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyruw.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyrik.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupytiq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galydyw.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyvuz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysytoj.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedylig.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedytoq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekysel.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysylun.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumymap.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyhag.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykyvyx.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purywyl.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyrul.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocygim.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojycec.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvygon.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujycyp.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvygog.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyhab.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyvup.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyjef.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymyjyd.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volybut.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadypah.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzybil.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofypam.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqykyv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxynir.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyxar.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumywug.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyzot.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyxel.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyqym.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyfiv.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygysen.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetylip.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojyduf.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyqeq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexynol.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufypeg.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyqyh.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahydyb.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvymej.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyfis.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyzoz.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowykuc.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvymaq.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqykus.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purylup.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupyxal.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volygoc.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocymak.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrylix.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegysyg.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykyfud.com', 'answers': [], 'time': '2023-04-18 18:03:31', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacynow.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykynon.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujyduv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujybig.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonykuk.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganykuw.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopypec.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatypas.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvyjyr.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebykul.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrytod.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvyjyl.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojybim.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyjet.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purytov.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyvuj.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymywun.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyrif.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzygop.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadycew.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofycyk.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyhez.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxygax.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyrib.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyrug.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufycyq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyhap.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysysyx.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galynab.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetytav.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyvuq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyvuh.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupypep.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumyliq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekynog.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volymaf.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedysyp.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyquc.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyrot.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupycuv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrysyj.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetysuq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacykub.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegynap.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygynox.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volyjym.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxyjun.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofydut.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyheh.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyzoh.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyvud.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyvuv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexykug.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxymed.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyqyv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymytar.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purypyq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocykif.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqypew.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyfil.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufybop.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyfow.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowypek.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufydul.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymylij.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqytal.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvywup.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofybic.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyxeg.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyvis.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyduz.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyloq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopycyf.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzymev.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryxen.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojygok.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahynaz.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvyliv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyzam.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykygaj.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatycyb.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojymet.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyqys.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puryxag.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujygaq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumytol.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyfir.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyriz.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzyjyg.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvylod.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyrip.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvywux.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyduh.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyheq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujymel.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebylov.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopydum.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykymyr.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyzas.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyqyl.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupydig.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumypyv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyhys.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyzac.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvyxeq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofygaf.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyquw.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryvur.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyfob.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowycut.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purycul.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopybok.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyvil.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvytan.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyviw.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyhev.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyteg.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupyboq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyrom.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujyjup.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykyjux.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyqug.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyroh.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonypyf.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekykup.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqycyz.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyriq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxywij.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyxyp.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysynaj.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzylol.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyneh.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volykit.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzywuq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyged.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqysuv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymysud.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymyxex.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volyquk.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufymyg.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowydic.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygymyn.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyzaw.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purydip.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganypeb.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedynaq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyfin.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumyxep.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyfog.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyzek.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryfox.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyqub.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyfop.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojyjyc.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvytag.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofymem.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galykiz.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufygav.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvyxyj.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexylal.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxylor.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqydus.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojyquf.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyfaz.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujywiv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyquz.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyvig.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojykom.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxytex.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyfaq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymyfoj.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyqup.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufyjuq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowybof.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekylag.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumydoq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonydik.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyzeb.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacypyz.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysymux.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexytep.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volyzef.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupymyp.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyjuj.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganydiw.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocypyt.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purybav.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopymyc.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebysul.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegykiq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrynad.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujylog.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykywid.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzyxyv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofyjuk.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofyqit.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzytap.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxyxyd.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyxuv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetynev.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatynes.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyxyq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopygat.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahykih.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyrov.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonycum.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyger.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyros.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyvob.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganycuh.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygywor.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupygel.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvysur.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purygeg.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufywil.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacycus.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvypul.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyhyl.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyhyw.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymyvin.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volyrac.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykylan.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumycug.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyraw.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrygyn.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowygem.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyfah.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyrol.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocycuc.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzyciq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyrab.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvyfad.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvyvix.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykyxur.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyfes.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedykiv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzypug.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysywon.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowymyk.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyxul.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvycip.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyhyg.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojyrak.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvydov.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofyref.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyhub.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujyteq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujyxyl.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyvop.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyjuf.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupyjuv.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyqih.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykytej.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojyzyt.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyquq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyzez.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrymuj.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyvoz.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonybat.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekytyq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocydof.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegylep.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofykoc.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyhuz.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyhup.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymygyx.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyjut.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purymuq.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymyner.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyjid.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufylap.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqynyw.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volypum.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxyvoj.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexysig.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxysun.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galypyh.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadykos.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqynel.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacydib.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygylax.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyqim.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyfav.com', 'answers': [], 'time': '2023-04-18 18:03:30', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumybal.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumygyp.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupywog.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyrag.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonygec.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galycuw.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volycik.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufytev.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyvoq.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygytyd.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyqiv.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyfel.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puryjil.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxyfar.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegytyv.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufyxug.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryjir.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyxun.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvybeg.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofyzym.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetykol.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyvah.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyqis.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzydal.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupylaq.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyvas.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojypuc.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahypus.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatykow.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysytyr.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocybam.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymymud.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyzyh.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyfew.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyleq.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volydot.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyhuq.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysylej.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekysip.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojycif.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykysix.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyvav.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrywax.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyxug.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocygyk.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvyguj.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujycov.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purywop.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyjim.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupytyl.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volybec.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykyvod.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahycib.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyrap.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujypup.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyhuh.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyrez.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyqoc.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvygyq.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumymuv.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganynyb.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopykak.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvynen.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonymuf.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebynyg.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyret.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galydoz.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumyjig.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedytul.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymyjon.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadypuw.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzybep.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqykog.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofypuk.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahydoh.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufypiq.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumywaq.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyvar.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqykab.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvymul.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygysij.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexynyp.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyvew.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocymut.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacynuz.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purylev.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetylyv.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegysoq.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojydam.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyqil.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyqow.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopypif.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujydag.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvymir.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyzys.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykyfen.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvyjop.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekynuq.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupyxup.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufycol.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyciz.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyxux.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyfeg.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzyguv.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyqok.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofycot.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyfyb.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymywaj.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyxip.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volygyf.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxygud.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyreh.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyval.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupypiv.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyhuv.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykynyj.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyrym.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebykap.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyhis.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujybyq.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purytyg.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxynyx.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyjic.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopyzuc.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowykaf.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrytun.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyreq.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatypub.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryled.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojybek.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetytug.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganykaz.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvyjox.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyket.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysysod.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galynuh.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumylel.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedysov.com', 'answers': [], 'time': '2023-04-18 18:03:29', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqylyl.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puryxuq.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvywav.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojygut.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volymum.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofydac.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqyzuw.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyqog.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyxiq.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxymin.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyfyz.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadydas.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzymig.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyqaf.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryxij.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymylyr.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvywed.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufydep.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowyzuk.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyqob.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopycom.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujygul.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatycoh.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyfyp.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygyfex.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyvan.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykygur.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufybyv.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojymic.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyhil.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyrys.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumytup.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofybyf.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzyjoq.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqytup.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyveg.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxyjaj.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymytux.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqypiz.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupycag.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebyrev.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyveb.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyryc.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyhiw.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volyjok.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupydeq.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexykaq.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatydaw.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahynus.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacykeh.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purypol.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyrysor.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebylug.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetysal.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegynuv.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocykem.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvylyn.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowypit.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvylyg.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujymip.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygynud.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopydek.com', 'answers': [], 'time': '2023-04-18 18:03:17', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganyzub.com', 'answers': [], 'time': '2023-04-18 18:03:16', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykymox.com', 'answers': [], 'time': '2023-04-18 18:03:16', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvyxor.com', 'answers': [{'data': '192.0.2.57', 'type': 'A'}], 'time': '2023-04-18 18:03:04.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyfus.com', 'answers': [{'data': '192.0.2.125', 'type': 'A'}], 'time': '2023-04-18 18:03:04.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyfuv.com', 'answers': [{'data': '192.0.2.131', 'type': 'A'}], 'time': '2023-04-18 18:03:04.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojyqem.com', 'answers': [{'data': '192.0.2.217', 'type': 'A'}], 'time': '2023-04-18 18:03:04.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzylyp.com', 'answers': [{'data': '192.0.2.246', 'type': 'A'}], 'time': '2023-04-18 18:03:04.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyqah.com', 'answers': [{'data': '192.0.2.91', 'type': 'A'}], 'time': '2023-04-18 18:03:04.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymysan.com', 'answers': [{'data': '192.0.2.139', 'type': 'A'}], 'time': '2023-04-18 18:03:04.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedynul.com', 'answers': [{'data': '192.0.2.120', 'type': 'A'}], 'time': '2023-04-18 18:03:04.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyniw.com', 'answers': [{'data': '192.0.2.208', 'type': 'A'}], 'time': '2023-04-18 18:03:04.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purycap.com', 'answers': [{'data': '192.0.2.200', 'type': 'A'}], 'time': '2023-04-18 18:03:04.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyzit.com', 'answers': [{'data': '192.0.2.178', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryfyd.com', 'answers': [{'data': '192.0.2.162', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonypom.com', 'answers': [{'data': '192.0.2.203', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyzuz.com', 'answers': [{'data': '192.0.2.28', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gatyvyz.com', 'answers': [{'data': '192.0.2.254', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygymoj.com', 'answers': [{'data': '192.0.2.198', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumypog.com', 'answers': [{'data': '192.0.2.173', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekykev.com', 'answers': [{'data': '192.0.2.67', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galykes.com', 'answers': [{'data': '192.0.2.57', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pupybul.com', 'answers': [{'data': '192.0.2.19', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'ganypih.com', 'answers': [{'data': '192.0.2.43', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gacyryw.com', 'answers': [{'data': '192.0.2.6', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lykyjad.com', 'answers': [{'data': '192.0.2.153', 'type': 'A'}], 'time': '2023-04-18 18:03:03.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowydef.com', 'answers': [{'data': '192.0.2.67', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qebytiq.com', 'answers': [{'data': '192.0.2.18', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufymoq.com', 'answers': [{'data': '192.0.2.94', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexylup.com', 'answers': [{'data': '192.0.2.54', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pujyjav.com', 'answers': [{'data': '192.0.2.155', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volykyc.com', 'answers': [{'data': '192.0.2.219', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvyxil.com', 'answers': [{'data': '192.0.2.33', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pufygug.com', 'answers': [{'data': '192.0.2.99', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofymik.com', 'answers': [{'data': '192.0.2.78', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysynur.com', 'answers': [{'data': '192.0.2.85', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqydeb.com', 'answers': [{'data': '192.0.2.167', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puzywel.com', 'answers': [{'data': '192.0.2.34', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxylux.com', 'answers': [{'data': '192.0.2.212', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqysag.com', 'answers': [{'data': '192.0.2.251', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyvytuj.com', 'answers': [{'data': '192.0.2.43', 'type': 'A'}], 'time': '2023-04-18 18:03:02.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'purydyv.com', 'answers': [{'data': '192.0.2.60', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyqaq.com', 'answers': [{'data': '192.0.2.25', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vocyruk.com', 'answers': [{'data': '192.0.2.28', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qegyhig.com', 'answers': [{'data': '192.0.2.172', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qetyvep.com', 'answers': [{'data': '192.0.2.133', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gahyhob.com', 'answers': [{'data': '192.0.2.106', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vojyjof.com', 'answers': [{'data': '192.0.2.92', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qexyryl.com', 'answers': [{'data': '192.0.2.167', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gaqycos.com', 'answers': [{'data': '192.0.2.44', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lygygin.com', 'answers': [{'data': '192.0.2.82', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyxywer.com', 'answers': [{'data': '192.0.2.92', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vowycac.com', 'answers': [{'data': '192.0.2.13', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qeqyxov.com', 'answers': [{'data': '192.0.2.172', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vofygum.com', 'answers': [{'data': '192.0.2.45', 'type': 'A'}], 'time': '2023-04-18 18:03:01.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'volyqat.com', 'answers': [{'data': '192.0.2.15', 'type': 'A'}], 'time': '2023-04-18 18:03:00.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'puvytuq.com', 'answers': [{'data': '192.0.2.124', 'type': 'A'}], 'time': '2023-04-18 18:03:00.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vopybyt.com', 'answers': [{'data': '192.0.2.153', 'type': 'A'}], 'time': '2023-04-18 18:03:00.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'gadyfuh.com', 'answers': [{'data': '192.0.2.240', 'type': 'A'}], 'time': '2023-04-18 18:03:00.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lyryvex.com', 'answers': [{'data': '192.0.2.74', 'type': 'A'}], 'time': '2023-04-18 18:03:00.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lymyxid.com', 'answers': [{'data': '192.0.2.238', 'type': 'A'}], 'time': '2023-04-18 18:03:00.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qekyqop.com', 'answers': [{'data': '192.0.2.232', 'type': 'A'}], 'time': '2023-04-18 18:03:00.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'qedyfyq.com', 'answers': [{'data': '192.0.2.123', 'type': 'A'}], 'time': '2023-04-18 18:03:00.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'vonyzuf.com', 'answers': [{'data': '192.0.2.192', 'type': 'A'}], 'time': '2023-04-18 18:03:00.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'galyqaz.com', 'answers': [{'data': '192.0.2.58', 'type': 'A'}], 'time': '2023-04-18 18:03:00.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'lysyfyj.com', 'answers': [{'data': '192.0.2.84', 'type': 'A'}], 'time': '2023-04-18 18:03:00.000', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}, {'type': 'A', 'request': 'pumyxiv.com', 'answers': [{'data': '192.0.2.254', 'type': 'A'}], 'time': '2023-04-18 18:02:59', 'guid': '{61a591c8-db51-643e-df02-000000002200}', 'pid': 4820, 'image': 'C:\\Windows\\apppatch\\svchost.exe'}],
            'smtp': [],
            'irc': [],
            'dead_hosts': [['192.0.2.42', 80]],
            'http_ex': [{'src': '192.168.0.9', 'sport': 50000, 'dst': '192.0.2.254', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'pumyxiv.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pumyxiv.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nDate: Tue, 18 Apr 2023 18:03:01 GMT\r\nConnection: Close\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50002, 'dst': '192.0.2.84', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lysyfyj.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lysyfyj.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:01 GMT\r\nConnection: Close\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50004, 'dst': '192.0.2.58', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'galyqaz.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: galyqaz.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:01 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50006, 'dst': '192.0.2.192', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'vonyzuf.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vonyzuf.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50008, 'dst': '192.0.2.123', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qedyfyq.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qedyfyq.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT\r\nConnection: Close\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50010, 'dst': '192.0.2.232', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qekyqop.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qekyqop.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT\r\nConnection: Close\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50012, 'dst': '192.0.2.238', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lymyxid.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lymyxid.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50014, 'dst': '192.0.2.74', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lyryvex.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyryvex.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50016, 'dst': '192.0.2.240', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'gadyfuh.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gadyfuh.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50018, 'dst': '192.0.2.153', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'vopybyt.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vopybyt.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT\r\nConnection: Close', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50020, 'dst': '192.0.2.124', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'puvytuq.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puvytuq.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT\r\nConnection: Close', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50022, 'dst': '192.0.2.15', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'volyqat.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: volyqat.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50024, 'dst': '192.0.2.45', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'vofygum.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vofygum.com', 'response': 'HTTP/1.1 200 OK\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50026, 'dst': '192.0.2.172', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qeqyxov.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qeqyxov.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT\r\nConnection: Close\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50028, 'dst': '192.0.2.13', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'vowycac.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vowycac.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:02 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50030, 'dst': '192.0.2.92', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lyxywer.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyxywer.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nConnection: Close\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50032, 'dst': '192.0.2.82', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lygygin.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lygygin.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50034, 'dst': '192.0.2.44', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'gaqycos.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gaqycos.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nConnection: Close\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50036, 'dst': '192.0.2.167', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qexyryl.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qexyryl.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nConnection: Close\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50038, 'dst': '192.0.2.92', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'vojyjof.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vojyjof.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nConnection: Close', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50040, 'dst': '192.0.2.106', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'gahyhob.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gahyhob.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50042, 'dst': '192.0.2.133', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qetyvep.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qetyvep.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50044, 'dst': '192.0.2.172', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qegyhig.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qegyhig.com', 'response': 'HTTP/1.1 200 OK\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50046, 'dst': '192.0.2.28', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'vocyruk.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vocyruk.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nConnection: Close\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50048, 'dst': '192.0.2.25', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qegyqaq.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qegyqaq.com', 'response': 'HTTP/1.1 200 OK\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50050, 'dst': '192.0.2.60', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'purydyv.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: purydyv.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50052, 'dst': '192.0.2.43', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lyvytuj.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyvytuj.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50054, 'dst': '192.0.2.251', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qeqysag.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qeqysag.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nConnection: Close', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50056, 'dst': '192.0.2.212', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lyxylux.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyxylux.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:03 GMT\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50058, 'dst': '192.0.2.34', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'puzywel.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puzywel.com', 'response': 'HTTP/1.1 200 OK\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50060, 'dst': '192.0.2.167', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'gaqydeb.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gaqydeb.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50062, 'dst': '192.0.2.85', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lysynur.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lysynur.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50064, 'dst': '192.0.2.78', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'vofymik.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vofymik.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50066, 'dst': '192.0.2.99', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'pufygug.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pufygug.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nConnection: Close\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50068, 'dst': '192.0.2.33', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'puvyxil.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puvyxil.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nConnection: Close', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50070, 'dst': '192.0.2.219', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'volykyc.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: volykyc.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nConnection: Close', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50072, 'dst': '192.0.2.155', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'pujyjav.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pujyjav.com', 'response': 'HTTP/1.1 200 OK\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50074, 'dst': '192.0.2.54', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qexylup.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qexylup.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50076, 'dst': '192.0.2.94', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'pufymoq.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pufymoq.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50078, 'dst': '192.0.2.18', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qebytiq.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qebytiq.com', 'response': 'HTTP/1.1 200 OK\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50080, 'dst': '192.0.2.67', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'vowydef.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vowydef.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50082, 'dst': '192.0.2.153', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lykyjad.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lykyjad.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50084, 'dst': '192.0.2.6', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'gacyryw.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gacyryw.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:04 GMT\r\nConnection: Close\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50086, 'dst': '192.0.2.43', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'ganypih.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: ganypih.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nConnection: Close\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50088, 'dst': '192.0.2.19', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'pupybul.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pupybul.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nConnection: Close\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50090, 'dst': '192.0.2.57', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'galykes.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: galykes.com', 'response': 'HTTP/1.1 200 OK\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50092, 'dst': '192.0.2.67', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qekykev.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qekykev.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50094, 'dst': '192.0.2.173', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'pumypog.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pumypog.com', 'response': 'HTTP/1.1 200 OK\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50096, 'dst': '192.0.2.198', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lygymoj.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lygymoj.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50098, 'dst': '192.0.2.254', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'gatyvyz.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gatyvyz.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nConnection: Close\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50100, 'dst': '192.0.2.28', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'gacyzuz.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gacyzuz.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nConnection: Close\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50102, 'dst': '192.0.2.203', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'vonypom.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vonypom.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nConnection: Close\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50104, 'dst': '192.0.2.162', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lyryfyd.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyryfyd.com', 'response': 'HTTP/1.1 200 OK\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50106, 'dst': '192.0.2.178', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'vocyzit.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vocyzit.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nConnection: Close\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50108, 'dst': '192.0.2.200', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'purycap.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: purycap.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50110, 'dst': '192.0.2.208', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'gadyniw.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gadyniw.com', 'response': 'HTTP/1.1 200 OK\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:05 GMT\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50112, 'dst': '192.0.2.120', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qedynul.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qedynul.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Length: 258\r\nServer: INetSim HTTP Server\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:06 GMT', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50114, 'dst': '192.0.2.139', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lymysan.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lymysan.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:06 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50116, 'dst': '192.0.2.91', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'gahyqah.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gahyqah.com', 'response': 'HTTP/1.1 200 OK\r\nServer: INetSim HTTP Server\r\nContent-Length: 258\r\nDate: Tue, 18 Apr 2023 18:03:06 GMT\r\nConnection: Close\r\nContent-Type: text/html', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50118, 'dst': '192.0.2.246', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'puzylyp.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puzylyp.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:06 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50120, 'dst': '192.0.2.217', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'vojyqem.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vojyqem.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:06 GMT\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50122, 'dst': '192.0.2.131', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qetyfuv.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qetyfuv.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:06 GMT\r\nConnection: Close\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50124, 'dst': '192.0.2.125', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'gatyfus.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gatyfus.com', 'response': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nDate: Tue, 18 Apr 2023 18:03:06 GMT\r\nConnection: Close\r\nContent-Length: 258\r\nServer: INetSim HTTP Server', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50126, 'dst': '192.0.2.57', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'lyvyxor.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyvyxor.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:06 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50216, 'dst': '192.0.2.181', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'ganyhus.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: ganyhus.com', 'response': 'HTTP/1.1 200 OK\r\nDate: Tue, 18 Apr 2023 18:03:46 GMT\r\nConnection: Close\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}, {'src': '192.168.0.9', 'sport': 50217, 'dst': '192.0.2.85', 'dport': 80, 'protocol': 'http', 'method': 'GET', 'host': 'qetyraq.com', 'uri': '/login.php', 'status': 200, 'request': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qetyraq.com', 'response': 'HTTP/1.1 200 OK\r\nConnection: Close\r\nDate: Tue, 18 Apr 2023 18:03:46 GMT\r\nContent-Type: text/html\r\nServer: INetSim HTTP Server\r\nContent-Length: 258', 'resp': {'md5': 'be5eae9bd85769bce02d6e52a4927bcd', 'sha1': 'c4489a059a38e94b666edcb0f9facbf823b142d0', 'sha256': 'f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0', 'preview': ['00000000  3c 68 74 6d 6c 3e 0a 20  20 3c 68 65 61 64 3e 0a  |<html>.  <head>.|', '00000010  20 20 20 20 3c 74 69 74  6c 65 3e 49 4e 65 74 53  |    <title>INetS|', '00000020  69 6d 20 64 65 66 61 75  6c 74 20 48 54 4d 4c 20  |im default HTML |'], 'path': '/opt/CAPEv2/storage/analyses/250343/network/f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0'}}],
            'https_ex': [],
            'smtp_ex': []
        }
        parent_result_section = ResultSection("blah")
        ontres = OntologyResults(service_name="blah")
        sandbox = ontres.create_sandbox(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), sandbox_name="CAPE")
        ontres.add_sandbox(sandbox)
        process_map = {
            4820: {'name': 'C:\\Windows\\apppatch\\svchost.exe', 'network_calls': [{'InternetConnectA': {'service': '3', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatyfus.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojyqem.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetyfuv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvyxil.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvyxor.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahyqah.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyryfyd.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegyqaq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacyzuz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygymoj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowydef.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexylup.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufymoq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqydeb.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxylux.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofymik.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqysag.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzylyp.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyniw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymysan.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volykyc.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedynul.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumypog.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galykes.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysynur.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonypom.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekykev.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupybul.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopybyt.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebytiq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujyjav.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatyvyz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvytuj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocyzit.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojyjof.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purydyv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetyvep.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvytuq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahyhob.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocyruk.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegyhig.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purycap.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowycac.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufygug.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqycos.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxywer.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofygum.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqyxov.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzywel.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyfuh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymyxid.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galyqaz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumyxiv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysyfyj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonyzuf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekyqop.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyryvex.com', 'serverport': '80'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pumyxiv.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://pumyxiv.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lysyfyj.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lysyfyj.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: galyqaz.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://galyqaz.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vonyzuf.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://vonyzuf.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qedyfyq.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qedyfyq.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qekyqop.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qekyqop.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lymyxid.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lymyxid.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyryvex.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lyryvex.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gadyfuh.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://gadyfuh.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vopybyt.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://vopybyt.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puvytuq.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://puvytuq.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: volyqat.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://volyqat.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vofygum.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://vofygum.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qeqyxov.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qeqyxov.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vowycac.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://vowycac.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyxywer.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lyxywer.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lygygin.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lygygin.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gaqycos.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://gaqycos.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qexyryl.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qexyryl.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vojyjof.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://vojyjof.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gahyhob.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://gahyhob.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qetyvep.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qetyvep.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qegyhig.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qegyhig.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vocyruk.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://vocyruk.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qegyqaq.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qegyqaq.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: purydyv.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://purydyv.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyvytuj.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lyvytuj.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qeqysag.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qeqysag.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyxylux.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lyxylux.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puzywel.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://puzywel.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gaqydeb.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://gaqydeb.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lysynur.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lysynur.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vofymik.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://vofymik.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pufygug.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://pufygug.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puvyxil.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://puvyxil.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: volykyc.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://volykyc.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pujyjav.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://pujyjav.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qexylup.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qexylup.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pufymoq.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://pufymoq.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qebytiq.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qebytiq.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vowydef.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://vowydef.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lykyjad.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lykyjad.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gacyryw.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://gacyryw.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: ganypih.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://ganypih.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pupybul.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://pupybul.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: galykes.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://galykes.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qekykev.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qekykev.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: pumypog.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://pumypog.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lygymoj.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lygymoj.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gatyvyz.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://gatyvyz.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gacyzuz.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://gacyzuz.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vonypom.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://vonypom.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyryfyd.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lyryfyd.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vocyzit.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://vocyzit.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: purycap.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://purycap.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gadyniw.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://gadyniw.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qedynul.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qedynul.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lymysan.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lymysan.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gahyqah.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://gahyqah.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: puzylyp.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://puzylyp.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: vojyqem.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://vojyqem.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qetyfuv.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qetyfuv.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: gatyfus.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://gatyfus.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: lyvyxor.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://lyvyxor.com/login.php'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupydeq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganyzub.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykymox.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopydek.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebylug.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujymip.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatydaw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvylyn.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetysal.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvylyg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahynus.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyrysor.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocykem.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegynuv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purypol.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacykeh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygynud.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexykaq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowypit.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufybyv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxyjaj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofybyf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqytup.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzyjoq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyveb.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymytux.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volyjok.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumytup.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedyveg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galyhiw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonyryc.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysyvan.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekyhil.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojymic.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupycag.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganyrys.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykygur.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopycom.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebyrev.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujygul.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatycoh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvywed.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojygut.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetyxiq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvywav.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahyfyz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyryxij.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegyfyp.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacyqob.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygyfex.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowyzuk.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexyqog.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufydep.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqyzuw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puryxuq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxymin.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofydac.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqylyl.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzymig.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadydas.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymylyr.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volymum.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqypiz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocyqaf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedysov.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galynuh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysysod.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonyket.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekynuq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupypiv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganykaz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykynyj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopypif.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebykap.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujybyq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatypub.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvyjox.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojybek.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetytug.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvyjop.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahyvew.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyrytun.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocyjic.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegyval.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purytyg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacyhis.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygyvar.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowyrym.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexyhuv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufycol.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqyreh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxygud.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofycot.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqyreq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymywaj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volygyf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedyxip.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galyfyb.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyciz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysyxux.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzyguv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekyfeg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykyfen.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopyzuc.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebyqil.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujydag.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatyzys.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvymir.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojydam.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahydoh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyryled.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocymut.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegysoq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purylev.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacynuz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowykaf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygysij.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvymul.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexynyp.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufypiq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxynyx.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumylel.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupyxup.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetylyv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqykab.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganyqow.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumywaq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofypuk.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqykog.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzybep.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadypuw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymyjon.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volybec.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedytul.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumyjig.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galyvas.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysytyr.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonyjim.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekyvav.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupytyl.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganyhuh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykyvod.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopyret.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebyhuq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujycov.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvyguj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojycif.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetyrap.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvygyq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahycib.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyrywax.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocygyk.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegyxug.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purywop.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacyfew.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowyqoc.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexyfel.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofyzym.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxyfar.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufyxug.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqyqiv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqyqis.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzydal.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymymud.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volydot.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedyleq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumymuv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatyrez.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galydoz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysylej.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonymuf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekysip.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupylaq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganynyb.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykysix.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopykak.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebynyg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujypup.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatykow.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvynen.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojypuc.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetykol.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvybeg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahypus.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocybam.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyryjir.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puryjil.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegytyv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacyvah.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyzyh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygyxun.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygytyd.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexyvoq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufytev.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqyhuz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxyvoj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowyjut.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofyref.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqyhup.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzyciq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyrab.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymygyx.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volycik.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedyrag.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumygyp.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galycuw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysywon.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonygec.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekyxul.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganyfes.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupywog.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykyxur.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopyqim.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebyfav.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujyxyl.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatyqih.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvyfad.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojyzyt.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetyquq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvydov.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahyzez.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyrymuj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocydof.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purymuq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegylep.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygylax.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacydib.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufylap.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqynyw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxysun.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowymyk.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofykoc.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqynel.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzypug.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadykos.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymyner.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedykiv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galypyh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volypum.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumybal.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysyjid.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonybat.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekytyq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupyjuv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganyvoz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykytej.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopyjuf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebyvop.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujyteq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvyvix.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojyrak.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetyhyg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvycip.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexysig.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatyhub.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahyraw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyrygyn.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocycuc.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegyrol.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purygeg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacycus.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygywor.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowygem.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexyxuv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufywil.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqyfah.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofyqit.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqyfaq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzyxyv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyquz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymyfoj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volyzef.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedyqup.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumydoq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galyzeb.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysymux.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonydik.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekylag.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupymyp.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganydiw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykylan.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopymyc.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebysul.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujylog.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatynes.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvysur.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojykom.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetynev.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvypul.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahykih.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyrynad.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegykiq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocypyt.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purybav.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacypyz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygyjuj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexytep.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowybof.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufyjuq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqyvob.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxytex.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqyvig.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofyjuk.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzytap.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymyvin.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyhyw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volyrac.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedyhyl.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumycug.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galyros.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysyger.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonycum.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykywid.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupygel.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganycuh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopygat.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebyxyq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekyrov.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxyxyd.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujywiv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvyxyj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojyquf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetyfop.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvyxeq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahyqub.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyryfox.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocyzek.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegyqug.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purydip.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacyzaw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygymyn.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowydic.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexylal.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufymyg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqydus.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxylor.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofymem.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqysuv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyneh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymysud.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzylol.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volykit.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedynaq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumypyv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galykiz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysynaj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekykup.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganypeb.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupyboq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykyjux.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopybok.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebyteg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatyfaz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatyviw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvytan.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvytag.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojyjyc.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahyhys.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyryvur.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocyrom.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purycul.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegyhev.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacyroh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygyged.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowycut.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexyriq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufygav.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxywij.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqycyz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofygaf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqyxyp.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzywuq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyfob.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymyxex.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volyquk.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galyquw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumyxep.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysyfin.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedyfog.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonyzac.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonypyf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujyjup.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetyvil.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupydig.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekyqyl.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganyzas.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykymyr.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopydum.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebylov.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujymel.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatyduh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvylod.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojymet.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvyliv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetysuq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahynaz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyrysyj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegynap.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocykif.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purypyq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacykub.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygynox.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowypek.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexykug.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufybop.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqypew.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxyjun.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofybic.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqytal.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzyjyg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyvis.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymytar.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volyjym.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedyvuv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysyvud.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galyheh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonyrot.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumytol.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekyheq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupycuv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganyriz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykygaj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebyrip.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopycyf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujygaq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatycyb.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvywux.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojygok.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetyxeg.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvywup.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahyfow.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocyquc.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegyfil.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puryxag.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacyqys.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygyfir.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowyzam.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexyqyv.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufydul.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqyzoh.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxymed.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofydut.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzymev.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymylij.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadyduz.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqyloq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyryxen.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qedysyp.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'volymaf.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pumyliq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'galynab.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lysysyx.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qekynog.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vonykuk.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pupypep.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lykynon.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'ganykuw.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vopypec.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gatypas.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pujybig.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qebykul.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyvyjyr.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qetytav.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vojybim.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puvyjyl.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyrytod.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qegyvuq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vocyjet.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'purytov.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lygyvuj.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gacyhez.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vowyrif.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qexyhap.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'pufycyq.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gaqyrib.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lyxygax.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'qeqyrug.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'vofycyk.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'puzygop.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gadycew.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'lymywun.com', 'serverport': '80'}}, {'InternetConnectA': {'service': '3', 'servername': 'gahyvuh.com', 'serverport': '80'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: ganyhus.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://ganyhus.com/login.php'}}, {'WSASend': {'buffer': 'GET /login.php HTTP/1.1\r\nReferer: http://www.google.com\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)\r\nHost: qetyraq.com\r\n\r\n'}}, {'InternetCrackUrlW': {'url': 'http://qetyraq.com/login.php'}}], 'decrypted_buffers': []}
        }

        correct_result_section = ResultSection("blah")
        correct_network_result_section = ResultSection("Network Activity")
        dns_subsection = ResultTableSection("Protocol: DNS", tags={'network.protocol': ['dns'], 'network.dynamic.domain': ['lykyvor.com', 'vopyrem.com', 'vonyjuc.com', 'puzydog.com', 'gacyfeb.com', 'gaqyqiw.com', 'lyrywoj.com', 'pupyteg.com', 'vojycit.com', 'lyxyfan.com', 'qexyfag.com', 'qegyxup.com', 'lyvygyd.com', 'puvygyv.com', 'vofyzyc.com', 'vocygef.com', 'lysytyn.com', 'gatyrah.com', 'volybak.com', 'pujycil.com', 'qeqyqul.com', 'gahycuz.com', 'purywoq.com', 'lygyxux.com', 'qebyhuv.com', 'lymyjix.com', 'pufyxyp.com', 'vowyqik.com', 'qetyraq.com', 'lysynur.com', 'ganyhus.com', 'qekyvol.com', 'pumyjip.com', 'galyvaw.com', 'qedytyg.com', 'puzybeq.com', 'gadypub.com', 'qeqykop.com', 'vofypuf.com', 'lyxynej.com', 'gaqykoz.com', 'qexynyq.com', 'pujydap.com', 'gatyzyw.com', 'puvymug.com', 'gahydos.com', 'purylal.com', 'pufypuv.com', 'lyryler.com', 'gacynyh.com', 'gatypuz.com', 'lyvyjoj.com', 'puvyjiq.com', 'qetytup.com', 'gahyvab.com', 'qebykoq.com', 'vowykat.com', 'lygysid.com', 'vocymum.com', 'qegysiv.com', 'vojydoc.com', 'vopyput.com', 'lykyfax.com', 'vojybef.com', 'purytyp.com', 'lyvymun.com', 'qetylel.com', 'qebyqig.com', 'gaqyres.com', 'lyxygur.com', 'pufycog.com', 'lygyvon.com', 'ganyqib.com', 'lysysir.com', 'vonykam.com', 'lykynyd.com', 'ganykah.com', 'vopyzyk.com', 'pupypil.com', 'volygyt.com', 'pupyxuq.com', 'qedyxuq.com', 'qekyfep.com', 'lymywad.com', 'puzygyl.com', 'vonyqof.com', 'qeqyrav.com', 'vofycim.com', 'qegyvag.com', 'galyfez.com', 'gadycih.com', 'pumywov.com', 'lysyxuj.com', 'qexyhul.com', 'vowyrec.com', 'gacyhuw.com', 'vocyjik.com', 'lyrytyx.com', 'pujybev.com', 'qekynyv.com', 'pumyleg.com', 'galynus.com', 'qedysol.com', 'volymuc.com', 'lymylen.com', 'vowypim.com', 'pufybyl.com', 'lygyfej.com', 'gahynuw.com', 'puzymup.com', 'qetysog.com', 'gatydab.com', 'qebylyp.com', 'pujymiq.com', 'lygynyr.com', 'gacykas.com', 'puryxuv.com', 'qegynul.com', 'lyryson.com', 'gaqypuh.com', 'vofybet.com', 'gadyvez.com', 'lysyvax.com', 'lykygun.com', 'galyhib.com', 'pufydaq.com', 'vofydak.com', 'gadydow.com', 'qexyqip.com', 'vowyzuf.com', 'qebyrel.com', 'qeqylyg.com', 'gaqyzyb.com', 'gacyqoz.com', 'vocykec.com', 'gatycis.com', 'qegyfeq.com', 'lyryxud.com', 'puvywal.com', 'gahyfyh.com', 'lyxymix.com', 'vocyqot.com', 'qetyxiv.com', 'vopydaf.com', 'lyvylyx.com', 'puvylep.com', 'purypig.com', 'qedyvap.com', 'vopycoc.com', 'lyvywar.com', 'vojygym.com', 'pujygug.com', 'qekyhug.com', 'qexykav.com', 'puzyjov.com', 'lymytuj.com', 'ganyrew.com', 'pupycop.com', 'vonyryk.com', 'pumytyq.com', 'qeqytuq.com', 'volyjif.com', 'lyxyjod.com', 'vojymuk.com', 'ganyzuz.com', 'lykymij.com', 'pupydev.com', 'qekyqoq.com', 'vonyzut.com', 'gadynub.com', 'gacyzuh.com', 'pujyjol.com', 'vojyjot.com', 'ganypis.com', 'puzylyq.com', 'qeqysap.com', 'vofymif.com', 'lyxylyj.com', 'lygymod.com', 'purydel.com', 'volyqam.com', 'pumyxul.com', 'gahyhiz.com', 'puvytuv.com', 'qegyhip.com', 'qetyveq.com', 'gacyryb.com', 'qexyreg.com', 'gadyfys.com', 'lygygux.com', 'vowycok.com', 'puzywag.com', 'gaqydaz.com', 'qedyfyv.com', 'qeqyxil.com', 'gahyqas.com', 'qedynug.com', 'vofyguc.com', 'galyqoh.com', 'purycaq.com', 'gatyveh.com', 'lymyxir.com', 'lysyfed.com', 'lyxywen.com', 'lykyjar.com', 'pupybyg.com', 'lysynun.com', 'qegyqov.com', 'puvyxig.com', 'galykew.com', 'gaqycow.com', 'qekykal.com', 'lymysox.com', 'vowydet.com', 'volykek.com', 'lyvytud.com', 'vopybym.com', 'qebytuv.com', 'pufygup.com', 'gatyfuw.com', 'pumypop.com', 'qexyluq.com', 'vocyryf.com', 'lyryvaj.com', 'pufymiv.com', 'vonypic.com', 'vocyzum.com', 'lyryfyr.com', 'qetyfyl.com', 'vojyqac.com', 'pujywep.com', 'qebyxog.com', 'lyvyxin.com', 'ganycob.com', 'pupymol.com', 'lykylud.com', 'gaqyvys.com', 'vopymit.com', 'pujylyv.com', 'qebysaq.com', 'gatyniz.com', 'vojykyf.com', 'qegykeg.com', 'gacypiw.com', 'vopyguk.com', 'lykywex.com', 'qexytil.com', 'lyxytur.com', 'vofyjom.com', 'pupyguq.com', 'puzytul.com', 'qekyryp.com', 'gadyhoh.com', 'vonycaf.com', 'lysygij.com', 'volyrut.com', 'qedyhiq.com', 'pumycav.com', 'galyryz.com', 'lymyved.com', 'qeqyvev.com', 'pufyjag.com', 'lygyjan.com', 'vowybyc.com', 'purybup.com', 'vonydem.com', 'gahykeb.com', 'vocypok.com', 'lyrynux.com', 'puvypoq.com', 'gadyqaw.com', 'vofyqek.com', 'lyvysaj.com', 'lyxyxox.com', 'lysymor.com', 'ganydeh.com', 'qekyluv.com', 'galyzus.com', 'pumydyg.com', 'lymyfyn.com', 'pufyweq.com', 'qedyqal.com', 'qetynup.com', 'qeqyfug.com', 'puzyxip.com', 'volyzic.com', 'gaqyfub.com', 'vowyguf.com', 'qexyxop.com', 'lygywyj.com', 'gacycaz.com', 'purygiv.com', 'qegyryq.com', 'puvycel.com', 'lyrygid.com', 'gahyruh.com', 'vocycat.com', 'pupyjap.com', 'volypof.com', 'lymynuj.com', 'gadykyz.com', 'gadyrus.com', 'puzyceg.com', 'lymygor.com', 'qeqyniq.com', 'qetyqag.com', 'purymog.com', 'vojyzik.com', 'puvydyp.com', 'lyryman.com', 'vocydyc.com', 'qetyhov.com', 'vojyrum.com', 'lygylur.com', 'qedykep.com', 'galypob.com', 'pujytug.com', 'lyvyver.com', 'gatyhos.com', 'lysyjex.com', 'vonybuk.com', 'qebyvyl.com', 'vopyjac.com', 'qekytig.com', 'ganyvyw.com', 'lykytin.com', 'lyxysad.com', 'vofyruc.com', 'gacydes.com', 'pufylul.com', 'lyvyfux.com', 'pujyxoq.com', 'vopyqef.com', 'pumybuq.com', 'puzypav.com', 'qexysev.com', 'vofykyt.com', 'vowymom.com', 'qegylul.com', 'gahyziw.com', 'lyxyvyn.com', 'volycem.com', 'qedyruv.com', 'lykyxoj.com', 'qebyfup.com', 'gaqynih.com', 'qekyxaq.com', 'pupywyv.com', 'gatyqeb.com', 'ganyfuz.com', 'lysywyd.com', 'galycah.com', 'pumygil.com', 'vonygit.com', 'qeqyhol.com', 'gaqyhaw.com', 'pufytip.com', 'vowyjak.com', 'qexyvyg.com', 'lygytix.com', 'gacyvub.com', 'pufyxov.com', 'puvybuv.com', 'vocybuf.com', 'gahypoz.com', 'lyryjej.com', 'qetykyq.com', 'vojypat.com', 'qegytop.com', 'puryjeq.com', 'qebyniv.com', 'vopykum.com', 'lykyser.com', 'vofyzof.com', 'qeqyqep.com', 'ganynos.com', 'lyxyfuj.com', 'gaqyqez.com', 'qexyfuq.com', 'vowyqyt.com', 'gacyfih.com', 'pujypal.com', 'volydyk.com', 'lygyxad.com', 'gatykyh.com', 'lymymax.com', 'pupylug.com', 'gadyzib.com', 'puzyduq.com', 'vonymoc.com', 'lyvynid.com', 'pumyjev.com', 'gahyces.com', 'qegyxav.com', 'lyrywur.com', 'gatyruw.com', 'vopyrik.com', 'pupytiq.com', 'galydyw.com', 'galyvuz.com', 'lysytoj.com', 'qedylig.com', 'qedytoq.com', 'qekysel.com', 'lysylun.com', 'pumymap.com', 'qebyhag.com', 'lykyvyx.com', 'purywyl.com', 'qetyrul.com', 'vocygim.com', 'vojycec.com', 'lyvygon.com', 'pujycyp.com', 'puvygog.com', 'ganyhab.com', 'qekyvup.com', 'vonyjef.com', 'lymyjyd.com', 'volybut.com', 'gadypah.com', 'puzybil.com', 'vofypam.com', 'qeqykyv.com', 'lyxynir.com', 'lysyxar.com', 'pumywug.com', 'vopyzot.com', 'qedyxel.com', 'vonyqym.com', 'qekyfiv.com', 'lygysen.com', 'qetylip.com', 'vojyduf.com', 'qebyqeq.com', 'qexynol.com', 'pufypeg.com', 'ganyqyh.com', 'gahydyb.com', 'lyvymej.com', 'galyfis.com', 'gatyzoz.com', 'vowykuc.com', 'puvymaq.com', 'gaqykus.com', 'purylup.com', 'pupyxal.com', 'volygoc.com', 'vocymak.com', 'lyrylix.com', 'qegysyg.com', 'lykyfud.com', 'gacynow.com', 'lykynon.com', 'pujyduv.com', 'pujybig.com', 'vonykuk.com', 'ganykuw.com', 'vopypec.com', 'gatypas.com', 'lyvyjyr.com', 'qebykul.com', 'lyrytod.com', 'puvyjyl.com', 'vojybim.com', 'vocyjet.com', 'purytov.com', 'lygyvuj.com', 'lymywun.com', 'vowyrif.com', 'puzygop.com', 'gadycew.com', 'vofycyk.com', 'gacyhez.com', 'lyxygax.com', 'gaqyrib.com', 'qeqyrug.com', 'pufycyq.com', 'qexyhap.com', 'lysysyx.com', 'galynab.com', 'qetytav.com', 'qegyvuq.com', 'gahyvuh.com', 'pupypep.com', 'pumyliq.com', 'qekynog.com', 'volymaf.com', 'qedysyp.com', 'vocyquc.com', 'vonyrot.com', 'pupycuv.com', 'lyrysyj.com', 'qetysuq.com', 'gacykub.com', 'qegynap.com', 'lygynox.com', 'volyjym.com', 'lyxyjun.com', 'vofydut.com', 'galyheh.com', 'gaqyzoh.com', 'lysyvud.com', 'qedyvuv.com', 'qexykug.com', 'lyxymed.com', 'qexyqyv.com', 'lymytar.com', 'purypyq.com', 'vocykif.com', 'gaqypew.com', 'qegyfil.com', 'pufybop.com', 'gahyfow.com', 'vowypek.com', 'pufydul.com', 'lymylij.com', 'qeqytal.com', 'puvywup.com', 'vofybic.com', 'qetyxeg.com', 'gadyvis.com', 'gadyduz.com', 'qeqyloq.com', 'vopycyf.com', 'puzymev.com', 'lyryxen.com', 'vojygok.com', 'gahynaz.com', 'puvyliv.com', 'vowyzam.com', 'lykygaj.com', 'gatycyb.com', 'vojymet.com', 'gacyqys.com', 'puryxag.com', 'pujygaq.com', 'pumytol.com', 'lygyfir.com', 'ganyriz.com', 'puzyjyg.com', 'lyvylod.com', 'qebyrip.com', 'lyvywux.com', 'gatyduh.com', 'qekyheq.com', 'pujymel.com', 'qebylov.com', 'vopydum.com', 'lykymyr.com', 'ganyzas.com', 'qekyqyl.com', 'pupydig.com', 'pumypyv.com', 'gahyhys.com', 'vonyzac.com', 'puvyxeq.com', 'vofygaf.com', 'galyquw.com', 'lyryvur.com', 'gadyfob.com', 'vowycut.com', 'purycul.com', 'vopybok.com', 'qetyvil.com', 'lyvytan.com', 'gatyviw.com', 'qegyhev.com', 'qebyteg.com', 'pupyboq.com', 'vocyrom.com', 'pujyjup.com', 'lykyjux.com', 'qegyqug.com', 'gacyroh.com', 'vonypyf.com', 'qekykup.com', 'gaqycyz.com', 'qexyriq.com', 'lyxywij.com', 'qeqyxyp.com', 'lysynaj.com', 'puzylol.com', 'gadyneh.com', 'volykit.com', 'puzywuq.com', 'lygyged.com', 'qeqysuv.com', 'lymysud.com', 'lymyxex.com', 'volyquk.com', 'pufymyg.com', 'vowydic.com', 'lygymyn.com', 'gacyzaw.com', 'purydip.com', 'ganypeb.com', 'qedynaq.com', 'lysyfin.com', 'pumyxep.com', 'qedyfog.com', 'vocyzek.com', 'lyryfox.com', 'gahyqub.com', 'qetyfop.com', 'vojyjyc.com', 'puvytag.com', 'vofymem.com', 'galykiz.com', 'pufygav.com', 'lyvyxyj.com', 'qexylal.com', 'lyxylor.com', 'gaqydus.com', 'vojyquf.com', 'gatyfaz.com', 'pujywiv.com', 'gadyquz.com', 'qeqyvig.com', 'vojykom.com', 'lyxytex.com', 'qeqyfaq.com', 'lymyfoj.com', 'qedyqup.com', 'pufyjuq.com', 'vowybof.com', 'qekylag.com', 'pumydoq.com', 'vonydik.com', 'galyzeb.com', 'gacypyz.com', 'lysymux.com', 'qexytep.com', 'volyzef.com', 'pupymyp.com', 'lygyjuj.com', 'ganydiw.com', 'vocypyt.com', 'purybav.com', 'vopymyc.com', 'qebysul.com', 'qegykiq.com', 'lyrynad.com', 'pujylog.com', 'lykywid.com', 'puzyxyv.com', 'vofyjuk.com', 'vofyqit.com', 'puzytap.com', 'lyxyxyd.com', 'qexyxuv.com', 'qetynev.com', 'gatynes.com', 'qebyxyq.com', 'vopygat.com', 'gahykih.com', 'qekyrov.com', 'vonycum.com', 'lysyger.com', 'galyros.com', 'gaqyvob.com', 'ganycuh.com', 'lygywor.com', 'pupygel.com', 'lyvysur.com', 'purygeg.com', 'pufywil.com', 'gacycus.com', 'puvypul.com', 'qedyhyl.com', 'gadyhyw.com', 'lymyvin.com', 'volyrac.com', 'lykylan.com', 'pumycug.com', 'gahyraw.com', 'lyrygyn.com', 'vowygem.com', 'gaqyfah.com', 'qegyrol.com', 'vocycuc.com', 'puzyciq.com', 'gadyrab.com', 'lyvyfad.com', 'lyvyvix.com', 'lykyxur.com', 'ganyfes.com', 'qedykiv.com', 'puzypug.com', 'lysywon.com', 'vowymyk.com', 'qekyxul.com', 'puvycip.com', 'qetyhyg.com', 'vojyrak.com', 'puvydov.com', 'vofyref.com', 'gatyhub.com', 'pujyteq.com', 'pujyxyl.com', 'qebyvop.com', 'vopyjuf.com', 'pupyjuv.com', 'gatyqih.com', 'lykytej.com', 'vojyzyt.com', 'qetyquq.com', 'gahyzez.com', 'lyrymuj.com', 'ganyvoz.com', 'vonybat.com', 'qekytyq.com', 'vocydof.com', 'qegylep.com', 'vofykoc.com', 'gaqyhuz.com', 'qeqyhup.com', 'lymygyx.com', 'vowyjut.com', 'purymuq.com', 'lymyner.com', 'lysyjid.com', 'pufylap.com', 'gaqynyw.com', 'volypum.com', 'lyxyvoj.com', 'qexysig.com', 'lyxysun.com', 'galypyh.com', 'gadykos.com', 'qeqynel.com', 'gacydib.com', 'lygylax.com', 'vopyqim.com', 'qebyfav.com', 'pumybal.com', 'pumygyp.com', 'pupywog.com', 'qedyrag.com', 'vonygec.com', 'galycuw.com', 'volycik.com', 'pufytev.com', 'qexyvoq.com', 'lygytyd.com', 'qeqyqiv.com', 'qexyfel.com', 'puryjil.com', 'lyxyfar.com', 'qegytyv.com', 'pufyxug.com', 'lyryjir.com', 'lygyxun.com', 'puvybeg.com', 'vofyzym.com', 'qetykol.com', 'gacyvah.com', 'gaqyqis.com', 'puzydal.com', 'pupylaq.com', 'galyvas.com', 'vojypuc.com', 'gahypus.com', 'gatykow.com', 'lysytyr.com', 'vocybam.com', 'lymymud.com', 'gadyzyh.com', 'gacyfew.com', 'qedyleq.com', 'volydot.com', 'qebyhuq.com', 'lysylej.com', 'qekysip.com', 'vojycif.com', 'lykysix.com', 'qekyvav.com', 'lyrywax.com', 'qegyxug.com', 'vocygyk.com', 'lyvyguj.com', 'pujycov.com', 'purywop.com', 'vonyjim.com', 'pupytyl.com', 'volybec.com', 'lykyvod.com', 'gahycib.com', 'qetyrap.com', 'pujypup.com', 'ganyhuh.com', 'gatyrez.com', 'vowyqoc.com', 'puvygyq.com', 'pumymuv.com', 'ganynyb.com', 'vopykak.com', 'lyvynen.com', 'vonymuf.com', 'qebynyg.com', 'vopyret.com', 'galydoz.com', 'pumyjig.com', 'qedytul.com', 'lymyjon.com', 'gadypuw.com', 'puzybep.com', 'qeqykog.com', 'vofypuk.com', 'gahydoh.com', 'pufypiq.com', 'pumywaq.com', 'lygyvar.com', 'gaqykab.com', 'puvymul.com', 'lygysij.com', 'qexynyp.com', 'gahyvew.com', 'vocymut.com', 'gacynuz.com', 'purylev.com', 'qetylyv.com', 'qegysoq.com', 'vojydam.com', 'qebyqil.com', 'ganyqow.com', 'vopypif.com', 'pujydag.com', 'lyvymir.com', 'gatyzys.com', 'lykyfen.com', 'puvyjop.com', 'qekynuq.com', 'pupyxup.com', 'pufycol.com', 'gadyciz.com', 'lysyxux.com', 'qekyfeg.com', 'puzyguv.com', 'vonyqok.com', 'vofycot.com', 'galyfyb.com', 'lymywaj.com', 'qedyxip.com', 'volygyf.com', 'lyxygud.com', 'gaqyreh.com', 'qegyval.com', 'pupypiv.com', 'qexyhuv.com', 'lykynyj.com', 'vowyrym.com', 'qebykap.com', 'gacyhis.com', 'pujybyq.com', 'purytyg.com', 'lyxynyx.com', 'vocyjic.com', 'vopyzuc.com', 'vowykaf.com', 'lyrytun.com', 'qeqyreq.com', 'gatypub.com', 'lyryled.com', 'vojybek.com', 'qetytug.com', 'ganykaz.com', 'lyvyjox.com', 'vonyket.com', 'lysysod.com', 'galynuh.com', 'pumylel.com', 'qedysov.com', 'qeqylyl.com', 'puryxuq.com', 'puvywav.com', 'vojygut.com', 'volymum.com', 'vofydac.com', 'gaqyzuw.com', 'qexyqog.com', 'qetyxiq.com', 'lyxymin.com', 'gahyfyz.com', 'gadydas.com', 'puzymig.com', 'vocyqaf.com', 'lyryxij.com', 'lymylyr.com', 'lyvywed.com', 'pufydep.com', 'vowyzuk.com', 'gacyqob.com', 'vopycom.com', 'pujygul.com', 'gatycoh.com', 'qegyfyp.com', 'lygyfex.com', 'lysyvan.com', 'lykygur.com', 'pufybyv.com', 'vojymic.com', 'qekyhil.com', 'ganyrys.com', 'pumytup.com', 'vofybyf.com', 'puzyjoq.com', 'qeqytup.com', 'qedyveg.com', 'lyxyjaj.com', 'lymytux.com', 'gaqypiz.com', 'pupycag.com', 'qebyrev.com', 'gadyveb.com', 'vonyryc.com', 'galyhiw.com', 'volyjok.com', 'pupydeq.com', 'qexykaq.com', 'gatydaw.com', 'gahynus.com', 'gacykeh.com', 'purypol.com', 'lyrysor.com', 'qebylug.com', 'qetysal.com', 'qegynuv.com', 'vocykem.com', 'lyvylyn.com', 'vowypit.com', 'puvylyg.com', 'pujymip.com', 'lygynud.com', 'vopydek.com', 'ganyzub.com', 'lykymox.com', 'lyvyxor.com', 'galykes.com', 'gatyfus.com', 'qetyfuv.com', 'vojyqem.com', 'puzylyp.com', 'gahyqah.com', 'lymysan.com', 'qedynul.com', 'gadyniw.com', 'purycap.com', 'vocyzit.com', 'lyryfyd.com', 'vonypom.com', 'gacyzuz.com', 'vocyruk.com', 'gatyvyz.com', 'pumyxiv.com', 'lygymoj.com', 'pumypog.com', 'qekykev.com', 'vowydef.com', 'pupybul.com', 'ganypih.com', 'lyvytuj.com', 'gacyryw.com', 'lykyjad.com', 'vopybyt.com', 'qebytiq.com', 'pufymoq.com', 'qexylup.com', 'pujyjav.com', 'volykyc.com', 'puvyxil.com', 'pufygug.com', 'vofymik.com', 'gaqydeb.com', 'qexyryl.com', 'puzywel.com', 'lyxylux.com', 'qeqysag.com', 'purydyv.com', 'qegyqaq.com', 'qegyhig.com', 'qeqyxov.com', 'qetyvep.com', 'gahyhob.com', 'vojyjof.com', 'lyxywer.com', 'gaqycos.com', 'lygygin.com', 'vowycac.com', 'vofygum.com', 'volyqat.com', 'puvytuq.com', 'gadyfuh.com', 'lyryvex.com', 'lymyxid.com', 'qekyqop.com', 'qedyfyq.com', 'vonyzuf.com', 'galyqaz.com', 'lysyfyj.com']})
        dns_subsection.add_row(TableRow({"domain": "lykyvor.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyrem.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyjuc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzydog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyfeb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyqiw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrywoj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupyteg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojycit.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxyfan.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyfag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyxup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvygyd.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvygyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofyzyc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocygef.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysytyn.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyrah.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volybak.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujycil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyqul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahycuz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purywoq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyxux.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyhuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymyjix.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufyxyp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyqik.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyraq.com", "answer": "192.0.2.85", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysynur.com", "answer": "192.0.2.85", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyhus.com", "answer": "192.0.2.181", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyvol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumyjip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyvaw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedytyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzybeq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadypub.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqykop.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofypuf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxynej.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqykoz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexynyq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujydap.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyzyw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvymug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahydos.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purylal.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufypuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryler.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacynyh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatypuz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvyjoj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvyjiq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetytup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyvab.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebykoq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowykat.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygysid.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocymum.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegysiv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojydoc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyput.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykyfax.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojybef.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purytyp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvymun.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetylel.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyqig.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyres.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxygur.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufycog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyvon.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyqib.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysysir.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonykam.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykynyd.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganykah.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyzyk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupypil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volygyt.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupyxuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyxuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyfep.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymywad.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzygyl.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyqof.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyrav.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofycim.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyvag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyfez.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadycih.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumywov.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyxuj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyhul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyrec.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyhuw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyjik.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrytyx.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujybev.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekynyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumyleg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galynus.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedysol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volymuc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymylen.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowypim.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufybyl.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyfej.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahynuw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzymup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetysog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatydab.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebylyp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujymiq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygynyr.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacykas.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puryxuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegynul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryson.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqypuh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofybet.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyvez.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyvax.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykygun.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyhib.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufydaq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofydak.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadydow.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyqip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyzuf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyrel.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqylyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyzyb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyqoz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocykec.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatycis.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyfeq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryxud.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvywal.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyfyh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxymix.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyqot.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyxiv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopydaf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvylyx.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvylep.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purypig.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyvap.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopycoc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvywar.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojygym.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujygug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyhug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexykav.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzyjov.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymytuj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyrew.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupycop.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyryk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumytyq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqytuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volyjif.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxyjod.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojymuk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyzuz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykymij.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupydev.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyqoq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyzut.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadynub.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyzuh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujyjol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojyjot.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganypis.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzylyq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqysap.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofymif.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxylyj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygymod.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purydel.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volyqam.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumyxul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyhiz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvytuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyhip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyveq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyryb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyreg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyfys.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygygux.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowycok.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzywag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqydaz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyfyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyxil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyqas.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedynug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofyguc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyqoh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purycaq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyveh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymyxir.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyfed.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxywen.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykyjar.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupybyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysynun.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyqov.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvyxig.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galykew.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqycow.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekykal.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymysox.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowydet.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volykek.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvytud.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopybym.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebytuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufygup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyfuw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumypop.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyluq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyryf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryvaj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufymiv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonypic.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyzum.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryfyr.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyfyl.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojyqac.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujywep.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyxog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvyxin.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganycob.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupymol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykylud.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyvys.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopymit.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujylyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebysaq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyniz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojykyf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegykeg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacypiw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyguk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykywex.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexytil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxytur.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofyjom.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupyguq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzytul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyryp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyhoh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonycaf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysygij.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volyrut.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyhiq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumycav.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyryz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymyved.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyvev.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufyjag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyjan.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowybyc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purybup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonydem.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahykeb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocypok.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrynux.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvypoq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyqaw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofyqek.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvysaj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxyxox.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysymor.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganydeh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyluv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyzus.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumydyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymyfyn.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufyweq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyqal.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetynup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyfug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzyxip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volyzic.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyfub.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyguf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyxop.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygywyj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacycaz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purygiv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyryq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvycel.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrygid.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyruh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocycat.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupyjap.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volypof.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymynuj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadykyz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyrus.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzyceg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymygor.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyniq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyqag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purymog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojyzik.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvydyp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryman.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocydyc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyhov.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojyrum.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygylur.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedykep.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galypob.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujytug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvyver.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyhos.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyjex.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonybuk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyvyl.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyjac.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekytig.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyvyw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykytin.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxysad.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofyruc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacydes.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufylul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvyfux.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujyxoq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyqef.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumybuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzypav.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexysev.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofykyt.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowymom.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegylul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyziw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxyvyn.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volycem.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyruv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykyxoj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyfup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqynih.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyxaq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupywyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyqeb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyfuz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysywyd.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galycah.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumygil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonygit.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyhol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyhaw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufytip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyjak.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyvyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygytix.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyvub.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufyxov.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvybuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocybuf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahypoz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryjej.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetykyq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojypat.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegytop.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puryjeq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyniv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopykum.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykyser.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofyzof.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyqep.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganynos.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxyfuj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyqez.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyfuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyqyt.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyfih.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujypal.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volydyk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyxad.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatykyh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymymax.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupylug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyzib.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzyduq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonymoc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvynid.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumyjev.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyces.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyxav.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrywur.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyruw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyrik.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupytiq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galydyw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyvuz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysytoj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedylig.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedytoq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekysel.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysylun.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumymap.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyhag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykyvyx.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purywyl.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyrul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocygim.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojycec.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvygon.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujycyp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvygog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyhab.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyvup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyjef.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymyjyd.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volybut.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadypah.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzybil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofypam.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqykyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxynir.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyxar.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumywug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyzot.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyxel.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyqym.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyfiv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygysen.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetylip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojyduf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyqeq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexynol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufypeg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyqyh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahydyb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvymej.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyfis.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyzoz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowykuc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvymaq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqykus.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purylup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupyxal.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volygoc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocymak.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrylix.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegysyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykyfud.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacynow.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykynon.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujyduv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujybig.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonykuk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganykuw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopypec.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatypas.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvyjyr.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebykul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrytod.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvyjyl.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojybim.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyjet.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purytov.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyvuj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymywun.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyrif.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzygop.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadycew.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofycyk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyhez.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxygax.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyrib.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyrug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufycyq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyhap.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysysyx.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galynab.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetytav.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyvuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyvuh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupypep.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumyliq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekynog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volymaf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedysyp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyquc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyrot.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupycuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrysyj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetysuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacykub.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegynap.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygynox.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volyjym.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxyjun.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofydut.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyheh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyzoh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyvud.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyvuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexykug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxymed.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyqyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymytar.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purypyq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocykif.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqypew.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyfil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufybop.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyfow.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowypek.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufydul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymylij.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqytal.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvywup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofybic.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyxeg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyvis.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyduz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyloq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopycyf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzymev.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryxen.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojygok.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahynaz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvyliv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyzam.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykygaj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatycyb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojymet.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyqys.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puryxag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujygaq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumytol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyfir.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyriz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzyjyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvylod.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyrip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvywux.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyduh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyheq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujymel.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebylov.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopydum.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykymyr.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyzas.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyqyl.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupydig.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumypyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyhys.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyzac.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvyxeq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofygaf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyquw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryvur.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyfob.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowycut.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purycul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopybok.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyvil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvytan.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyviw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyhev.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyteg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupyboq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyrom.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujyjup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykyjux.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyqug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyroh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonypyf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekykup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqycyz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyriq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxywij.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyxyp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysynaj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzylol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyneh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volykit.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzywuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyged.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqysuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymysud.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymyxex.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volyquk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufymyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowydic.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygymyn.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyzaw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purydip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganypeb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedynaq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyfin.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumyxep.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyfog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyzek.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryfox.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyqub.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyfop.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojyjyc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvytag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofymem.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galykiz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufygav.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvyxyj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexylal.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxylor.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqydus.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojyquf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyfaz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujywiv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyquz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyvig.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojykom.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxytex.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyfaq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymyfoj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyqup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufyjuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowybof.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekylag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumydoq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonydik.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyzeb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacypyz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysymux.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexytep.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volyzef.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupymyp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyjuj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganydiw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocypyt.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purybav.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopymyc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebysul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegykiq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrynad.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujylog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykywid.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzyxyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofyjuk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofyqit.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzytap.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxyxyd.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyxuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetynev.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatynes.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyxyq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopygat.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahykih.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyrov.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonycum.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyger.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyros.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyvob.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganycuh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygywor.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupygel.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvysur.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purygeg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufywil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacycus.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvypul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyhyl.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyhyw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymyvin.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volyrac.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykylan.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumycug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyraw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrygyn.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowygem.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyfah.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyrol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocycuc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzyciq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyrab.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvyfad.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvyvix.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykyxur.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyfes.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedykiv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzypug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysywon.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowymyk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyxul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvycip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyhyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojyrak.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvydov.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofyref.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyhub.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujyteq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujyxyl.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyvop.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyjuf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupyjuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyqih.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykytej.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojyzyt.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyquq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyzez.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrymuj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyvoz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonybat.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekytyq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocydof.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegylep.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofykoc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyhuz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyhup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymygyx.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyjut.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purymuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymyner.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyjid.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufylap.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqynyw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volypum.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxyvoj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexysig.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxysun.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galypyh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadykos.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqynel.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacydib.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygylax.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyqim.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyfav.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumybal.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumygyp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupywog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyrag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonygec.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galycuw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volycik.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufytev.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyvoq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygytyd.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyqiv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyfel.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puryjil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxyfar.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegytyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufyxug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryjir.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyxun.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvybeg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofyzym.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetykol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyvah.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyqis.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzydal.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupylaq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyvas.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojypuc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahypus.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatykow.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysytyr.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocybam.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymymud.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyzyh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyfew.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyleq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volydot.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyhuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysylej.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekysip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojycif.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykysix.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyvav.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrywax.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyxug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocygyk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvyguj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujycov.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purywop.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyjim.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupytyl.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volybec.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykyvod.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahycib.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyrap.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujypup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyhuh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyrez.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyqoc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvygyq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumymuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganynyb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopykak.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvynen.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonymuf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebynyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyret.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galydoz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumyjig.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedytul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymyjon.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadypuw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzybep.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqykog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofypuk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahydoh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufypiq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumywaq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyvar.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqykab.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvymul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygysij.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexynyp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyvew.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocymut.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacynuz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purylev.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetylyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegysoq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojydam.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyqil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyqow.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopypif.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujydag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvymir.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyzys.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykyfen.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvyjop.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekynuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupyxup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufycol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyciz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyxux.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyfeg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzyguv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyqok.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofycot.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyfyb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymywaj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyxip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volygyf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxygud.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyreh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyval.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupypiv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyhuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykynyj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyrym.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebykap.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyhis.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujybyq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purytyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxynyx.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyjic.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopyzuc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowykaf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrytun.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyreq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatypub.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryled.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojybek.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetytug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganykaz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvyjox.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyket.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysysod.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galynuh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumylel.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedysov.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqylyl.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puryxuq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvywav.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojygut.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volymum.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofydac.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqyzuw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyqog.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyxiq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxymin.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyfyz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadydas.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzymig.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyqaf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryxij.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymylyr.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvywed.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufydep.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowyzuk.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyqob.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopycom.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujygul.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatycoh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyfyp.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygyfex.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyvan.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykygur.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufybyv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojymic.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyhil.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyrys.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumytup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofybyf.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzyjoq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqytup.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyveg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxyjaj.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymytux.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqypiz.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupycag.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebyrev.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyveb.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyryc.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyhiw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volyjok.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupydeq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexykaq.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatydaw.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahynus.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacykeh.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purypol.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyrysor.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebylug.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetysal.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegynuv.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocykem.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvylyn.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowypit.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvylyg.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujymip.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygynud.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopydek.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganyzub.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykymox.com", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvyxor.com", "answer": "192.0.2.57", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galykes.com", "answer": "192.0.2.57", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyfus.com", "answer": "192.0.2.125", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyfuv.com", "answer": "192.0.2.131", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojyqem.com", "answer": "192.0.2.217", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzylyp.com", "answer": "192.0.2.246", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyqah.com", "answer": "192.0.2.91", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymysan.com", "answer": "192.0.2.139", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedynul.com", "answer": "192.0.2.120", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyniw.com", "answer": "192.0.2.208", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purycap.com", "answer": "192.0.2.200", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyzit.com", "answer": "192.0.2.178", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryfyd.com", "answer": "192.0.2.162", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonypom.com", "answer": "192.0.2.203", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyzuz.com", "answer": "192.0.2.28", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vocyruk.com", "answer": "192.0.2.28", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gatyvyz.com", "answer": "192.0.2.254", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumyxiv.com", "answer": "192.0.2.254", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygymoj.com", "answer": "192.0.2.198", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pumypog.com", "answer": "192.0.2.173", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekykev.com", "answer": "192.0.2.67", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowydef.com", "answer": "192.0.2.67", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pupybul.com", "answer": "192.0.2.19", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "ganypih.com", "answer": "192.0.2.43", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyvytuj.com", "answer": "192.0.2.43", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gacyryw.com", "answer": "192.0.2.6", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lykyjad.com", "answer": "192.0.2.153", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vopybyt.com", "answer": "192.0.2.153", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qebytiq.com", "answer": "192.0.2.18", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufymoq.com", "answer": "192.0.2.94", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexylup.com", "answer": "192.0.2.54", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pujyjav.com", "answer": "192.0.2.155", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volykyc.com", "answer": "192.0.2.219", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvyxil.com", "answer": "192.0.2.33", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "pufygug.com", "answer": "192.0.2.99", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofymik.com", "answer": "192.0.2.78", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqydeb.com", "answer": "192.0.2.167", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qexyryl.com", "answer": "192.0.2.167", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puzywel.com", "answer": "192.0.2.34", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxylux.com", "answer": "192.0.2.212", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqysag.com", "answer": "192.0.2.251", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "purydyv.com", "answer": "192.0.2.60", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyqaq.com", "answer": "192.0.2.25", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qegyhig.com", "answer": "192.0.2.172", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qeqyxov.com", "answer": "192.0.2.172", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qetyvep.com", "answer": "192.0.2.133", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gahyhob.com", "answer": "192.0.2.106", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vojyjof.com", "answer": "192.0.2.92", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyxywer.com", "answer": "192.0.2.92", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gaqycos.com", "answer": "192.0.2.44", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lygygin.com", "answer": "192.0.2.82", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vowycac.com", "answer": "192.0.2.13", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vofygum.com", "answer": "192.0.2.45", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "volyqat.com", "answer": "192.0.2.15", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "puvytuq.com", "answer": "192.0.2.124", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "gadyfuh.com", "answer": "192.0.2.240", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lyryvex.com", "answer": "192.0.2.74", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lymyxid.com", "answer": "192.0.2.238", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qekyqop.com", "answer": "192.0.2.232", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "qedyfyq.com", "answer": "192.0.2.123", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "vonyzuf.com", "answer": "192.0.2.192", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "galyqaz.com", "answer": "192.0.2.58", "type": "A"}))
        dns_subsection.add_row(TableRow({"domain": "lysyfyj.com", "answer": "192.0.2.84", "type": "A"}))
        dns_subsection.set_heuristic(1000)
        correct_network_result_section.add_subsection(dns_subsection)
        tcp_udp_subsection = ResultTableSection("TCP/UDP Network Traffic", tags={'network.dynamic.domain': ['qetyraq.com', 'ganyhus.com', 'lyvyxor.com', 'gatyfus.com', 'qetyfuv.com', 'vojyqem.com', 'puzylyp.com', 'gahyqah.com', 'lymysan.com', 'qedynul.com', 'gadyniw.com', 'purycap.com', 'vocyzit.com', 'lyryfyd.com', 'vonypom.com', 'gacyzuz.com', 'gatyvyz.com', 'lygymoj.com', 'pumypog.com', 'qekykev.com', 'pupybul.com', 'ganypih.com', 'gacyryw.com', 'lykyjad.com', 'qebytiq.com', 'pufymoq.com', 'qexylup.com', 'pujyjav.com', 'volykyc.com', 'puvyxil.com', 'pufygug.com', 'vofymik.com', 'gaqydeb.com', 'puzywel.com', 'lyxylux.com', 'qeqysag.com', 'purydyv.com', 'qegyqaq.com', 'qegyhig.com', 'qetyvep.com', 'gahyhob.com', 'vojyjof.com', 'gaqycos.com', 'lygygin.com', 'vowycac.com', 'vofygum.com', 'volyqat.com', 'puvytuq.com', 'gadyfuh.com', 'lyryvex.com', 'lymyxid.com', 'qekyqop.com', 'qedyfyq.com', 'vonyzuf.com', 'galyqaz.com', 'lysyfyj.com'], 'network.protocol': ['tcp'], 'network.port': [80, 50217, 50216, 50126, 50124, 50122, 50120, 50118, 50116, 50114, 50112, 50110, 50108, 50106, 50104, 50102, 50100, 50098, 50096, 50094, 50092, 50088, 50086, 50084, 50082, 50078, 50076, 50074, 50072, 50070, 50068, 50066, 50064, 50060, 50058, 50056, 50054, 50050, 50048, 50044, 50042, 50040, 50038, 50034, 50032, 50028, 50024, 50022, 50020, 50016, 50014, 50012, 50010, 50008, 50006, 50004, 50002]})
        tcp_udp_subsection.set_heuristic(1004)
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50217, "domain": "qetyraq.com", "dest_ip": "192.0.2.85", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50216, "domain": "ganyhus.com", "dest_ip": "192.0.2.181", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50126, "domain": "lyvyxor.com", "dest_ip": "192.0.2.57", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50124, "domain": "gatyfus.com", "dest_ip": "192.0.2.125", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50122, "domain": "qetyfuv.com", "dest_ip": "192.0.2.131", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50120, "domain": "vojyqem.com", "dest_ip": "192.0.2.217", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50118, "domain": "puzylyp.com", "dest_ip": "192.0.2.246", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50116, "domain": "gahyqah.com", "dest_ip": "192.0.2.91", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50114, "domain": "lymysan.com", "dest_ip": "192.0.2.139", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50112, "domain": "qedynul.com", "dest_ip": "192.0.2.120", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50110, "domain": "gadyniw.com", "dest_ip": "192.0.2.208", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50108, "domain": "purycap.com", "dest_ip": "192.0.2.200", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50106, "domain": "vocyzit.com", "dest_ip": "192.0.2.178", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50104, "domain": "lyryfyd.com", "dest_ip": "192.0.2.162", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50102, "domain": "vonypom.com", "dest_ip": "192.0.2.203", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50100, "domain": "gacyzuz.com", "dest_ip": "192.0.2.28", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50098, "domain": "gatyvyz.com", "dest_ip": "192.0.2.254", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50096, "domain": "lygymoj.com", "dest_ip": "192.0.2.198", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50094, "domain": "pumypog.com", "dest_ip": "192.0.2.173", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50092, "domain": "qekykev.com", "dest_ip": "192.0.2.67", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50088, "domain": "pupybul.com", "dest_ip": "192.0.2.19", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50086, "domain": "ganypih.com", "dest_ip": "192.0.2.43", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50084, "domain": "gacyryw.com", "dest_ip": "192.0.2.6", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50082, "domain": "lykyjad.com", "dest_ip": "192.0.2.153", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50078, "domain": "qebytiq.com", "dest_ip": "192.0.2.18", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50076, "domain": "pufymoq.com", "dest_ip": "192.0.2.94", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50074, "domain": "qexylup.com", "dest_ip": "192.0.2.54", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50072, "domain": "pujyjav.com", "dest_ip": "192.0.2.155", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50070, "domain": "volykyc.com", "dest_ip": "192.0.2.219", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50068, "domain": "puvyxil.com", "dest_ip": "192.0.2.33", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50066, "domain": "pufygug.com", "dest_ip": "192.0.2.99", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50064, "domain": "vofymik.com", "dest_ip": "192.0.2.78", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50060, "domain": "gaqydeb.com", "dest_ip": "192.0.2.167", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50058, "domain": "puzywel.com", "dest_ip": "192.0.2.34", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50056, "domain": "lyxylux.com", "dest_ip": "192.0.2.212", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50054, "domain": "qeqysag.com", "dest_ip": "192.0.2.251", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50050, "domain": "purydyv.com", "dest_ip": "192.0.2.60", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50048, "domain": "qegyqaq.com", "dest_ip": "192.0.2.25", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50044, "domain": "qegyhig.com", "dest_ip": "192.0.2.172", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50042, "domain": "qetyvep.com", "dest_ip": "192.0.2.133", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50040, "domain": "gahyhob.com", "dest_ip": "192.0.2.106", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50038, "domain": "vojyjof.com", "dest_ip": "192.0.2.92", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50034, "domain": "gaqycos.com", "dest_ip": "192.0.2.44", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50032, "domain": "lygygin.com", "dest_ip": "192.0.2.82", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50028, "domain": "vowycac.com", "dest_ip": "192.0.2.13", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50024, "domain": "vofygum.com", "dest_ip": "192.0.2.45", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50022, "domain": "volyqat.com", "dest_ip": "192.0.2.15", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50020, "domain": "puvytuq.com", "dest_ip": "192.0.2.124", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50016, "domain": "gadyfuh.com", "dest_ip": "192.0.2.240", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50014, "domain": "lyryvex.com", "dest_ip": "192.0.2.74", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50012, "domain": "lymyxid.com", "dest_ip": "192.0.2.238", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50010, "domain": "qekyqop.com", "dest_ip": "192.0.2.232", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50008, "domain": "qedyfyq.com", "dest_ip": "192.0.2.123", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50006, "domain": "vonyzuf.com", "dest_ip": "192.0.2.192", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50004, "domain": "galyqaz.com", "dest_ip": "192.0.2.58", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_row(TableRow({"protocol": "tcp", "src_ip": "192.168.0.9", "src_port": 50002, "domain": "lysyfyj.com", "dest_ip": "192.0.2.84", "dest_port": 80, "image": "C:\\Windows\\apppatch\\svchost.exe", "pid": 4820, "guid": "{61a591c8-db51-643e-df02-000000002200}"}))
        tcp_udp_subsection.add_subsection(ResultSection("TCP Network Traffic Detected", auto_collapse=True, heuristic=Heuristic(1010)))
        correct_network_result_section.add_subsection(tcp_udp_subsection)
        http_subsection = ResultTableSection("Protocol: HTTP/HTTPS", tags={'network.protocol': ['http'], 'network.dynamic.domain': ['pumyxiv.com', 'lysyfyj.com', 'galyqaz.com', 'vonyzuf.com', 'qedyfyq.com', 'qekyqop.com', 'lymyxid.com', 'lyryvex.com', 'gadyfuh.com', 'vopybyt.com', 'puvytuq.com', 'volyqat.com', 'vofygum.com', 'qeqyxov.com', 'vowycac.com', 'lyxywer.com', 'lygygin.com', 'gaqycos.com', 'qexyryl.com', 'vojyjof.com', 'gahyhob.com', 'qetyvep.com', 'qegyhig.com', 'vocyruk.com', 'qegyqaq.com', 'purydyv.com', 'lyvytuj.com', 'qeqysag.com', 'lyxylux.com', 'puzywel.com', 'gaqydeb.com', 'lysynur.com', 'vofymik.com', 'pufygug.com', 'puvyxil.com', 'volykyc.com', 'pujyjav.com', 'qexylup.com', 'pufymoq.com', 'qebytiq.com', 'vowydef.com', 'lykyjad.com', 'gacyryw.com', 'ganypih.com', 'pupybul.com', 'galykes.com', 'qekykev.com', 'pumypog.com', 'lygymoj.com', 'gatyvyz.com', 'gacyzuz.com', 'vonypom.com', 'lyryfyd.com', 'vocyzit.com', 'purycap.com', 'gadyniw.com', 'qedynul.com', 'lymysan.com', 'gahyqah.com', 'puzylyp.com', 'vojyqem.com', 'qetyfuv.com', 'gatyfus.com', 'lyvyxor.com', 'ganyhus.com', 'qetyraq.com'], 'network.dynamic.uri': ['http://pumyxiv.com/login.php', 'http://lysyfyj.com/login.php', 'http://galyqaz.com/login.php', 'http://vonyzuf.com/login.php', 'http://qedyfyq.com/login.php', 'http://qekyqop.com/login.php', 'http://lymyxid.com/login.php', 'http://lyryvex.com/login.php', 'http://gadyfuh.com/login.php', 'http://vopybyt.com/login.php', 'http://puvytuq.com/login.php', 'http://volyqat.com/login.php', 'http://vofygum.com/login.php', 'http://qeqyxov.com/login.php', 'http://vowycac.com/login.php', 'http://lyxywer.com/login.php', 'http://lygygin.com/login.php', 'http://gaqycos.com/login.php', 'http://qexyryl.com/login.php', 'http://vojyjof.com/login.php', 'http://gahyhob.com/login.php', 'http://qetyvep.com/login.php', 'http://qegyhig.com/login.php', 'http://vocyruk.com/login.php', 'http://qegyqaq.com/login.php', 'http://purydyv.com/login.php', 'http://lyvytuj.com/login.php', 'http://qeqysag.com/login.php', 'http://lyxylux.com/login.php', 'http://puzywel.com/login.php', 'http://gaqydeb.com/login.php', 'http://lysynur.com/login.php', 'http://vofymik.com/login.php', 'http://pufygug.com/login.php', 'http://puvyxil.com/login.php', 'http://volykyc.com/login.php', 'http://pujyjav.com/login.php', 'http://qexylup.com/login.php', 'http://pufymoq.com/login.php', 'http://qebytiq.com/login.php', 'http://vowydef.com/login.php', 'http://lykyjad.com/login.php', 'http://gacyryw.com/login.php', 'http://ganypih.com/login.php', 'http://pupybul.com/login.php', 'http://galykes.com/login.php', 'http://qekykev.com/login.php', 'http://pumypog.com/login.php', 'http://lygymoj.com/login.php', 'http://gatyvyz.com/login.php', 'http://gacyzuz.com/login.php', 'http://vonypom.com/login.php', 'http://lyryfyd.com/login.php', 'http://vocyzit.com/login.php', 'http://purycap.com/login.php', 'http://gadyniw.com/login.php', 'http://qedynul.com/login.php', 'http://lymysan.com/login.php', 'http://gahyqah.com/login.php', 'http://puzylyp.com/login.php', 'http://vojyqem.com/login.php', 'http://qetyfuv.com/login.php', 'http://gatyfus.com/login.php', 'http://lyvyxor.com/login.php', 'http://ganyhus.com/login.php', 'http://qetyraq.com/login.php'], 'network.dynamic.uri_path': ['/login.php']})

        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "pumyxiv.com"}, "uri": "http://pumyxiv.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lysyfyj.com"}, "uri": "http://lysyfyj.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "galyqaz.com"}, "uri": "http://galyqaz.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "vonyzuf.com"}, "uri": "http://vonyzuf.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qedyfyq.com"}, "uri": "http://qedyfyq.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qekyqop.com"}, "uri": "http://qekyqop.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lymyxid.com"}, "uri": "http://lymyxid.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lyryvex.com"}, "uri": "http://lyryvex.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "gadyfuh.com"}, "uri": "http://gadyfuh.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "vopybyt.com"}, "uri": "http://vopybyt.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "puvytuq.com"}, "uri": "http://puvytuq.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "volyqat.com"}, "uri": "http://volyqat.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "vofygum.com"}, "uri": "http://vofygum.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qeqyxov.com"}, "uri": "http://qeqyxov.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "vowycac.com"}, "uri": "http://vowycac.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lyxywer.com"}, "uri": "http://lyxywer.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lygygin.com"}, "uri": "http://lygygin.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "gaqycos.com"}, "uri": "http://gaqycos.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qexyryl.com"}, "uri": "http://qexyryl.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "vojyjof.com"}, "uri": "http://vojyjof.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "gahyhob.com"}, "uri": "http://gahyhob.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qetyvep.com"}, "uri": "http://qetyvep.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qegyhig.com"}, "uri": "http://qegyhig.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "vocyruk.com"}, "uri": "http://vocyruk.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qegyqaq.com"}, "uri": "http://qegyqaq.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "purydyv.com"}, "uri": "http://purydyv.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lyvytuj.com"}, "uri": "http://lyvytuj.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qeqysag.com"}, "uri": "http://qeqysag.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lyxylux.com"}, "uri": "http://lyxylux.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "puzywel.com"}, "uri": "http://puzywel.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "gaqydeb.com"}, "uri": "http://gaqydeb.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lysynur.com"}, "uri": "http://lysynur.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "vofymik.com"}, "uri": "http://vofymik.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "pufygug.com"}, "uri": "http://pufygug.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "puvyxil.com"}, "uri": "http://puvyxil.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "volykyc.com"}, "uri": "http://volykyc.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "pujyjav.com"}, "uri": "http://pujyjav.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qexylup.com"}, "uri": "http://qexylup.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "pufymoq.com"}, "uri": "http://pufymoq.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qebytiq.com"}, "uri": "http://qebytiq.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "vowydef.com"}, "uri": "http://vowydef.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lykyjad.com"}, "uri": "http://lykyjad.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "gacyryw.com"}, "uri": "http://gacyryw.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "ganypih.com"}, "uri": "http://ganypih.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "pupybul.com"}, "uri": "http://pupybul.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "galykes.com"}, "uri": "http://galykes.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qekykev.com"}, "uri": "http://qekykev.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "pumypog.com"}, "uri": "http://pumypog.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lygymoj.com"}, "uri": "http://lygymoj.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "gatyvyz.com"}, "uri": "http://gatyvyz.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "gacyzuz.com"}, "uri": "http://gacyzuz.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "vonypom.com"}, "uri": "http://vonypom.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lyryfyd.com"}, "uri": "http://lyryfyd.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "vocyzit.com"}, "uri": "http://vocyzit.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "purycap.com"}, "uri": "http://purycap.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "gadyniw.com"}, "uri": "http://gadyniw.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qedynul.com"}, "uri": "http://qedynul.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lymysan.com"}, "uri": "http://lymysan.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "gahyqah.com"}, "uri": "http://gahyqah.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "puzylyp.com"}, "uri": "http://puzylyp.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "vojyqem.com"}, "uri": "http://vojyqem.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qetyfuv.com"}, "uri": "http://qetyfuv.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "gatyfus.com"}, "uri": "http://gatyfus.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "lyvyxor.com"}, "uri": "http://lyvyxor.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "ganyhus.com"}, "uri": "http://ganyhus.com/login.php"}))
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "GET", "request": {"Referer": "http://www.google.com", "UserAgent": "Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)", "Host": "qetyraq.com"}, "uri": "http://qetyraq.com/login.php"}))
        http_subsection.set_heuristic(1002)
        access_remote_subsection = ResultSection("Access Remote File", tags={'network.dynamic.domain': ['pumyxiv.com', 'lysyfyj.com', 'galyqaz.com', 'vonyzuf.com', 'qedyfyq.com', 'qekyqop.com', 'lymyxid.com', 'lyryvex.com', 'gadyfuh.com', 'vopybyt.com', 'puvytuq.com', 'volyqat.com', 'vofygum.com', 'qeqyxov.com', 'vowycac.com', 'lyxywer.com', 'lygygin.com', 'gaqycos.com', 'qexyryl.com', 'vojyjof.com', 'gahyhob.com', 'qetyvep.com', 'qegyhig.com', 'vocyruk.com', 'qegyqaq.com', 'purydyv.com', 'lyvytuj.com', 'qeqysag.com', 'lyxylux.com', 'puzywel.com', 'gaqydeb.com', 'lysynur.com', 'vofymik.com', 'pufygug.com', 'puvyxil.com', 'volykyc.com', 'pujyjav.com', 'qexylup.com', 'pufymoq.com', 'qebytiq.com', 'vowydef.com', 'lykyjad.com', 'gacyryw.com', 'ganypih.com', 'pupybul.com', 'galykes.com', 'qekykev.com', 'pumypog.com', 'lygymoj.com', 'gatyvyz.com', 'gacyzuz.com', 'vonypom.com', 'lyryfyd.com', 'vocyzit.com', 'purycap.com', 'gadyniw.com', 'qedynul.com', 'lymysan.com', 'gahyqah.com', 'puzylyp.com', 'vojyqem.com', 'qetyfuv.com', 'gatyfus.com', 'lyvyxor.com', 'ganyhus.com', 'qetyraq.com'], 'network.dynamic.uri': ['http://pumyxiv.com/login.php', 'http://lysyfyj.com/login.php', 'http://galyqaz.com/login.php', 'http://vonyzuf.com/login.php', 'http://qedyfyq.com/login.php', 'http://qekyqop.com/login.php', 'http://lymyxid.com/login.php', 'http://lyryvex.com/login.php', 'http://gadyfuh.com/login.php', 'http://vopybyt.com/login.php', 'http://puvytuq.com/login.php', 'http://volyqat.com/login.php', 'http://vofygum.com/login.php', 'http://qeqyxov.com/login.php', 'http://vowycac.com/login.php', 'http://lyxywer.com/login.php', 'http://lygygin.com/login.php', 'http://gaqycos.com/login.php', 'http://qexyryl.com/login.php', 'http://vojyjof.com/login.php', 'http://gahyhob.com/login.php', 'http://qetyvep.com/login.php', 'http://qegyhig.com/login.php', 'http://vocyruk.com/login.php', 'http://qegyqaq.com/login.php', 'http://purydyv.com/login.php', 'http://lyvytuj.com/login.php', 'http://qeqysag.com/login.php', 'http://lyxylux.com/login.php', 'http://puzywel.com/login.php', 'http://gaqydeb.com/login.php', 'http://lysynur.com/login.php', 'http://vofymik.com/login.php', 'http://pufygug.com/login.php', 'http://puvyxil.com/login.php', 'http://volykyc.com/login.php', 'http://pujyjav.com/login.php', 'http://qexylup.com/login.php', 'http://pufymoq.com/login.php', 'http://qebytiq.com/login.php', 'http://vowydef.com/login.php', 'http://lykyjad.com/login.php', 'http://gacyryw.com/login.php', 'http://ganypih.com/login.php', 'http://pupybul.com/login.php', 'http://galykes.com/login.php', 'http://qekykev.com/login.php', 'http://pumypog.com/login.php', 'http://lygymoj.com/login.php', 'http://gatyvyz.com/login.php', 'http://gacyzuz.com/login.php', 'http://vonypom.com/login.php', 'http://lyryfyd.com/login.php', 'http://vocyzit.com/login.php', 'http://purycap.com/login.php', 'http://gadyniw.com/login.php', 'http://qedynul.com/login.php', 'http://lymysan.com/login.php', 'http://gahyqah.com/login.php', 'http://puzylyp.com/login.php', 'http://vojyqem.com/login.php', 'http://qetyfuv.com/login.php', 'http://gatyfus.com/login.php', 'http://lyvyxor.com/login.php', 'http://ganyhus.com/login.php', 'http://qetyraq.com/login.php'], 'network.dynamic.uri_path': ['/login.php']}, body="The sample attempted to download the following files:\n\thttp://pumyxiv.com/login.php\n\thttp://lysyfyj.com/login.php\n\thttp://galyqaz.com/login.php\n\thttp://vonyzuf.com/login.php\n\thttp://qedyfyq.com/login.php\n\thttp://qekyqop.com/login.php\n\thttp://lymyxid.com/login.php\n\thttp://lyryvex.com/login.php\n\thttp://gadyfuh.com/login.php\n\thttp://vopybyt.com/login.php\n\thttp://puvytuq.com/login.php\n\thttp://volyqat.com/login.php\n\thttp://vofygum.com/login.php\n\thttp://qeqyxov.com/login.php\n\thttp://vowycac.com/login.php\n\thttp://lyxywer.com/login.php\n\thttp://lygygin.com/login.php\n\thttp://gaqycos.com/login.php\n\thttp://qexyryl.com/login.php\n\thttp://vojyjof.com/login.php\n\thttp://gahyhob.com/login.php\n\thttp://qetyvep.com/login.php\n\thttp://qegyhig.com/login.php\n\thttp://vocyruk.com/login.php\n\thttp://qegyqaq.com/login.php\n\thttp://purydyv.com/login.php\n\thttp://lyvytuj.com/login.php\n\thttp://qeqysag.com/login.php\n\thttp://lyxylux.com/login.php\n\thttp://puzywel.com/login.php\n\thttp://gaqydeb.com/login.php\n\thttp://lysynur.com/login.php\n\thttp://vofymik.com/login.php\n\thttp://pufygug.com/login.php\n\thttp://puvyxil.com/login.php\n\thttp://volykyc.com/login.php\n\thttp://pujyjav.com/login.php\n\thttp://qexylup.com/login.php\n\thttp://pufymoq.com/login.php\n\thttp://qebytiq.com/login.php\n\thttp://vowydef.com/login.php\n\thttp://lykyjad.com/login.php\n\thttp://gacyryw.com/login.php\n\thttp://ganypih.com/login.php\n\thttp://pupybul.com/login.php\n\thttp://galykes.com/login.php\n\thttp://qekykev.com/login.php\n\thttp://pumypog.com/login.php\n\thttp://lygymoj.com/login.php\n\thttp://gatyvyz.com/login.php\n\thttp://gacyzuz.com/login.php\n\thttp://vonypom.com/login.php\n\thttp://lyryfyd.com/login.php\n\thttp://vocyzit.com/login.php\n\thttp://purycap.com/login.php\n\thttp://gadyniw.com/login.php\n\thttp://qedynul.com/login.php\n\thttp://lymysan.com/login.php\n\thttp://gahyqah.com/login.php\n\thttp://puzylyp.com/login.php\n\thttp://vojyqem.com/login.php\n\thttp://qetyfuv.com/login.php\n\thttp://gatyfus.com/login.php\n\thttp://lyvyxor.com/login.php\n\thttp://ganyhus.com/login.php\n\thttp://qetyraq.com/login.php")
        access_remote_subsection.set_heuristic(1003)
        http_subsection.add_subsection(access_remote_subsection)
        http_header_ioc_subsection = ResultTableSection("IOCs found in HTTP/HTTPS Headers", tags={'network.dynamic.domain': ['gacyryw.com', 'gacyzuz.com', 'gadyfuh.com', 'gadyniw.com', 'gahyhob.com', 'gahyqah.com', 'galykes.com', 'galyqaz.com', 'ganyhus.com', 'ganypih.com', 'gaqycos.com', 'gaqydeb.com', 'gatyfus.com', 'gatyvyz.com', 'lygygin.com', 'lygymoj.com', 'lykyjad.com', 'lymysan.com', 'lymyxid.com', 'lyryfyd.com', 'lyryvex.com', 'lysyfyj.com', 'lysynur.com', 'lyvytuj.com', 'lyvyxor.com', 'lyxylux.com', 'lyxywer.com', 'pufygug.com', 'pufymoq.com', 'pujyjav.com', 'pumypog.com', 'pumyxiv.com', 'pupybul.com', 'purycap.com', 'purydyv.com', 'puvytuq.com', 'puvyxil.com', 'puzylyp.com', 'puzywel.com', 'qebytiq.com', 'qedyfyq.com', 'qedynul.com', 'qegyhig.com', 'qegyqaq.com', 'qekykev.com', 'qekyqop.com', 'qeqysag.com', 'qeqyxov.com', 'qetyfuv.com', 'qetyraq.com', 'qetyvep.com', 'qexylup.com', 'qexyryl.com', 'vocyruk.com', 'vocyzit.com', 'vofygum.com', 'vofymik.com', 'vojyjof.com', 'vojyqem.com', 'volykyc.com', 'volyqat.com', 'vonypom.com', 'vonyzuf.com', 'vopybyt.com', 'vowycac.com', 'vowydef.com', 'www.google.com'], 'network.dynamic.uri': ['http://www.google.com']})
        for domain in ['gacyryw.com', 'gacyzuz.com', 'gadyfuh.com', 'gadyniw.com', 'gahyhob.com', 'gahyqah.com', 'galykes.com', 'galyqaz.com', 'ganyhus.com', 'ganypih.com', 'gaqycos.com', 'gaqydeb.com', 'gatyfus.com', 'gatyvyz.com', 'lygygin.com', 'lygymoj.com', 'lykyjad.com', 'lymysan.com', 'lymyxid.com', 'lyryfyd.com', 'lyryvex.com', 'lysyfyj.com', 'lysynur.com', 'lyvytuj.com', 'lyvyxor.com', 'lyxylux.com', 'lyxywer.com', 'pufygug.com', 'pufymoq.com', 'pujyjav.com', 'pumypog.com', 'pumyxiv.com', 'pupybul.com', 'purycap.com', 'purydyv.com', 'puvytuq.com', 'puvyxil.com', 'puzylyp.com', 'puzywel.com', 'qebytiq.com', 'qedyfyq.com', 'qedynul.com', 'qegyhig.com', 'qegyqaq.com', 'qekykev.com', 'qekyqop.com', 'qeqysag.com', 'qeqyxov.com', 'qetyfuv.com', 'qetyraq.com', 'qetyvep.com', 'qexylup.com', 'qexyryl.com', 'vocyruk.com', 'vocyzit.com', 'vofygum.com', 'vofymik.com', 'vojyjof.com', 'vojyqem.com', 'volykyc.com', 'volyqat.com', 'vonypom.com', 'vonyzuf.com', 'vopybyt.com', 'vowycac.com', 'vowydef.com', 'www.google.com']:
            http_header_ioc_subsection.add_row(TableRow({"ioc_type": "domain", "ioc": domain}))

        http_header_ioc_subsection.add_row(TableRow({"ioc_type": "uri", "ioc": "http://www.google.com"}))
        http_subsection.add_subsection(http_header_ioc_subsection)
        correct_network_result_section.add_subsection(http_subsection)

        all_domains = ['gacycus.com', 'gacydib.com', 'gacyfew.com', 'gacyhez.com', 'gacyhis.com', 'gacykeh.com', 'gacykub.com', 'gacynuz.com', 'gacypyz.com', 'gacyqob.com', 'gacyqys.com', 'gacyroh.com', 'gacyvah.com', 'gacyzaw.com', 'gadycew.com', 'gadyciz.com', 'gadydas.com', 'gadyduz.com', 'gadyfob.com', 'gadyhyw.com', 'gadykos.com', 'gadyneh.com', 'gadypuw.com', 'gadyquz.com', 'gadyrab.com', 'gadyveb.com', 'gadyvis.com', 'gadyzyh.com', 'gahycib.com', 'gahydoh.com', 'gahyfow.com', 'gahyfyz.com', 'gahyhys.com', 'gahykih.com', 'gahynaz.com', 'gahynus.com', 'gahypus.com', 'gahyqub.com', 'gahyraw.com', 'gahyvew.com', 'gahyvuh.com', 'gahyzez.com', 'galycuw.com', 'galydoz.com', 'galyfyb.com', 'galyheh.com', 'galyhiw.com', 'galykiz.com', 'galynab.com', 'galynuh.com', 'galypyh.com', 'galyquw.com', 'galyros.com', 'galyvas.com', 'galyzeb.com', 'ganycuh.com', 'ganydiw.com', 'ganyfes.com', 'ganyhuh.com', 'ganykaz.com', 'ganykuw.com', 'ganynyb.com', 'ganypeb.com', 'ganyqow.com', 'ganyriz.com', 'ganyrys.com', 'ganyvoz.com', 'ganyzas.com', 'ganyzub.com', 'gaqycyz.com', 'gaqydus.com', 'gaqyfah.com', 'gaqyhuz.com', 'gaqykab.com', 'gaqynyw.com', 'gaqypew.com', 'gaqypiz.com', 'gaqyqis.com', 'gaqyreh.com', 'gaqyrib.com', 'gaqyvob.com', 'gaqyzoh.com', 'gaqyzuw.com', 'gatycoh.com', 'gatycyb.com', 'gatydaw.com', 'gatyduh.com', 'gatyfaz.com', 'gatyhub.com', 'gatykow.com', 'gatynes.com', 'gatypas.com', 'gatypub.com', 'gatyqih.com', 'gatyrez.com', 'gatyviw.com', 'gatyzys.com', 'lygyfex.com', 'lygyfir.com', 'lygyged.com', 'lygyjuj.com', 'lygylax.com', 'lygymyn.com', 'lygynox.com', 'lygynud.com', 'lygysij.com', 'lygytyd.com', 'lygyvar.com', 'lygyvuj.com', 'lygywor.com', 'lygyxun.com', 'lykyfen.com', 'lykygaj.com', 'lykygur.com', 'lykyjux.com', 'lykylan.com', 'lykymox.com', 'lykymyr.com', 'lykynon.com', 'lykynyj.com', 'lykysix.com', 'lykytej.com', 'lykyvod.com', 'lykywid.com', 'lykyxur.com', 'lymyfoj.com', 'lymygyx.com', 'lymyjon.com', 'lymylij.com', 'lymylyr.com', 'lymymud.com', 'lymyner.com', 'lymysud.com', 'lymytar.com', 'lymytux.com', 'lymyvin.com', 'lymywaj.com', 'lymywun.com', 'lymyxex.com', 'lyryfox.com', 'lyrygyn.com', 'lyryjir.com', 'lyryled.com', 'lyrymuj.com', 'lyrynad.com', 'lyrysor.com', 'lyrysyj.com', 'lyrytod.com', 'lyrytun.com', 'lyryvur.com', 'lyrywax.com', 'lyryxen.com', 'lyryxij.com', 'lysyfin.com', 'lysyger.com', 'lysyjid.com', 'lysylej.com', 'lysymux.com', 'lysynaj.com', 'lysysod.com', 'lysysyx.com', 'lysytyr.com', 'lysyvan.com', 'lysyvud.com', 'lysywon.com', 'lysyxux.com', 'lyvyfad.com', 'lyvyguj.com', 'lyvyjox.com', 'lyvyjyr.com', 'lyvylod.com', 'lyvylyn.com', 'lyvymir.com', 'lyvynen.com', 'lyvysur.com', 'lyvytan.com', 'lyvyvix.com', 'lyvywed.com', 'lyvywux.com', 'lyvyxyj.com', 'lyxyfar.com', 'lyxygax.com', 'lyxygud.com', 'lyxyjaj.com', 'lyxyjun.com', 'lyxylor.com', 'lyxymed.com', 'lyxymin.com', 'lyxynyx.com', 'lyxysun.com', 'lyxytex.com', 'lyxyvoj.com', 'lyxywij.com', 'lyxyxyd.com', 'pufybop.com', 'pufybyv.com', 'pufycol.com', 'pufycyq.com', 'pufydep.com', 'pufydul.com', 'pufygav.com', 'pufyjuq.com', 'pufylap.com', 'pufymyg.com', 'pufypiq.com', 'pufytev.com', 'pufywil.com', 'pufyxug.com', 'pujybig.com', 'pujybyq.com', 'pujycov.com', 'pujydag.com', 'pujygaq.com', 'pujygul.com', 'pujyjup.com', 'pujylog.com', 'pujymel.com', 'pujymip.com', 'pujypup.com', 'pujyteq.com', 'pujywiv.com', 'pujyxyl.com', 'pumybal.com', 'pumycug.com', 'pumydoq.com', 'pumygyp.com', 'pumyjig.com', 'pumylel.com', 'pumyliq.com', 'pumymuv.com', 'pumypyv.com', 'pumytol.com', 'pumytup.com', 'pumywaq.com', 'pumyxep.com', 'pupyboq.com', 'pupycag.com', 'pupycuv.com', 'pupydeq.com', 'pupydig.com', 'pupygel.com', 'pupyjuv.com', 'pupylaq.com', 'pupymyp.com', 'pupypep.com', 'pupypiv.com', 'pupytyl.com', 'pupywog.com', 'pupyxup.com', 'purybav.com', 'purycul.com', 'purydip.com', 'purygeg.com', 'puryjil.com', 'purylev.com', 'purymuq.com', 'purypol.com', 'purypyq.com', 'purytov.com', 'purytyg.com', 'purywop.com', 'puryxag.com', 'puryxuq.com', 'puvybeg.com', 'puvycip.com', 'puvydov.com', 'puvygyq.com', 'puvyjop.com', 'puvyjyl.com', 'puvyliv.com', 'puvylyg.com', 'puvymul.com', 'puvypul.com', 'puvytag.com', 'puvywav.com', 'puvywup.com', 'puvyxeq.com', 'puzybep.com', 'puzyciq.com', 'puzydal.com', 'puzygop.com', 'puzyguv.com', 'puzyjoq.com', 'puzyjyg.com', 'puzylol.com', 'puzymev.com', 'puzymig.com', 'puzypug.com', 'puzytap.com', 'puzywuq.com', 'puzyxyv.com', 'qebyfav.com', 'qebyhuq.com', 'qebykap.com', 'qebykul.com', 'qebylov.com', 'qebylug.com', 'qebynyg.com', 'qebyqil.com', 'qebyrev.com', 'qebyrip.com', 'qebysul.com', 'qebyteg.com', 'qebyvop.com', 'qebyxyq.com', 'qedyfog.com', 'qedyhyl.com', 'qedykiv.com', 'qedyleq.com', 'qedynaq.com', 'qedyqup.com', 'qedyrag.com', 'qedysov.com', 'qedysyp.com', 'qedytul.com', 'qedyveg.com', 'qedyvuv.com', 'qedyxip.com', 'qegyfil.com', 'qegyfyp.com', 'qegyhev.com', 'qegykiq.com', 'qegylep.com', 'qegynap.com', 'qegynuv.com', 'qegyqug.com', 'qegyrol.com', 'qegysoq.com', 'qegytyv.com', 'qegyval.com', 'qegyvuq.com', 'qegyxug.com', 'qekyfeg.com', 'qekyheq.com', 'qekyhil.com', 'qekykup.com', 'qekylag.com', 'qekynog.com', 'qekynuq.com', 'qekyqyl.com', 'qekyrov.com', 'qekysip.com', 'qekytyq.com', 'qekyvav.com', 'qekyxul.com', 'qeqyfaq.com', 'qeqyhup.com', 'qeqykog.com', 'qeqyloq.com', 'qeqylyl.com', 'qeqynel.com', 'qeqyqiv.com', 'qeqyreq.com', 'qeqyrug.com', 'qeqysuv.com', 'qeqytal.com', 'qeqytup.com', 'qeqyvig.com', 'qeqyxyp.com', 'qetyfop.com', 'qetyhyg.com', 'qetykol.com', 'qetylyv.com', 'qetynev.com', 'qetyquq.com', 'qetyrap.com', 'qetysal.com', 'qetysuq.com', 'qetytav.com', 'qetytug.com', 'qetyvil.com', 'qetyxeg.com', 'qetyxiq.com', 'qexyfel.com', 'qexyhap.com', 'qexyhuv.com', 'qexykaq.com', 'qexykug.com', 'qexylal.com', 'qexynyp.com', 'qexyqog.com', 'qexyqyv.com', 'qexyriq.com', 'qexysig.com', 'qexytep.com', 'qexyvoq.com', 'qexyxuv.com', 'vocybam.com', 'vocycuc.com', 'vocydof.com', 'vocygyk.com', 'vocyjet.com', 'vocyjic.com', 'vocykem.com', 'vocykif.com', 'vocymut.com', 'vocypyt.com', 'vocyqaf.com', 'vocyquc.com', 'vocyrom.com', 'vocyzek.com', 'vofybic.com', 'vofybyf.com', 'vofycot.com', 'vofycyk.com', 'vofydac.com', 'vofydut.com', 'vofygaf.com', 'vofyjuk.com', 'vofykoc.com', 'vofymem.com', 'vofypuk.com', 'vofyqit.com', 'vofyref.com', 'vofyzym.com', 'vojybek.com', 'vojybim.com', 'vojycif.com', 'vojydam.com', 'vojygok.com', 'vojygut.com', 'vojyjyc.com', 'vojykom.com', 'vojymet.com', 'vojymic.com', 'vojypuc.com', 'vojyquf.com', 'vojyrak.com', 'vojyzyt.com', 'volybec.com', 'volycik.com', 'volydot.com', 'volygyf.com', 'volyjok.com', 'volyjym.com', 'volykit.com', 'volymaf.com', 'volymum.com', 'volypum.com', 'volyquk.com', 'volyrac.com', 'volyzef.com', 'vonybat.com', 'vonycum.com', 'vonydik.com', 'vonygec.com', 'vonyjim.com', 'vonyket.com', 'vonykuk.com', 'vonymuf.com', 'vonypyf.com', 'vonyrot.com', 'vonyryc.com', 'vonyzac.com', 'vopybok.com', 'vopycom.com', 'vopycyf.com', 'vopydek.com', 'vopydum.com', 'vopygat.com', 'vopyjuf.com', 'vopykak.com', 'vopymyc.com', 'vopypec.com', 'vopypif.com', 'vopyqim.com', 'vopyret.com', 'vopyzuc.com', 'vowybof.com', 'vowycut.com', 'vowydic.com', 'vowygem.com', 'vowyjut.com', 'vowykaf.com', 'vowymyk.com', 'vowypek.com', 'vowypit.com', 'vowyqoc.com', 'vowyrif.com', 'vowyrym.com', 'vowyzam.com', 'vowyzuk.com', 'www.google.com']

        unseen_ioc_section = ResultTableSection("Unseen IOCs found in API calls", tags={'network.dynamic.domain': all_domains})
        for domain in all_domains:
            unseen_ioc_section.add_row(TableRow({"ioc_type": "domain", "ioc": domain}))
        unseen_ioc_section.set_heuristic(1013)
        correct_network_result_section.add_subsection(unseen_ioc_section)

        correct_result_section.add_subsection(correct_network_result_section)

        correct_netflows = [
            {'objectid': {'tag': '192.0.2.85:80', 'ontology_id': 'network_550DdvgkfnwyTggvjMO6NR', 'service_name': 'blah', 'guid': '{9A0F74D4-B438-43F3-8E04-20F4BE3E3581}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:44.000', 'session': None}, 'destination_ip': '192.0.2.85', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50217, 'http_details': {'request_uri': 'http://lysynur.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'lysynur.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.181:80', 'ontology_id': 'network_h4lCCPiVGpyWSVPprvxL9', 'service_name': 'blah', 'guid': '{3B408BE9-9D8F-4288-9199-0A46736094CC}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:44.000', 'session': None}, 'destination_ip': '192.0.2.181', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50216, 'http_details': {'request_uri': 'http://ganyhus.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'ganyhus.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.57:80', 'ontology_id': 'network_6SgUyi61GJ9wD7mfALcska', 'service_name': 'blah', 'guid': '{CD780F23-9C4C-47E3-9F36-65B0E16D0A7A}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:04.000', 'session': None}, 'destination_ip': '192.0.2.57', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50126, 'http_details': {'request_uri': 'http://galykes.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'galykes.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.125:80', 'ontology_id': 'network_18D7iEtWrktlw2vNTZUwLl', 'service_name': 'blah', 'guid': '{64CD1B07-095D-4B26-AE25-ABC4DE7C979D}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:04.000', 'session': None}, 'destination_ip': '192.0.2.125', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50124, 'http_details': {'request_uri': 'http://gatyfus.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'gatyfus.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.131:80', 'ontology_id': 'network_LhiiOq9EcnoGORBBQ5xcb', 'service_name': 'blah', 'guid': '{99B8065B-5A0F-48D5-84B4-CF2AE5E389D0}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:04.000', 'session': None}, 'destination_ip': '192.0.2.131', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50122, 'http_details': {'request_uri': 'http://qetyfuv.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'qetyfuv.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.217:80', 'ontology_id': 'network_5s9Cuy9geRePiia5P28ZAA', 'service_name': 'blah', 'guid': '{8B5CC06B-B702-4461-BB8D-4B2CD5FCDCF3}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:04.000', 'session': None}, 'destination_ip': '192.0.2.217', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50120, 'http_details': {'request_uri': 'http://vojyqem.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'vojyqem.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.246:80', 'ontology_id': 'network_1gsYRfQXomAMATyYd59DEv', 'service_name': 'blah', 'guid': '{1F598CC4-CFA3-439C-8381-CA42F91ADEBF}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:04.000', 'session': None}, 'destination_ip': '192.0.2.246', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50118, 'http_details': {'request_uri': 'http://puzylyp.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'puzylyp.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.91:80', 'ontology_id': 'network_2lnoehdBfRuDuylFP0x708', 'service_name': 'blah', 'guid': '{D4729539-50BA-4835-AD03-A809905F9339}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:04.000', 'session': None}, 'destination_ip': '192.0.2.91', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50116, 'http_details': {'request_uri': 'http://gahyqah.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'gahyqah.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.139:80', 'ontology_id': 'network_9ounWfmLHbRGHkqYxSFFb', 'service_name': 'blah', 'guid': '{C4A3B17E-E87A-4DCC-B556-177023BFFCB4}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:04.000', 'session': None}, 'destination_ip': '192.0.2.139', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50114, 'http_details': {'request_uri': 'http://lymysan.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'lymysan.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.120:80', 'ontology_id': 'network_5ZHHowzo6Jvp8L2SxjBTXe', 'service_name': 'blah', 'guid': '{2F9CEAF9-FE48-435E-B734-D8094FDAF514}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:04.000', 'session': None}, 'destination_ip': '192.0.2.120', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50112, 'http_details': {'request_uri': 'http://qedynul.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'qedynul.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.208:80', 'ontology_id': 'network_3zQ3o8jfjd2IcpANpiWEBY', 'service_name': 'blah', 'guid': '{2BB494FB-6230-419E-BB59-C152AC2EFE39}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:04.000', 'session': None}, 'destination_ip': '192.0.2.208', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50110, 'http_details': {'request_uri': 'http://gadyniw.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'gadyniw.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.200:80', 'ontology_id': 'network_51S4ygtpR6Q1WeMfykO6Ic', 'service_name': 'blah', 'guid': '{C701F7CC-81B2-439F-BCEF-27DCDC7EBDC9}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:04.000', 'session': None}, 'destination_ip': '192.0.2.200', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50108, 'http_details': {'request_uri': 'http://purycap.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'purycap.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.178:80', 'ontology_id': 'network_61CB5oY4FjpFDxEzp0DTlb', 'service_name': 'blah', 'guid': '{FDD4CE7F-E330-4E76-81A2-468749C3BCC6}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.178', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50106, 'http_details': {'request_uri': 'http://vocyzit.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'vocyzit.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.162:80', 'ontology_id': 'network_1ynStFC56ngx1dLjMi5Uxv', 'service_name': 'blah', 'guid': '{FCA3FE75-0231-499F-9B44-C4DBAD0AE4AC}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.162', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50104, 'http_details': {'request_uri': 'http://lyryfyd.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'lyryfyd.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.203:80', 'ontology_id': 'network_5gYS7ZprItf2dP0Mk0xfUt', 'service_name': 'blah', 'guid': '{D0608E2B-2E5D-42D8-BFAB-87EBDC96DFDC}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.203', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50102, 'http_details': {'request_uri': 'http://vonypom.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'vonypom.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.28:80', 'ontology_id': 'network_3PRDVdSwiHhmWUj6NXAXDM', 'service_name': 'blah', 'guid': '{9BFE26B1-D8BC-408A-8333-065240C52A1A}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.28', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50100, 'http_details': {'request_uri': 'http://vocyruk.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'vocyruk.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.254:80', 'ontology_id': 'network_3c2sXxUmcDneQFTCFLum1m', 'service_name': 'blah', 'guid': '{004504F3-4C72-4C46-BB09-2BC42E860907}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.254', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50098, 'http_details': {'request_uri': 'http://pumyxiv.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'pumyxiv.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.198:80', 'ontology_id': 'network_9hTC5jHDMWWbnKwNwWlHD', 'service_name': 'blah', 'guid': '{31716BF9-A22C-4353-B97D-68214589DB95}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.198', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50096, 'http_details': {'request_uri': 'http://lygymoj.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'lygymoj.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.173:80', 'ontology_id': 'network_4G9xrReRkp0ue96XJb1HJT', 'service_name': 'blah', 'guid': '{1E2B4447-3497-4D31-8A8C-3098AA0BC08D}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.173', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50094, 'http_details': {'request_uri': 'http://pumypog.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'pumypog.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.67:80', 'ontology_id': 'network_4KFAC7PcorCiovATAGt4F7', 'service_name': 'blah', 'guid': '{F7F0C167-9A9D-4DB2-8CCB-BF8AB134D8E2}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.67', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50092, 'http_details': {'request_uri': 'http://vowydef.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'vowydef.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.19:80', 'ontology_id': 'network_60ACR6kq5VK7wglXkN3rBw', 'service_name': 'blah', 'guid': '{4107127B-D9C7-4ED3-A8DE-6C562CDB6771}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.19', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50088, 'http_details': {'request_uri': 'http://pupybul.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'pupybul.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.43:80', 'ontology_id': 'network_57N6KJfZxlROew7cWaIzZp', 'service_name': 'blah', 'guid': '{DD7254B0-306C-4652-AC12-C670782C7FF3}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.43', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50086, 'http_details': {'request_uri': 'http://lyvytuj.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'lyvytuj.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.6:80', 'ontology_id': 'network_1nu514SE7BzOfdmfAM3tq1', 'service_name': 'blah', 'guid': '{D274024D-F84C-46BE-A4DE-3657C68BE07E}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.6', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50084, 'http_details': {'request_uri': 'http://gacyryw.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'gacyryw.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.153:80', 'ontology_id': 'network_3WPTh1XoSdJ8nv4bTU6Afq', 'service_name': 'blah', 'guid': '{97B82ED6-2265-40DE-9670-14BF0D10FCBF}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:03.000', 'session': None}, 'destination_ip': '192.0.2.153', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50082, 'http_details': {'request_uri': 'http://vopybyt.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'vopybyt.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.18:80', 'ontology_id': 'network_1e6yax8XX1KnoniROiTO2O', 'service_name': 'blah', 'guid': '{F8E2C370-6421-4558-8A50-46E490791F64}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.18', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50078, 'http_details': {'request_uri': 'http://qebytiq.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'qebytiq.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.94:80', 'ontology_id': 'network_1yxfWeXKGzKu69QLDqym3J', 'service_name': 'blah', 'guid': '{6E270263-AA5F-4010-87DA-09FF27C16961}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.94', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50076, 'http_details': {'request_uri': 'http://pufymoq.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'pufymoq.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.54:80', 'ontology_id': 'network_3AV5JkuHB6bwuyja9qVZUV', 'service_name': 'blah', 'guid': '{F93FB76E-A36E-452D-BFDC-192322449B5C}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.54', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50074, 'http_details': {'request_uri': 'http://qexylup.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'qexylup.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.155:80', 'ontology_id': 'network_2t8JL40JVk83xJechxyyXU', 'service_name': 'blah', 'guid': '{42FF9EDA-0385-46E7-9B2C-B112427D1D74}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.155', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50072, 'http_details': {'request_uri': 'http://pujyjav.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'pujyjav.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.219:80', 'ontology_id': 'network_1qwLQysQsjCLEqZHvGps3D', 'service_name': 'blah', 'guid': '{6FAA22CA-9886-4104-94C1-94A62363294C}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.219', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50070, 'http_details': {'request_uri': 'http://volykyc.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'volykyc.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.33:80', 'ontology_id': 'network_1FwlAqLnzYzSpmHhfWDubB', 'service_name': 'blah', 'guid': '{AF669C7F-AB2B-481C-8B42-A33A297AF58D}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.33', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50068, 'http_details': {'request_uri': 'http://puvyxil.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'puvyxil.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.99:80', 'ontology_id': 'network_1Gza83IAK0aOci4AkkVLDs', 'service_name': 'blah', 'guid': '{F1EA81C0-C318-4BB2-B7F4-734D922B63A0}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.99', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50066, 'http_details': {'request_uri': 'http://pufygug.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'pufygug.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.78:80', 'ontology_id': 'network_wPFmXzLo2uWLTfffbqyED', 'service_name': 'blah', 'guid': '{B7F4A98B-F244-405F-8070-27982BF191D9}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.78', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50064, 'http_details': {'request_uri': 'http://vofymik.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'vofymik.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.167:80', 'ontology_id': 'network_4bfSba3uqwUF1pHGw3jLDi', 'service_name': 'blah', 'guid': '{058E7509-0515-4488-847D-6EE4866F8388}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.167', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50060, 'http_details': {'request_uri': 'http://qexyryl.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'qexyryl.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.34:80', 'ontology_id': 'network_7G1IgvqUlSRMf7QBmozDny', 'service_name': 'blah', 'guid': '{6B9AA4FC-8999-4698-A46A-FDA2A77D326B}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.34', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50058, 'http_details': {'request_uri': 'http://puzywel.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'puzywel.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.212:80', 'ontology_id': 'network_6aIzlbQm5XW4pr2DOSJMZ5', 'service_name': 'blah', 'guid': '{22AD5C43-D9A0-47AD-B9D5-DC0DD89EBE67}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.212', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50056, 'http_details': {'request_uri': 'http://lyxylux.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'lyxylux.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.251:80', 'ontology_id': 'network_2mfyQzZkEBb5P4SWXWts9s', 'service_name': 'blah', 'guid': '{69091D77-36FC-47AF-B34B-046B7FC13B53}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:02.000', 'session': None}, 'destination_ip': '192.0.2.251', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50054, 'http_details': {'request_uri': 'http://qeqysag.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'qeqysag.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.60:80', 'ontology_id': 'network_1nw9JkFvHd90bc5WgP4GuO', 'service_name': 'blah', 'guid': '{D876709F-9859-4687-944B-565683721A32}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:01.000', 'session': None}, 'destination_ip': '192.0.2.60', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50050, 'http_details': {'request_uri': 'http://purydyv.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'purydyv.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.25:80', 'ontology_id': 'network_6c3UDV8y0Lce8RKaie56Et', 'service_name': 'blah', 'guid': '{37E7F484-7781-479D-B8AB-D1FDD65D16B1}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:01.000', 'session': None}, 'destination_ip': '192.0.2.25', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50048, 'http_details': {'request_uri': 'http://qegyqaq.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'qegyqaq.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.172:80', 'ontology_id': 'network_6cwEzn5WzptbXLpzFib6ZU', 'service_name': 'blah', 'guid': '{124FE8C1-27C2-4348-B475-687D9A8DB199}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:01.000', 'session': None}, 'destination_ip': '192.0.2.172', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50044, 'http_details': {'request_uri': 'http://qeqyxov.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'qeqyxov.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.133:80', 'ontology_id': 'network_5PzPv9wE97frwV8tH0EFWv', 'service_name': 'blah', 'guid': '{6623DF83-C706-4F7A-AF68-473879FC3373}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:01.000', 'session': None}, 'destination_ip': '192.0.2.133', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50042, 'http_details': {'request_uri': 'http://qetyvep.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'qetyvep.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.106:80', 'ontology_id': 'network_2laWa6ShSzMkszn5zR5opE', 'service_name': 'blah', 'guid': '{A96AB7B0-6EC5-402D-8128-387174639472}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:01.000', 'session': None}, 'destination_ip': '192.0.2.106', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50040, 'http_details': {'request_uri': 'http://gahyhob.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'gahyhob.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.92:80', 'ontology_id': 'network_2HqpGx1eUn8sM4K8dNeLJD', 'service_name': 'blah', 'guid': '{F781F5FD-B8A8-44C7-AD4F-18889E16016C}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:01.000', 'session': None}, 'destination_ip': '192.0.2.92', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50038, 'http_details': {'request_uri': 'http://lyxywer.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'lyxywer.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.44:80', 'ontology_id': 'network_2lb4Ii7BERRbWXJpJJYyvs', 'service_name': 'blah', 'guid': '{02359B43-D23B-4746-BCCD-C3BDF820C293}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:01.000', 'session': None}, 'destination_ip': '192.0.2.44', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50034, 'http_details': {'request_uri': 'http://gaqycos.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'gaqycos.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.82:80', 'ontology_id': 'network_y7G06aUbzuS6WkrWYfVE3', 'service_name': 'blah', 'guid': '{85E65D7C-3F32-4004-A46D-CB9F4FCEB350}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:01.000', 'session': None}, 'destination_ip': '192.0.2.82', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50032, 'http_details': {'request_uri': 'http://lygygin.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'lygygin.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.13:80', 'ontology_id': 'network_2b6Bozm6WRZ989WusZBYC0', 'service_name': 'blah', 'guid': '{5B05EB06-8EF1-46DD-A7AC-86801F70474F}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:01.000', 'session': None}, 'destination_ip': '192.0.2.13', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50028, 'http_details': {'request_uri': 'http://vowycac.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'vowycac.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.45:80', 'ontology_id': 'network_23YaMjOIUjmMASNeYEVBS5', 'service_name': 'blah', 'guid': '{6F8346DD-7440-4431-817F-7DE52B686F93}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:01.000', 'session': None}, 'destination_ip': '192.0.2.45', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50024, 'http_details': {'request_uri': 'http://vofygum.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'vofygum.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.15:80', 'ontology_id': 'network_5pmgVhykWU2Mv7YWUzKFYc', 'service_name': 'blah', 'guid': '{6F35E9C5-02FB-4365-8D4E-C128AC7F6203}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:00.000', 'session': None}, 'destination_ip': '192.0.2.15', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50022, 'http_details': {'request_uri': 'http://volyqat.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'volyqat.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.124:80', 'ontology_id': 'network_6l0RVifCGHge13kVJEBjIh', 'service_name': 'blah', 'guid': '{53E789DD-3CCB-45ED-AF47-DE35031DDD15}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:00.000', 'session': None}, 'destination_ip': '192.0.2.124', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50020, 'http_details': {'request_uri': 'http://puvytuq.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'puvytuq.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.240:80', 'ontology_id': 'network_XjOMhw3KdPdgbNdSDHads', 'service_name': 'blah', 'guid': '{EBCF699D-CD75-4E1E-BE90-BE82E638F703}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:00.000', 'session': None}, 'destination_ip': '192.0.2.240', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50016, 'http_details': {'request_uri': 'http://gadyfuh.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'gadyfuh.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.74:80', 'ontology_id': 'network_2JHwVElJppLKvieK13YbAz', 'service_name': 'blah', 'guid': '{71E416C2-689E-450E-BD05-F600A86DBA4C}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:00.000', 'session': None}, 'destination_ip': '192.0.2.74', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50014, 'http_details': {'request_uri': 'http://lyryvex.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'lyryvex.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.238:80', 'ontology_id': 'network_2UMXALemxFkNIMq3jwMHPH', 'service_name': 'blah', 'guid': '{7396D3D4-9F50-4688-8875-5DD3D234E1C1}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:00.000', 'session': None}, 'destination_ip': '192.0.2.238', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50012, 'http_details': {'request_uri': 'http://lymyxid.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'lymyxid.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.232:80', 'ontology_id': 'network_1JhVw4JaUjSwuuROHeDY3g', 'service_name': 'blah', 'guid': '{41797FE6-57A0-4AC1-AA4C-FCBE78B4D762}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:00.000', 'session': None}, 'destination_ip': '192.0.2.232', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50010, 'http_details': {'request_uri': 'http://qekyqop.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'qekyqop.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.123:80', 'ontology_id': 'network_jlFFuFU2DnH3iep3gO0GB', 'service_name': 'blah', 'guid': '{7CDA65D1-68ED-40C4-BD17-93E0DD8856A9}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:00.000', 'session': None}, 'destination_ip': '192.0.2.123', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50008, 'http_details': {'request_uri': 'http://qedyfyq.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'qedyfyq.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.192:80', 'ontology_id': 'network_5ZcTvhePCXnBZjDVEhOTet', 'service_name': 'blah', 'guid': '{FB71F64E-27E2-44D6-A41C-D25AA0DDB0FF}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:00.000', 'session': None}, 'destination_ip': '192.0.2.192', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50006, 'http_details': {'request_uri': 'http://vonyzuf.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'vonyzuf.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.58:80', 'ontology_id': 'network_M3EqIGew2LZL1XeDSxVxq', 'service_name': 'blah', 'guid': '{AB6CF9FB-A2E0-4A8D-B666-111624AC4F7B}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:00.000', 'session': None}, 'destination_ip': '192.0.2.58', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50004, 'http_details': {'request_uri': 'http://galyqaz.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'galyqaz.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.0.2.84:80', 'ontology_id': 'network_7jz5FF3p5Ik4z906k7qBfL', 'service_name': 'blah', 'guid': '{31F86178-62E4-4D49-8210-792AD3BCB2DC}', 'treeid': None, 'processtree': None, 'time_observed': '2023-04-18 18:03:00.000', 'session': None}, 'destination_ip': '192.0.2.84', 'destination_port': 80, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': '192.168.0.9', 'source_port': 50002, 'http_details': {'request_uri': 'http://lysyfyj.com/login.php', 'request_method': 'GET', 'request_headers': {'Referer': 'http://www.google.com', 'UserAgent': 'Mozilla/4.0 (compatible; MSIE 2.0; Windows NT 5.0; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 'Host': 'lysyfyj.com'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{2C5E0080-6567-4063-88BE-1E66A2F4B143}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qetyraq.com', 'resolved_ips': ['192.0.2.85'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{5A9F0D73-912E-46C0-9064-6891B2D231B5}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lysynur.com', 'resolved_ips': ['192.0.2.85'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{9BCE002E-6241-421E-8960-4E331BAEC521}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'ganyhus.com', 'resolved_ips': ['192.0.2.181'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{FFFA0EEB-EE5B-4F4B-A987-48B79D2D0528}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'DESKTOP-LG3F6GA', 'resolved_ips': ['192.168.0.9'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{21783F3F-622F-4F99-A54E-1229CF0CB9B9}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lyvyxor.com', 'resolved_ips': ['192.0.2.57'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{D7A6C1B8-71DD-4105-AA68-F1523329469E}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'galykes.com', 'resolved_ips': ['192.0.2.57'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{5975E197-A93A-4E40-963F-5725D09DAA7D}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'gatyfus.com', 'resolved_ips': ['192.0.2.125'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{F61F561C-D71F-4783-81F5-A38AFEEC14C7}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qetyfuv.com', 'resolved_ips': ['192.0.2.131'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{39E18DDF-06C8-4A73-9D55-543608FDC31E}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'vojyqem.com', 'resolved_ips': ['192.0.2.217'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{0E7037B8-3287-4B7D-8027-BE6AC58681F0}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'puzylyp.com', 'resolved_ips': ['192.0.2.246'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{9A887B6D-3AC8-4BF7-8789-53CE4C5DFD58}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'gahyqah.com', 'resolved_ips': ['192.0.2.91'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{FE089C88-31AB-4CE3-8CD6-22E281158D72}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lymysan.com', 'resolved_ips': ['192.0.2.139'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{CFEDEE14-A76B-4116-A600-61725D95A28E}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qedynul.com', 'resolved_ips': ['192.0.2.120'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{276A95E6-B730-4DF5-87C7-F3DEFCE17F82}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'gadyniw.com', 'resolved_ips': ['192.0.2.208'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{6F6FA3B0-CF69-4D43-84FC-A2B6F07B30AD}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'purycap.com', 'resolved_ips': ['192.0.2.200'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{7E9A98C4-04FC-429F-B13F-713713BD9E0E}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'vocyzit.com', 'resolved_ips': ['192.0.2.178'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{2BE9A773-700E-4859-8ED6-B88247A3C148}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lyryfyd.com', 'resolved_ips': ['192.0.2.162'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{5098A9E2-02A2-49B3-8E7E-B959C043B735}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'vonypom.com', 'resolved_ips': ['192.0.2.203'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{9BF05949-89D7-42ED-9FAE-A90EE6CB9318}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'gacyzuz.com', 'resolved_ips': ['192.0.2.28'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{B66537D0-75AF-43EB-ACA2-9DD7B58BA73D}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'vocyruk.com', 'resolved_ips': ['192.0.2.28'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{3C0442E8-F30C-4DCD-9E06-90750F1666B4}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'gatyvyz.com', 'resolved_ips': ['192.0.2.254'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{C6A19982-467D-4C68-9E0E-43C6670D6177}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'pumyxiv.com', 'resolved_ips': ['192.0.2.254'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{280007B4-4CFE-4920-AE91-682C6E8C58FE}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lygymoj.com', 'resolved_ips': ['192.0.2.198'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{CD6FAA20-5604-4E0B-9406-C33920755E42}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'pumypog.com', 'resolved_ips': ['192.0.2.173'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{C63CD44C-3484-4576-8CA6-29CBA58B5F5F}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qekykev.com', 'resolved_ips': ['192.0.2.67'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{7C8E0B08-3AB2-4C62-A10B-51E98D4248DB}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'vowydef.com', 'resolved_ips': ['192.0.2.67'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{752FDACA-B37D-4B5C-AD25-EA5128C24D83}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'pupybul.com', 'resolved_ips': ['192.0.2.19'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{69D51266-09FE-4056-8217-7B4B5FC537E7}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'ganypih.com', 'resolved_ips': ['192.0.2.43'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{2447013D-2DE4-4495-88FA-2CA598162EB8}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lyvytuj.com', 'resolved_ips': ['192.0.2.43'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{531AE8FF-220A-4BE4-ADA3-EBAE980772EB}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'gacyryw.com', 'resolved_ips': ['192.0.2.6'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{41660B13-0ACD-4161-B9C9-3B06E684C212}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lykyjad.com', 'resolved_ips': ['192.0.2.153'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{0E842725-144E-436A-8C09-73C4A512CDB2}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'vopybyt.com', 'resolved_ips': ['192.0.2.153'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{BAB3DA6E-2EB9-455D-8431-9B9818573FA2}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qebytiq.com', 'resolved_ips': ['192.0.2.18'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{8A72841C-A1A7-4703-B2A3-13D13B374A58}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'pufymoq.com', 'resolved_ips': ['192.0.2.94'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{C60B7E99-E7F2-45B7-870D-DA721526CA9D}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qexylup.com', 'resolved_ips': ['192.0.2.54'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{26247731-3C8A-4EDF-8730-2FCCAD9800A6}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'pujyjav.com', 'resolved_ips': ['192.0.2.155'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{0E72FA92-390B-4106-802D-F6320AC72E3B}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'volykyc.com', 'resolved_ips': ['192.0.2.219'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{11634AEE-9BAB-412E-A87B-A298C9500FC3}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'puvyxil.com', 'resolved_ips': ['192.0.2.33'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{03EACF59-E5EF-44AE-903E-4CDEE8E7CAB7}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'pufygug.com', 'resolved_ips': ['192.0.2.99'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{32774EFE-5671-4240-9586-E10FB9D73C51}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'vofymik.com', 'resolved_ips': ['192.0.2.78'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{32EB2492-871A-4FA1-8DB0-EF22E6438676}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'gaqydeb.com', 'resolved_ips': ['192.0.2.167'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{F8B0FC3E-2EEB-4500-862E-34D23F1B2BDA}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qexyryl.com', 'resolved_ips': ['192.0.2.167'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{13522284-DDD4-4275-8257-D5A355EECCCB}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'puzywel.com', 'resolved_ips': ['192.0.2.34'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{D150EDD2-9231-42B4-A13A-89C9C10F7D61}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lyxylux.com', 'resolved_ips': ['192.0.2.212'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{F5896043-7B0F-49DB-8A4C-1DA2B9F73EE9}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qeqysag.com', 'resolved_ips': ['192.0.2.251'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{85FA10C1-517B-4576-A407-53CFB3B2218E}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'purydyv.com', 'resolved_ips': ['192.0.2.60'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{E911CD3C-23FE-4D65-ACAD-A1A5E54A2FC4}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qegyqaq.com', 'resolved_ips': ['192.0.2.25'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{3AA75047-9B2D-491A-8CCC-6ABE387E6E1C}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qegyhig.com', 'resolved_ips': ['192.0.2.172'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{3DAC6981-1B96-4DFE-B9DF-B84A71C9D0E9}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qeqyxov.com', 'resolved_ips': ['192.0.2.172'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{94EB7619-995C-4C40-992B-09BD2838645D}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qetyvep.com', 'resolved_ips': ['192.0.2.133'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{52BBEAF3-A42C-4F4B-A6E1-83E617867C95}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'gahyhob.com', 'resolved_ips': ['192.0.2.106'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{CDA94564-ECDD-4A39-934E-B3C3F7BCD6EA}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'vojyjof.com', 'resolved_ips': ['192.0.2.92'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{36DA6E20-4485-46F2-8A1D-C03C2414A048}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lyxywer.com', 'resolved_ips': ['192.0.2.92'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{F9E32787-5BD7-4317-B083-57EA1AB2038F}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'gaqycos.com', 'resolved_ips': ['192.0.2.44'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{BC8EAF53-DE21-448F-A77E-514D19DAEEE0}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lygygin.com', 'resolved_ips': ['192.0.2.82'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{D39D7CFD-1CAE-4C3F-B18F-9B9B6ED63C35}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'vowycac.com', 'resolved_ips': ['192.0.2.13'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{D8A1765C-F47F-4B74-8BDC-0AC56C4B2E2A}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'vofygum.com', 'resolved_ips': ['192.0.2.45'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{09D873E0-5157-49F0-B543-3A0CC5952444}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'volyqat.com', 'resolved_ips': ['192.0.2.15'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{BBFBC9FC-D318-45B5-9DB2-ED086B61B46B}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'puvytuq.com', 'resolved_ips': ['192.0.2.124'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{41F8364E-2A96-4DA9-9005-0250C0F0A3B3}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'gadyfuh.com', 'resolved_ips': ['192.0.2.240'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{9F514DDB-CD22-4864-AC81-BFF3AD60A915}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lyryvex.com', 'resolved_ips': ['192.0.2.74'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{E340989B-8AE1-4A9A-BC4C-3F28C6636B4C}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lymyxid.com', 'resolved_ips': ['192.0.2.238'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{B56B905B-ACF5-42EA-A9E2-B33665AF5424}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qekyqop.com', 'resolved_ips': ['192.0.2.232'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{BA65FFF6-BB4E-4AD5-8FDC-F5F932ACC0B6}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'qedyfyq.com', 'resolved_ips': ['192.0.2.123'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{3C993504-B3C9-4F03-BEDE-9464F526A705}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'vonyzuf.com', 'resolved_ips': ['192.0.2.192'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{83780A8C-A5BF-4793-9206-CB35AC2F845B}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'galyqaz.com', 'resolved_ips': ['192.0.2.58'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{98378EE0-60C3-4EAE-8E32-C08640DDCF41}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'lysyfyj.com', 'resolved_ips': ['192.0.2.84'], 'lookup_type': 'A'}, 'connection_type': 'dns'}
        ]

        process_network(network, parent_result_section, inetsim_network, routing, process_map, safelist, ontres, inetsim_dns_servers, False)
        assert check_section_equality(parent_result_section, correct_result_section)

        for index, netflow in enumerate(ontres.netflows):
            # Ignore guids since they are random
            netflow_as_prims = netflow.as_primitives()
            _ = netflow_as_prims["objectid"].pop("guid")
            _ = correct_netflows[index]["objectid"].pop("guid")
            assert netflow_as_prims == correct_netflows[index]

        # Example 5: Non-standard DNS Server
        network = {"udp": [{"dst": "1.2.3.4", "dport": 53, "src": "1.1.1.1", "time": 1681841026.165553}]}
        parent_result_section = ResultSection("blah")
        ontres = OntologyResults(service_name="blah")
        sandbox = ontres.create_sandbox(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), sandbox_name="CAPE")
        ontres.add_sandbox(sandbox)
        process_map = {}

        correct_result_section = ResultSection("blah")
        correct_network_result_section = ResultSection("Network Activity", parent=correct_result_section)
        dns_server_heur = Heuristic(1008)
        dns_server_sec = ResultTextSection(dns_server_heur.name, heuristic=dns_server_heur, body=dns_server_heur.description, parent=correct_network_result_section)
        dns_server_sec.add_line("\t-\t1.2.3.4")
        dns_server_sec.add_tag("network.dynamic.ip", "1.2.3.4")
        process_network(network, parent_result_section, inetsim_network, routing, process_map, safelist, ontres, inetsim_dns_servers, False)
        assert check_section_equality(parent_result_section, correct_result_section)

        # Example 6: DNS Server that matches INetSim DNS server and routing is INETSIM
        inetsim_dns_servers = ["1.2.3.4"]
        network = {"udp": [{"dst": "1.2.3.4", "dport": 53, "src": "1.1.1.1", "time": 1681841026.165553}]}
        parent_result_section = ResultSection("blah")
        ontres = OntologyResults(service_name="blah")
        sandbox = ontres.create_sandbox(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), sandbox_name="CAPE")
        ontres.add_sandbox(sandbox)
        process_map = {}

        correct_result_section = ResultSection("blah")
        process_network(network, parent_result_section, inetsim_network, routing, process_map, safelist, ontres, inetsim_dns_servers, False)
        assert check_section_equality(parent_result_section, correct_result_section)

        # Example 7: HTTPS Proxy causes decrypted URL to be reported
        network =  {
            'hosts': [],
            'domains': [
                {'domain': 'microsoft.com', 'ip': ''},
            ],
            'tcp': [],
            'udp': [],
            'icmp': [],
            'http': [
                {'count': 2, 'host': 'microsoft.com:443', 'port': 8080, 'data': 'CONNECT microsoft.com:443 HTTP/1.0\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)\r\nHost: microsoft.com:443\r\nContent-Length: 0\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n', 'uri': 'http://microsoft.com:443', 'body': '', 'path': '', 'user-agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'version': '1.0', 'method': 'CONNECT'},
            ],
            'dns': [
                {'request': 'microsoft.com', 'type': 'A', 'answers': [{'type': 'A', 'data': '192.0.2.126'}]},
            ],
            'smtp': [],
            'irc': [],
            'dead_hosts': [],
            'http_ex': [],
            'https_ex': [],
            'smtp_ex': []
        }
        parent_result_section = ResultSection("blah")
        ontres = OntologyResults(service_name="blah")
        sandbox = ontres.create_sandbox(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), sandbox_name="CAPE")
        ontres.add_sandbox(sandbox)
        process_map = {
            512: {'name': 'C:\\Windows\\System32\\rundll32.exe', 'network_calls': [], 'decrypted_buffers': []},
            1296: {'name': 'C:\\Windows\\System32\\wermgr.exe', 'network_calls': [{'InternetCrackUrlA': {'url': 'https://microsoft.com:443/'}}, {'InternetConnectA': {'service': '3', 'servername': 'microsoft.com', 'serverport': '443'}}, {'GetAddrInfoW': {'nodename': 'wpad'}}, {'GetAddrInfoW': {'nodename': 'microsoft.com'}}], 'decrypted_buffers': []}
        }

        correct_result_section = ResultSection("blah")
        correct_network_result_section = ResultSection("Network Activity")

        dns_subsection = ResultTableSection("Protocol: DNS", tags={'network.protocol': ['dns'], 'network.dynamic.domain': ['microsoft.com']})
        dns_subsection.add_row(TableRow({"domain": "microsoft.com", "answer": "192.0.2.126", "type": "A"}))
        dns_subsection.set_heuristic(1000)

        http_subsection = ResultTableSection("Protocol: HTTP/HTTPS", tags={'network.protocol': ['http'], 'network.dynamic.domain': ['microsoft.com'], 'network.dynamic.uri': ['https://microsoft.com']})
        http_subsection.add_row(TableRow({"process_name": "None (None)", "method": "CONNECT", "request": {"UserAgent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)", "Host": "microsoft.com:443", "ContentLength": "0", "ProxyConnection": "Keep-Alive", "Pragma": "no-cache"}, "uri": "https://microsoft.com"}))
        http_subsection.set_heuristic(1002)

        http_header_ioc_subsection = ResultTableSection("IOCs found in HTTP/HTTPS Headers", tags={'network.dynamic.domain': ['microsoft.com']})
        http_header_ioc_subsection.add_row(TableRow({"ioc_type": "domain", "ioc": "microsoft.com"}))
        http_subsection.add_subsection(http_header_ioc_subsection)

        correct_network_result_section.add_subsection(dns_subsection)
        correct_network_result_section.add_subsection(http_subsection)

        correct_result_section.add_subsection(correct_network_result_section)

        correct_netflows = [
            {'objectid': {'tag': '192.168.0.4:53', 'ontology_id': 'network_gDS744W2fiKNBFkc7fWIw', 'service_name': 'blah', 'guid': '{E100429A-B64B-4FE5-92C4-422F1F762228}', 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.168.0.4', 'destination_port': 53, 'transport_layer_protocol': 'udp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': None, 'dns_details': {'domain': 'microsoft.com', 'resolved_ips': ['192.0.2.126'], 'lookup_type': 'A'}, 'connection_type': 'dns'},
            {'objectid': {'tag': '192.0.2.126:8080', 'ontology_id': 'network_5p4ftHudCdnVUAj31rdsMI', 'service_name': 'blah', 'guid': None, 'treeid': None, 'processtree': None, 'time_observed': None, 'session': None}, 'destination_ip': '192.0.2.126', 'destination_port': 8080, 'transport_layer_protocol': 'tcp', 'direction': 'outbound', 'process': None, 'source_ip': None, 'source_port': None, 'http_details': {'request_uri': 'http://microsoft.com:443', 'request_method': 'CONNECT', 'request_headers': {'UserAgent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; InfoPath.3; .NET4.0C; .NET4.0E)', 'Host': 'microsoft.com:443', 'ContentLength': '0', 'ProxyConnection': 'Keep-Alive', 'Pragma': 'no-cache'}, 'response_headers': {}, 'request_body': None, 'response_status_code': None, 'response_body': None}, 'dns_details': None, 'connection_type': 'http'},
        ]

        process_network(network, parent_result_section, inetsim_network, routing, process_map, safelist, ontres, inetsim_dns_servers, True)
        assert check_section_equality(parent_result_section, correct_result_section)

    @staticmethod
    def test_process_unseen_iocs():
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
        unseen_res = ResultTableSection("Unseen IOCs found in API calls", tags={'network.dynamic.domain': ['blah.com'], 'network.dynamic.uri': ['http://blah.com/blah'], 'network.dynamic.uri_path': ['/blah']})
        unseen_res.add_row(TableRow({"ioc_type": "domain", "ioc": "blah.com"}))
        unseen_res.add_row(TableRow({"ioc_type": "uri", "ioc": "http://blah.com/blah"}))
        unseen_res.set_heuristic(1013)
        correct_result_section.add_subsection(unseen_res)
        process_map = {123: {"network_calls": [{"something": {"uri": "http://blah.com/blah"}}]}}
        _process_unseen_iocs(parent_result_section, process_map, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)

        # Seen URI
        parent_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah")
        process_map = {123: {"network_calls": [{"something": {"uri": "http://blah.ca/blah"}}]}}
        _process_unseen_iocs(parent_result_section, process_map, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)

        # Seen URI after massaging
        parent_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah")
        process_map = {123: {"network_calls": [{"something": {"uri": "http://blah.ca/blah:80", "uri2": "https://blah.ca/blah:443"}}]}}
        _process_unseen_iocs(parent_result_section, process_map, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)

        # Seen URI in blob
        parent_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah")
        process_map = {123: {"network_calls": [{"something": {"uri": "blahblahblah http://blah.ca/blah blahblahblah", "uri2": "blahblahblah https://blah.ca/blah blahblahblah"}}]}}
        _process_unseen_iocs(parent_result_section, process_map, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)

        # Seen URI in blob after massaging
        parent_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah")
        process_map = {123: {"network_calls": [{"something": {"uri": "blahblahblah http://blah.ca/blah blahblahblah", "uri2": "blahblahblah https://blah.ca/blah blahblahblah"}}]}}
        _process_unseen_iocs(parent_result_section, process_map, default_so, {})
        assert check_section_equality(parent_result_section, correct_result_section)

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
    def test_get_dns_sec():
        # Nothing test
        resolved_ips = {}
        safelist = []
        assert _get_dns_sec(resolved_ips, safelist) is None

        # Standard test with no type
        resolved_ips = {"1.1.1.1": [{"domain": "blah.com"}]}
        expected_res_sec = ResultSection(
            "Protocol: DNS", body_format=BODY_FORMAT.TABLE, body=dumps([{"domain": "blah.com", "answer": "1.1.1.1", "type": None}])
        )
        expected_res_sec.set_heuristic(1000)
        expected_res_sec.add_tag("network.protocol", "dns")
        expected_res_sec.add_tag("network.dynamic.ip", "1.1.1.1")
        expected_res_sec.add_tag("network.dynamic.domain", "blah.com")
        actual_res_sec = _get_dns_sec(resolved_ips, safelist)
        assert check_section_equality(actual_res_sec, expected_res_sec)

        # Standard test with type
        resolved_ips = {"1.1.1.1": [{"domain": "blah.com", "type": "A"}]}
        expected_res_sec = ResultSection(
            "Protocol: DNS", body_format=BODY_FORMAT.TABLE, body=dumps([{"domain": "blah.com", "answer": "1.1.1.1", "type": "A"}])
        )
        expected_res_sec.set_heuristic(1000)
        expected_res_sec.add_tag("network.protocol", "dns")
        expected_res_sec.add_tag("network.dynamic.ip", "1.1.1.1")
        expected_res_sec.add_tag("network.dynamic.domain", "blah.com")
        actual_res_sec = _get_dns_sec(resolved_ips, safelist)
        assert check_section_equality(actual_res_sec, expected_res_sec)

        # No answer test
        resolved_ips = {"0": [{"domain": "blah.com"}]}
        expected_res_sec = ResultSection(
            "Protocol: DNS", body_format=BODY_FORMAT.TABLE, body=dumps([{"domain": "blah.com", "type": None}])
        )
        expected_res_sec.set_heuristic(1000)
        expected_res_sec.add_tag("network.protocol", "dns")
        expected_res_sec.add_tag("network.dynamic.domain", "blah.com")
        expected_res_sec.add_subsection(ResultSection(
            title_text="DNS services are down!",
            body="Contact the CAPE administrator for details.",
        ))
        actual_res_sec = _get_dns_sec(resolved_ips, safelist)
        assert check_section_equality(actual_res_sec, expected_res_sec)

        # Non-standard DNS query
        resolved_ips = {"1.1.1.1": [{"domain": "blah.com", "type": "TXT"}]}
        expected_res_sec = ResultSection(
            "Protocol: DNS", body_format=BODY_FORMAT.TABLE, body=dumps([{"domain": "blah.com", "answer": "1.1.1.1", "type": "TXT"}])
        )
        expected_res_sec.set_heuristic(1000)
        expected_res_sec.add_tag("network.protocol", "dns")
        expected_res_sec.add_tag("network.dynamic.ip", "1.1.1.1")
        expected_res_sec.add_tag("network.dynamic.domain", "blah.com")
        expected_dns_query_res_sec = ResultSection("Non-Standard DNS Query Used", body="CAPE detected a non-standard DNS query being used")
        expected_dns_query_res_sec.set_heuristic(1009)
        expected_dns_query_res_sec.add_line(f"\t-\tTXT")
        expected_res_sec.add_subsection(expected_dns_query_res_sec)
        actual_res_sec = _get_dns_sec(resolved_ips, safelist)
        assert check_section_equality(actual_res_sec, expected_res_sec)

    @staticmethod
    @pytest.mark.parametrize(
        "dns_calls, process_map, routing, expected_return",
        [
            ([], {}, "", {}),
            ([{"answers": []}], {}, "", {}),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {},
                "",
                {
                    "answer": [{
                        "domain": "request",
                        "guid": None,
                        "process_id": None,
                        "process_name": None,
                        "time": None,
                        "type": "dns_type",
                    }]
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {},
                "INetSim",
                {
                    "answer": [{
                        "domain": "request",
                        "guid": None,
                        "process_id": None,
                        "process_name": None,
                        "time": None,
                        "type": "dns_type",
                    }]
                },
            ),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "PTR"}], {}, "INetSim", {}),
            (
                [{"answers": [{"data": "answer"}], "request": "10.10.10.10.in-addr.arpa", "type": "PTR"}],
                {},
                "Internet",
                {"10.10.10.10": [{"domain": "answer"}]},
            ),
            (
                [
                    {"answers": [{"data": "10.10.10.10"}], "request": "answer", "type": "A"},
                    {"answers": [{"data": "answer"}], "request": "10.10.10.10.in-addr.arpa", "type": "PTR"},
                ],
                {},
                "Internet",
                {
                    "10.10.10.10": [{
                        "domain": "answer",
                        "guid": None,
                        "process_id": None,
                        "process_name": None,
                        "time": None,
                        "type": "A",
                    }]
                },
            ),
            ([{"answers": [{"data": "answer"}], "request": "ya:ba:da:ba:do:oo.ip6.arpa", "type": "PTR"}], {}, "Internet", {}),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"network_calls": [{"blah": {"hostname": "blah"}}]}},
                "",
                {
                    "answer": [{
                        "domain": "request",
                        "guid": None,
                        "process_id": None,
                        "process_name": None,
                        "time": None,
                        "type": "dns_type",
                    }]
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"blah": {"hostname": "request"}}]}},
                "",
                {
                    "answer": [{
                        "domain": "request",
                        "guid": None,
                        "process_id": None,
                        "process_name": None,
                        "time": None,
                        "type": "dns_type",
                    }]
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"getaddrinfo": {"hostname": "request"}}]}},
                "",
                {
                    "answer": [{
                        "domain": "request",
                        "process_id": 1,
                        "process_name": "blah",
                        "guid": None,
                        "time": None,
                        "type": "dns_type",
                    }]
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"InternetConnectW": {"hostname": "request"}}]}},
                "",
                {
                    "answer": [{
                        "domain": "request",
                        "process_id": 1,
                        "process_name": "blah",
                        "guid": None,
                        "time": None,
                        "type": "dns_type",
                    }]
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"InternetConnectA": {"hostname": "request"}}]}},
                "",
                {
                    "answer": [{
                        "domain": "request",
                        "process_id": 1,
                        "process_name": "blah",
                        "guid": None,
                        "time": None,
                        "type": "dns_type",
                    }]
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"GetAddrInfoW": {"hostname": "request"}}]}},
                "",
                {
                    "answer": [{
                        "domain": "request",
                        "process_id": 1,
                        "process_name": "blah",
                        "guid": None,
                        "time": None,
                        "type": "dns_type",
                    }]
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"gethostbyname": {"hostname": "request"}}]}},
                "",
                {
                    "answer": [{
                        "domain": "request",
                        "process_id": 1,
                        "process_name": "blah",
                        "guid": None,
                        "time": None,
                        "type": "dns_type",
                    }]
                },
            ),
            ([{"answers": []}], {1: {"name": "blah", "network_calls": [{"gethostbyname": {"hostname": "request"}}]}}, "", {}),
            (
                [{"answers": [{"data": "1.1.1.1"}], "request": "request", "type": "dns_type"}],
                {1: {"network_calls": [{"blah": {"hostname": "blah"}}]}},
                "",
                {},
            ),
            (
                [{"answers": [], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"getaddrinfo": {"hostname": "request"}}]}},
                "",
                {
                    '0': [{
                        'domain': 'request',
                        'guid': None,
                        'process_id': 1,
                        'process_name': 'blah',
                        'time': None,
                        'type': 'dns_type'
                    }]
                },
            ),
            # DNS call with first_seen field populated as float
            (
                [{"answers": [], "request": "request", "type": "dns_type", "first_seen": 123.123}],
                {1: {"name": "blah", "network_calls": [{"getaddrinfo": {"hostname": "request"}}]}},
                "",
                {
                    '0': [{
                        'domain': 'request',
                        'guid': None,
                        'process_id': 1,
                        'process_name': 'blah',
                        'time': "1970-01-01 00:02:03.123",
                        'type': 'dns_type'
                    }]
                },
            ),
            # DNS call with first_seen field populated as str
            (
                [{"answers": [], "request": "request", "type": "dns_type", "first_seen": "2023-09-05"}],
                {1: {"name": "blah", "network_calls": [{"getaddrinfo": {"hostname": "request"}}]}},
                "",
                {
                    '0': [{
                        'domain': 'request',
                        'guid': None,
                        'process_id': 1,
                        'process_name': 'blah',
                        'time': "2023-09-05",
                        'type': 'dns_type'
                    }]
                },
            ),
        ],
    )
    def test_get_dns_map(dns_calls, process_map, routing, expected_return):
        dns_servers = ["1.1.1.1"]
        assert _get_dns_map(dns_calls, process_map, routing, dns_servers) == expected_return

    @staticmethod
    @pytest.mark.parametrize(
        "resolved_ips, flows, expected_return",
        [
            ({}, {}, ([], "")),
            ({}, {"udp": []}, ([], "")),
            (
                {},
                {"udp": [{"dst": "blah", "src": "1.1.1.1", "time": "blah", "dport": 123}]},
                (
                    [
                        {
                            "dest_ip": "blah",
                            "dest_port": 123,
                            "domain": None,
                            "guid": None,
                            "image": None,
                            "pid": None,
                            "protocol": "udp",
                            "src_ip": "1.1.1.1",
                            "src_port": None,
                            "timestamp": "blah",
                        }
                    ],
                    "",
                ),
            ),
            (
                {},
                {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": 123}]},
                (
                    [
                        {
                            "dest_ip": "blah",
                            "dest_port": 123,
                            "domain": None,
                            "guid": None,
                            "image": None,
                            "pid": None,
                            "protocol": "udp",
                            "src_ip": "blah",
                            "src_port": "blah",
                            "timestamp": "blah",
                        }
                    ],
                    "",
                ),
            ),
            (
                {"blah": [{"domain": "blah"}]},
                {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": 123}]},
                (
                    [
                        {
                            "dest_ip": "blah",
                            "dest_port": 123,
                            "domain": "blah",
                            "guid": None,
                            "image": None,
                            "pid": None,
                            "protocol": "udp",
                            "src_ip": "blah",
                            "src_port": "blah",
                            "timestamp": "blah",
                        }
                    ],
                    "",
                ),
            ),
            (
                {"blah": [{"domain": "blah", "process_name": "blah", "process_id": "blah"}]},
                {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": 123}]},
                (
                    [
                        {
                            "dest_ip": "blah",
                            "dest_port": 123,
                            "domain": "blah",
                            "guid": None,
                            "image": "blah",
                            "pid": "blah",
                            "protocol": "udp",
                            "src_ip": "blah",
                            "src_port": "blah",
                            "timestamp": "blah",
                        }
                    ],
                    "",
                ),
            ),
            ({}, {}, ([], "flag")),
        ],
    )
    def test_get_low_level_flows(resolved_ips, flows, expected_return):
        expected_network_flows_table, expected_netflows_sec_body = expected_return
        correct_netflows_sec = ResultTableSection(title_text="TCP/UDP Network Traffic")
        if expected_netflows_sec_body == "flag":
            too_many_unique_ips_sec = ResultSection(title_text="Too Many Unique IPs")
            too_many_unique_ips_sec.set_body(
                f"The number of TCP calls displayed has been capped "
                f"at 100. The full results can be found "
                f"in the supplementary PCAP file included with the analysis."
            )
            correct_netflows_sec.add_subsection(too_many_unique_ips_sec)
            flows = {"udp": []}
            expected_network_flows_table = []
            for i in range(101):
                flows["udp"].append({"dst": "blah", "src": "1.1.1.1", "dport": f"blah{i}", "time": "blah"})
                expected_network_flows_table.append(
                    {
                        "protocol": "udp",
                        "domain": None,
                        "dest_ip": "blah",
                        "src_ip": "1.1.1.1",
                        "src_port": None,
                        "dest_port": f"blah{i}",
                        "timestamp": "blah",
                        "image": None,
                        "guid": None,
                        "pid": None,
                    }
                )
            expected_network_flows_table = expected_network_flows_table[:100]

        network_flows_table, netflows_sec = _get_low_level_flows(resolved_ips, flows)
        assert network_flows_table == expected_network_flows_table
        assert check_section_equality(netflows_sec, correct_netflows_sec)

    @staticmethod
    def test_massage_host_data():
        assert _massage_host_data("blah.blah") == "blah.blah"
        assert _massage_host_data("blah.blah:80") == "blah.blah"

    @staticmethod
    @pytest.mark.parametrize(
        "host, dns_servers, resolved_ips, http_call, expected_uri, expected_http_call",
        [
            # normal host, no dns servers, no resolved_ips, normal http_call
            ("blah.com", [], {}, {"uri": "/blah", "protocol": "http", "dst": "127.0.0.1"}, "http://blah.com/blah", {"uri": "/blah", "protocol": "http", "dst": "127.0.0.1"}),
            # host in path/uri, no dns servers, no resolved_ips, normal http_call
            ("blah.com", [], {}, {"uri": "blah.com/blah", "protocol": "http", "dst": "127.0.0.1"}, "http://blah.com/blah", {"uri": "blah.com/blah", "protocol": "http", "dst": "127.0.0.1"}),
            # http_call[dst] is in dns_servers, but no resolved_ips, normal http_call
            ("blah.com", ["127.0.0.1"], {}, {"uri": "blah.com/blah", "protocol": "http", "dst": "127.0.0.1"}, "http://blah.com/blah", {"uri": "blah.com/blah", "protocol": "http", "dst": "127.0.0.1"}),
            # http_call[dst] is in dns_servers, with resolved_ips, normal http_call
            ("blah.com", ["127.0.0.1"], {"1.1.1.1": [{"domain": "blah.com"}], "1": [{"domain": "blah"}]}, {"uri": "blah.com/blah", "protocol": "http", "dst": "127.0.0.1"}, "http://blah.com/blah", {"uri": "blah.com/blah", "protocol": "http", "dst": "1.1.1.1"}),
        ]
    )
    def test_massage_http_ex_data(host, dns_servers, resolved_ips, http_call, expected_uri, expected_http_call):
        assert _massage_http_ex_data(host, dns_servers, resolved_ips, http_call) == (expected_uri, expected_http_call)

    @staticmethod
    @pytest.mark.parametrize(
        "protocol, host, dns_servers, resolved_ips, http_call, expected_request, expected_port, expected_uri, expected_http_call",
        [
            # non-ex protocol
            # normal host, no dns servers, no resolved_ips, normal http_call
            ("http", "blah.com", [], {}, {"data": "GET blah.com", "uri": "http://blah.com/blah", "port": 123}, "GET blah.com", 123, "http://blah.com/blah", {"data": "GET blah.com", "uri": "http://blah.com/blah", "port": 123}),
            # ex protocol
            # normal host, no dns servers, no resolved_ips, normal http_call
            ("http_ex", "blah.com", [], {}, {"request": "GET blah.com", "dport": 123, "uri": "/blah", "protocol": "http", "dst": "127.0.0.1"}, "GET blah.com", 123, "http://blah.com/blah", {"request": "GET blah.com", "dport": 123, "uri": "/blah", "protocol": "http", "dst": "127.0.0.1"}),
        ]
    )
    def test_get_important_fields_from_http_call(protocol, host, dns_servers, resolved_ips, http_call, expected_request, expected_port, expected_uri, expected_http_call):
        assert _get_important_fields_from_http_call(protocol, host, dns_servers, resolved_ips, http_call) == (expected_request, expected_port, expected_uri, expected_http_call)

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
        ]
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
            ({"req": {"path": "blah/network/blahblah"}, "resp": {"path": "blah/network/blahblah"}}, "network/blahblah", "network/blahblah"),
        ]
    )
    def test_massage_body_paths(http_call, expected_request_body_path, expected_response_body_path):
        assert _massage_body_paths(http_call) == (expected_request_body_path, expected_response_body_path)

    @staticmethod
    @pytest.mark.parametrize(
        "http_call, dns_servers, host, expected_destination_ip",
        [
            # http_call has no dst and NetworkDNS object does not exist in ontres, no dns_servers
            ({}, [], "blah.com", None),
            # http_call has dst and dst in dns_servers and NetworkDNS object does not exist in ontres
            ({"dst": "127.0.0.1"}, ["127.0.0.1"], "blah.com", None),
            # http_call has dst and dst not in dns_servers and NetworkDNS object does not exist in ontres
            ({"dst": "127.0.0.1"}, [], "blah.com", "127.0.0.1"),
            # http_call has no dst and NetworkDNS object does exists in ontres
            ({}, [], "blah.ca", "1.1.1.1"),
        ]
    )
    def test_get_destination_ip(http_call, dns_servers, host, expected_destination_ip):
        ontres = OntologyResults(service_name="blah")
        dns = NetworkDNS("blah.ca", ["1.1.1.1"], "A")
        ontres.add_network_dns(dns)

        assert _get_destination_ip(http_call, dns_servers, host, ontres) == expected_destination_ip

    @staticmethod
    @pytest.mark.parametrize(
        "uri, http_call, request_headers, response_headers, request_body_path, response_body_path, expected_nh",
        [
            # No body paths
            ("http://blah.com/blah", {"method": "GET"}, {}, {}, None, None, {
                'request_body': None,
                'request_headers': {},
                'request_method': 'GET',
                'request_uri': 'http://blah.com/blah',
                'response_body': None,
                'response_headers': {},
                'response_status_code': None
            }),
            # Body paths
            ("http://blah.com/blah", {"method": "GET"}, {}, {}, "blah", "blah", {
                'request_body': None,
                'request_headers': {},
                'request_method': 'GET',
                'request_uri': 'http://blah.com/blah',
                'response_body': None,
                'response_headers': {},
                'response_status_code': None
            }),
        ]
    )
    def test_create_network_http(uri, http_call, request_headers, response_headers, request_body_path, response_body_path, expected_nh):
        ontres = OntologyResults(service_name="blah")
        assert _create_network_http(uri, http_call, request_headers, response_headers, request_body_path, response_body_path, ontres).as_primitives() == expected_nh


    @staticmethod
    @pytest.mark.parametrize(
        "destination_ip, destination_port, expected_nc",
        [
            # No network connection with details
            ("127.0.0.1", 123, None),
            # Network connection with details
            ("1.1.1.1", 123,
                {
                    'connection_type': None,
                    'destination_ip': '1.1.1.1',
                    'destination_port': 123,
                    'direction': 'outbound',
                    'dns_details': None,
                    'http_details': None,
                    'objectid': {'guid': None,
                                    'ontology_id': 'blah',
                                    'processtree': None,
                                    'service_name': 'CAPE',
                                    'session': None,
                                    'tag': 'blah',
                                    'time_observed': None,
                                    'treeid': None},
                    'process': None,
                    'source_ip': None,
                    'source_port': None,
                    'transport_layer_protocol': 'tcp',
                }
            ),
        ]
    )
    def test_get_network_connection_by_details(destination_ip, destination_port, expected_nc):
        ontres = OntologyResults(service_name="blah")
        nc = NetworkConnection(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), destination_ip="1.1.1.1", destination_port=123, transport_layer_protocol="tcp", direction="outbound")
        ontres.add_network_connection(nc)

        if destination_ip == "127.0.0.1":
            assert _get_network_connection_by_details(destination_ip, destination_port, ontres) == expected_nc
        elif destination_ip == "1.1.1.1":
            assert _get_network_connection_by_details(destination_ip, destination_port, ontres).as_primitives() == expected_nc

    @staticmethod
    @pytest.mark.parametrize(
        "http_call, destination_ip, destination_port, expected_nc",
        [
            # The bare minimum
            ({}, "127.0.0.1", 123, {
                'connection_type': 'http',
                'destination_ip': '127.0.0.1',
                'destination_port': 123,
                'direction': 'outbound',
                'dns_details': None,
                'http_details': {'request_body': None,
                                'request_headers': {},
                                'request_method': 'GET',
                                'request_uri': 'http://blah.com/blah',
                                'response_body': None,
                                'response_headers': {},
                                'response_status_code': None},
                'objectid': {'guid': None,
                            'ontology_id': 'network_6aD7OJbTRyh0nd8yeckFeS',
                            'processtree': None,
                            'service_name': 'blah',
                            'session': None,
                            'tag': '127.0.0.1:123',
                            'time_observed': None,
                            'treeid': None},
                'process': None,
                'source_ip': None,
                'source_port': None,
                'transport_layer_protocol': 'tcp',
            }),
            # The bare minimum with source_ip and source_port
            ({"src": "1.1.1.1", "sport": 321}, "127.0.0.1", 123, {
                'connection_type': 'http',
                'destination_ip': '127.0.0.1',
                'destination_port': 123,
                'direction': 'outbound',
                'dns_details': None,
                'http_details': {'request_body': None,
                                'request_headers': {},
                                'request_method': 'GET',
                                'request_uri': 'http://blah.com/blah',
                                'response_body': None,
                                'response_headers': {},
                                'response_status_code': None},
                'objectid': {'guid': None,
                            'ontology_id': 'network_4bcLl8bsAoN7PGatc9qwFC',
                            'processtree': None,
                            'service_name': 'blah',
                            'session': None,
                            'tag': '127.0.0.1:123',
                            'time_observed': None,
                            'treeid': None},
                'process': None,
                'source_ip': "1.1.1.1",
                'source_port': 321,
                'transport_layer_protocol': 'tcp',
            }),

        ]
    )
    def test_create_network_connection_for_http_call(http_call, destination_ip, destination_port, expected_nc):
        ontres = OntologyResults(service_name="blah")
        sandbox = ontres.create_sandbox(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), sandbox_name="CAPE")
        ontres.add_sandbox(sandbox)
        nh = NetworkHTTP("http://blah.com/blah", "GET")
        assert _create_network_connection_for_http_call(http_call, destination_ip, destination_port, nh, ontres).as_primitives() == expected_nc

    @staticmethod
    @pytest.mark.parametrize(
        "uri, http_call, request_headers, response_headers, request_body_path, response_body_path, port, destination_ip, expected_nc, expected_nh",
        [
            # NetworkConnection does not exist
            ("http://blah.com/blah", {"method": "GET"}, {}, {}, None, None, 123, "127.0.0.1", {
                'connection_type': 'http',
                'destination_ip': '127.0.0.1',
                'destination_port': 123,
                'direction': 'outbound',
                'dns_details': None,
                'http_details': {'request_body': None,
                                 'request_headers': {},
                                 'request_method': 'GET',
                                 'request_uri': 'http://blah.com/blah',
                                 'response_body': None,
                                 'response_headers': {},
                                 'response_status_code': None},
                'objectid': {'guid': None,
                             'ontology_id': 'network_6aD7OJbTRyh0nd8yeckFeS',
                             'processtree': None,
                             'service_name': 'blah',
                             'session': None,
                             'tag': '127.0.0.1:123',
                             'time_observed': None,
                             'treeid': None},
                'process': None,
                'source_ip': None,
                'source_port': None,
                'transport_layer_protocol': 'tcp'
            }, {
                'request_body': None,
                'request_headers': {},
                'request_method': 'GET',
                'request_uri': 'http://blah.com/blah',
                'response_body': None,
                'response_headers': {},
                'response_status_code': None
            }),
            # NetworkConnection does exist
            ("http://blah.com/blah", {"method": "GET"}, {}, {}, "blah", "blah", 123, "1.1.1.1", {
                'connection_type': 'http',
                'destination_ip': '1.1.1.1',
                'destination_port': 123,
                'direction': 'outbound',
                'dns_details': None,
                'http_details': {'request_body': None,
                                 'request_headers': {},
                                 'request_method': 'GET',
                                 'request_uri': 'http://blah.com/blah',
                                 'response_body': None,
                                 'response_headers': {},
                                 'response_status_code': None},
                'objectid': {'guid': None,
                             'ontology_id': 'blah',
                             'processtree': None,
                             'service_name': 'CAPE',
                             'session': None,
                             'tag': 'blah',
                             'time_observed': None,
                             'treeid': None},
                'process': None,
                'source_ip': None,
                'source_port': None,
                'transport_layer_protocol': 'tcp'
            }, {
                'request_body': None,
                'request_headers': {},
                'request_method': 'GET',
                'request_uri': 'http://blah.com/blah',
                'response_body': None,
                'response_headers': {},
                'response_status_code': None
            }),
        ]
    )
    def test_setup_network_connection_with_network_http(uri, http_call, request_headers, response_headers, request_body_path, response_body_path, port, destination_ip, expected_nc, expected_nh):
        ontres = OntologyResults(service_name="blah")

        sandbox = ontres.create_sandbox(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), sandbox_name="CAPE")
        ontres.add_sandbox(sandbox)

        nc = NetworkConnection(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), destination_ip="1.1.1.1", destination_port=123, transport_layer_protocol="tcp", direction="outbound")
        ontres.add_network_connection(nc)

        actual_nc, actual_nh = _setup_network_connection_with_network_http(uri, http_call, request_headers, response_headers, request_body_path, response_body_path, port, destination_ip, ontres)

        assert actual_nc.as_primitives() == expected_nc
        assert actual_nh.as_primitives() == expected_nh

    @staticmethod
    @pytest.mark.parametrize(
        "process_map, request_data, uri, expected_nc_process",
        [
            # Nothing to do
            ({}, "", "", None),
            # Process map with network call of service = 3
            ({1: {"network_calls": [{"send": {"service": 3}}]}}, "", "", None),
            # Process map with network call of service = 3 and servername in uri
            ({1: {"network_calls": [{"send": {"service": "3", "servername": "blah.com"}}]}}, "", "http://blah.com/blah", {
                'command_line': None,
                'end_time': None,
                'image': 'blah',
                'image_hash': None,
                'integrity_level': None,
                'objectid': {'guid': None,
                             'ontology_id': 'blah',
                             'processtree': None,
                             'service_name': 'CAPE',
                             'session': None,
                             'tag': 'blah',
                             'time_observed': '1970-01-01 00:00:01',
                             'treeid': None},
                'original_file_name': None,
                'pcommand_line': None,
                'pid': 1,
                'pimage': None,
                'pobjectid': None,
                'ppid': None,
                'start_time': '1970-01-01 00:00:01',
            }),
            # Process map with network call of buffer = request_data, InternetConnectW
            ({1: {"network_calls": [{"InternetConnectW": {"buffer": "check me"}}]}}, "check me", "", {
                'command_line': None,
                'end_time': None,
                'image': 'blah',
                'image_hash': None,
                'integrity_level': None,
                'objectid': {'guid': None,
                             'ontology_id': 'blah',
                             'processtree': None,
                             'service_name': 'CAPE',
                             'session': None,
                             'tag': 'blah',
                             'time_observed': '1970-01-01 00:00:01',
                             'treeid': None},
                'original_file_name': None,
                'pcommand_line': None,
                'pid': 1,
                'pimage': None,
                'pobjectid': None,
                'ppid': None,
                'start_time': '1970-01-01 00:00:01',
            }),
            # Process map with network call of equal uris despite discrepancies
            ({1: {"network_calls": [{"InternetCrackUrlA": {"url": "https://blah.com/"}}]}}, "", "http://blah.com", {
                'command_line': None,
                'end_time': None,
                'image': 'blah',
                'image_hash': None,
                'integrity_level': None,
                'objectid': {'guid': None,
                             'ontology_id': 'blah',
                             'processtree': None,
                             'service_name': 'CAPE',
                             'session': None,
                             'tag': 'blah',
                             'time_observed': '1970-01-01 00:00:01',
                             'treeid': None},
                'original_file_name': None,
                'pcommand_line': None,
                'pid': 1,
                'pimage': None,
                'pobjectid': None,
                'ppid': None,
                'start_time': '1970-01-01 00:00:01',
            }),
            # Process map with network call of service = "3" as a string and servername in uri
            ({1: {"network_calls": [{"InternetConnectA": {"service": "3", "servername": "blah.com"}}]}}, "", "http://blah.com/blah", {
                'command_line': None,
                'end_time': None,
                'image': 'blah',
                'image_hash': None,
                'integrity_level': None,
                'objectid': {'guid': None,
                             'ontology_id': 'blah',
                             'processtree': None,
                             'service_name': 'CAPE',
                             'session': None,
                             'tag': 'blah',
                             'time_observed': '1970-01-01 00:00:01',
                             'treeid': None},
                'original_file_name': None,
                'pcommand_line': None,
                'pid': 1,
                'pimage': None,
                'pobjectid': None,
                'ppid': None,
                'start_time': '1970-01-01 00:00:01',
            }),
            # Process map with network call with servername in uri, with port
            ({1: {"network_calls": [{"InternetConnectA": {"service": "3", "servername": "blah.com"}}]}}, "", "http://blah.com:8080/blah", {
                'command_line': None,
                'end_time': None,
                'image': 'blah',
                'image_hash': None,
                'integrity_level': None,
                'objectid': {'guid': None,
                             'ontology_id': 'blah',
                             'processtree': None,
                             'service_name': 'CAPE',
                             'session': None,
                             'tag': 'blah',
                             'time_observed': '1970-01-01 00:00:01',
                             'treeid': None},
                'original_file_name': None,
                'pcommand_line': None,
                'pid': 1,
                'pimage': None,
                'pobjectid': None,
                'ppid': None,
                'start_time': '1970-01-01 00:00:01',
            }),
            # Process map with network call of buffer = request_data, WSASend
            ({1: {"network_calls": [{"WSASend": {"buffer": "check me"}}]}}, "check me", "", {
                'command_line': None,
                'end_time': None,
                'image': 'blah',
                'image_hash': None,
                'integrity_level': None,
                'objectid': {'guid': None,
                             'ontology_id': 'blah',
                             'processtree': None,
                             'service_name': 'CAPE',
                             'session': None,
                             'tag': 'blah',
                             'time_observed': '1970-01-01 00:00:01',
                             'treeid': None},
                'original_file_name': None,
                'pcommand_line': None,
                'pid': 1,
                'pimage': None,
                'pobjectid': None,
                'ppid': None,
                'start_time': '1970-01-01 00:00:01',
            }),
        ]
    )
    def test_link_process_to_http_call(process_map, request_data, uri, expected_nc_process):
        ontres = OntologyResults(service_name="blah")

        nc = NetworkConnection(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), destination_ip="1.1.1.1", destination_port=123, transport_layer_protocol="tcp", direction="outbound", http_details=NetworkHTTP(request_uri="http://blah.com", request_method="GET"), connection_type="http")
        ontres.add_network_connection(nc)

        p = Process(objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE"), image="blah", start_time="1970-01-01 00:00:01", pid=1)
        ontres.add_process(p)

        _link_process_to_http_call(process_map, request_data, uri, nc, ontres)

        if expected_nc_process is None:
            assert nc.process is None
        else:
            assert nc.process.as_primitives() == expected_nc_process


    @staticmethod
    @pytest.mark.parametrize(
        "process_map, http_level_flows, expected_req_table",
        [
            ({}, {}, []),
            ({}, {"http": [], "https": [], "http_ex": [], "https_ex": []}, []),
            (
                {},
                {
                    "http": [
                        {"host": "blah", "path": "blah", "data": "blah", "port": 123, "uri": "http://blah", "method": "blah"}
                    ],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [],
                },
                [],
            ),
            (
                {},
                {
                    "http": [
                        {"host": "3.3.3.3", "path": "blah", "data": "blah", "port": 123, "uri": "http://blah.com", "method": "blah"}
                    ],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [],
                },
                [
                    {
                        "request_uri": "http://blah.com",
                        "request_headers": {},
                        "request_body": None,
                        "request_method": "blah",
                        "response_headers": {},
                        "response_status_code": None,
                        "response_body": None,
                        "request_body_path": None,
                        "response_body_path": None,
                    }
                ],
            ),
            (
                {},
                {
                    "http": [],
                    "https": [
                        {"host": "3.3.3.3", "path": "blah", "data": "blah", "port": 123, "uri": "http://blah.com", "method": "blah"}
                    ],
                    "http_ex": [],
                    "https_ex": [],
                },
                [
                    {
                        "request_uri": "http://blah.com",
                        "request_headers": {},
                        "request_body": None,
                        "request_method": "blah",
                        "response_headers": {},
                        "response_status_code": None,
                        "response_body": None,
                        "request_body_path": None,
                        "response_body_path": None,
                    }
                ],
            ),
            (
                {},
                {
                    "http": [],
                    "https": [],
                    "http_ex": [
                        {
                            "host": "blah",
                            "request": "blah",
                            "dst": "2.2.2.2",
                            "dport": 123,
                            "uri": "http://blah.com",
                            "protocol": "http",
                            "method": "blah",
                        }
                    ],
                    "https_ex": [],
                },
                [],
            ),
            (
                {},
                {
                    "http": [],
                    "https": [],
                    "http_ex": [
                        {
                            "host": "nope.com",
                            "request": "blah",
                            "dst": "2.2.2.2",
                            "dport": 123,
                            "uri": "/blah",
                            "protocol": "http",
                            "method": "blah",
                        }
                    ],
                    "https_ex": [],
                },
                [
                    {
                        "request_uri": "http://nope.com/blah",
                        "request_headers": {},
                        "request_body": None,
                        "request_method": "blah",
                        "response_headers": {},
                        "response_status_code": None,
                        "response_body": None,
                        "request_body_path": None,
                        "response_body_path": None,
                    }
                ],
            ),
            (
                {},
                {
                    "http": [],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [
                        {
                            "host": "nope.com",
                            "request": "blah",
                            "dst": "2.2.2.2",
                            "dport": 123,
                            "uri": "/blah",
                            "protocol": "https",
                            "method": "blah",
                        }
                    ],
                },
                [
                    {
                        "request_uri": "https://nope.com/blah",
                        "request_headers": {},
                        "request_body": None,
                        "request_method": "blah",
                        "response_headers": {},
                        "response_status_code": None,
                        "response_body": None,
                        "request_body_path": None,
                        "response_body_path": None,
                    }
                ],
            ),
            (
                {},
                {
                    "http": [
                        {"host": "192.168.0.1", "path": "blah", "data": "blah", "port": 123, "uri": "blah", "method": "blah"}
                    ],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [],
                },
                [],
            ),
            (
                {},
                {
                    "http": [
                        {
                            "host": "something.adobe.com",
                            "path": "blah",
                            "data": "blah",
                            "port": 123,
                            "uri": "blah",
                            "method": "blah",
                        }
                    ],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [],
                },
                [],
            ),
            (
                {},
                {
                    "http": [
                        {
                            "host": "blah",
                            "path": "blah",
                            "data": "blah",
                            "port": 123,
                            "uri": "http://localhost/blah",
                            "method": "blah",
                        }
                    ],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [],
                },
                [],
            ),
            (
                {},
                {
                    "http": [
                        {
                            "host": "3.3.3.3",
                            "path": "blah",
                            "data": "blah",
                            "port": 123,
                            "uri": "http://blah.com",
                            "method": "blah",
                        },
                        {
                            "host": "3.3.3.3",
                            "path": "blah",
                            "data": "blah",
                            "port": 123,
                            "uri": "http://blah.com",
                            "method": "blah",
                        },
                    ],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [],
                },
                [
                    {
                        "request_uri": "http://blah.com",
                        "request_headers": {},
                        "request_body": None,
                        "request_method": "blah",
                        "response_headers": {},
                        "response_status_code": None,
                        "response_body": None,
                        "request_body_path": None,
                        "response_body_path": None,
                    }
                ],
            ),
            (
                {1: {"network_calls": [{"send": {"service": 3}}], "name": "blah"}},
                {
                    "http": [
                        {"host": "3.3.3.3", "path": "blah", "data": "blah", "port": 123, "uri": "http://blah.com", "method": "blah"}
                    ],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [],
                },
                [
                    {
                        "request_uri": "http://blah.com",
                        "request_headers": {},
                        "request_body": None,
                        "request_method": "blah",
                        "response_headers": {},
                        "response_status_code": None,
                        "response_body": None,
                        "request_body_path": None,
                        "response_body_path": None,
                    }
                ],
            ),
            (
                {1: {"network_calls": [{"InternetConnectW": {"buffer": "check me"}}], "name": "blah"}},
                {
                    "http": [
                        {
                            "host": "3.3.3.3",
                            "path": "blah",
                            "data": "check me",
                            "port": 123,
                            "uri": "http://blah.com",
                            "method": "blah",
                        }
                    ],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [],
                },
                [
                    {
                        "request_uri": "http://blah.com",
                        "request_headers": {},
                        "request_body": None,
                        "request_method": "blah",
                        "response_headers": {},
                        "response_status_code": None,
                        "response_body": None,
                        "request_body_path": None,
                        "response_body_path": None,
                    }
                ],
            ),
            (
                {1: {"network_calls": [{"InternetConnectA": {"buffer": "check me"}}], "name": "blah"}},
                {
                    "http": [
                        {
                            "host": "3.3.3.3",
                            "path": "blah",
                            "data": "check me",
                            "port": 123,
                            "uri": "http://blah.com",
                            "method": "blah",
                        }
                    ],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [],
                },
                [
                    {
                        "request_uri": "http://blah.com",
                        "request_headers": {},
                        "request_body": None,
                        "request_method": "blah",
                        "response_headers": {},
                        "response_status_code": None,
                        "response_body": None,
                        "request_body_path": None,
                        "response_body_path": None,
                    }
                ],
            ),
            (
                {1: {"network_calls": [{"URLDownloadToFileW": {"url": "http://bad.evil.com"}}], "name": "blah"}},
                {
                    "http": [
                        {"host": "3.3.3.3", "path": "blah", "data": "check me", "port": 123, "uri": "http://bad.evil.com", "method": "blah"}
                    ],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [],
                },
                [
                    {
                        "request_uri": "http://bad.evil.com",
                        "request_headers": {},
                        "request_body": None,
                        "request_method": "blah",
                        "response_headers": {},
                        "response_status_code": None,
                        "response_body": None,
                        "request_body_path": None,
                        "response_body_path": None,
                    }
                ],
            ),
            (
                {},
                {
                    "http": [],
                    "https": [],
                    "http_ex": [],
                    "https_ex": [
                        {
                            "host": "nope.com",
                            "req": {"path": "/blahblah/network/blahblah"},
                            "resp": {"path": "blahblah/network/blahblah"},
                            "dport": 123,
                            "uri": "/blah",
                            "protocol": "https",
                            "method": "blah",
                            "sport": 123,
                            "dst": "blah",
                            "src": "blah",
                            "response": "blah",
                            "request": "blah",
                        }
                    ],
                },
                [
                    {
                        "request_uri": "https://nope.com/blah",
                        "request_headers": {},
                        "request_body": None,
                        "request_method": "blah",
                        "response_headers": {},
                        "response_status_code": None,
                        "response_body": None,
                        "request_body_path": "network/blahblah",
                        "response_body_path": "network/blahblah",
                    }
                ],
            ),
        ],
    )
    def test_process_http_calls(process_map, http_level_flows, expected_req_table, mocker):
        default_so = OntologyResults(service_name="CAPE")
        mocker.patch.object(default_so, "sandboxes", return_value="blah")
        safelist = {
            "regex": {
                "network.dynamic.ip": ["(?:127\.|10\.|192\.168|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.).*"],
                "network.dynamic.domain": [".*\.adobe\.com$"],
                "network.dynamic.uri": ["(?:ftp|http)s?://localhost(?:$|/.*)"],
            }
        }
        dns_servers = ["2.2.2.2"]
        resolved_ips = {"1.1.1.1": [{"domain": "nope.com"}]}
        _process_http_calls(http_level_flows, process_map, dns_servers, resolved_ips, safelist, default_so)
        actual_req_table = []
        for nh in default_so.get_network_http():
            nh_as_prim = nh.__dict__
            actual_req_table.append(nh_as_prim)
        assert expected_req_table == actual_req_table

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
    def test_process_non_http_traffic_over_http():
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
        correct_result_section.set_body(dumps(network_flows), BODY_FORMAT.TABLE)
        _process_non_http_traffic_over_http(test_parent_section, network_flows)
        assert check_section_equality(test_parent_section.subsections[0], correct_result_section)

    @staticmethod
    def test_process_all_events():
        default_so = OntologyResults()
        al_result = ResultSection("blah")
        p = default_so.create_process(
            pid=1,
            ppid=1,
            guid="{12345678-1234-5678-1234-567812345679}",
            command_line="blah blah.com",
            image="blah",
            start_time="1970-01-01 00:00:01.000",
            pguid="{12345678-1234-5678-1234-567812345679}",
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE")
        )
        default_so.add_process(p)

        dns = default_so.create_network_dns(domain="blah", resolved_ips=["1.1.1.1"], lookup_type="A")
        default_so.add_network_dns(dns)

        nc_dns = default_so.create_network_connection(
            source_port=1,
            destination_ip="1.1.1.1",
            source_ip="2.2.2.2",
            destination_port=1,
            transport_layer_protocol="udp",
            direction="outbound",
            process=p,
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE", time_observed="1970-01-01 00:00:02.000"),
            dns_details=dns,
            connection_type=NetworkConnection.DNS,
        )
        default_so.add_network_connection(nc_dns)

        http = default_so.create_network_http(request_uri="blah", request_method="GET")
        default_so.add_network_http(http)

        nc_http = default_so.create_network_connection(
            source_port=1,
            destination_ip="1.1.1.1",
            source_ip="2.2.2.2",
            destination_port=80,
            transport_layer_protocol="tcp",
            direction="outbound",
            process=p,
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE", time_observed="1970-01-01 00:00:03.000"),
            http_details=http,
            connection_type=NetworkConnection.HTTP,
        )
        default_so.add_network_connection(nc_http)

        nc_tcp = default_so.create_network_connection(
            source_port=1,
            destination_ip="1.1.1.1",
            source_ip="2.2.2.2",
            destination_port=123,
            transport_layer_protocol="tcp",
            direction="outbound",
            process=p,
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE", time_observed="1970-01-01 00:00:04.000"),
        )
        default_so.add_network_connection(nc_tcp)

        correct_result_section = ResultTableSection(title_text="Event Log")
        correct_result_section.add_tag("dynamic.process.command_line", "blah blah.com")
        correct_result_section.add_tag("dynamic.process.file_name", "blah")

        correct_result_section.add_row(
            TableRow(
                **{
                    "time_observed": "1970-01-01 00:00:01.000",
                    "process_name": "blah (1)",
                    "details": {"command_line": "blah blah.com"},
                }
            )
        )
        correct_result_section.add_row(
            TableRow(
                **{
                    "time_observed": "1970-01-01 00:00:02.000",
                    "process_name": "blah (1)",
                    "details": {"protocol": "dns", "domain": "blah", "lookup_type": "A", "resolved_ips": ["1.1.1.1"]},
                }
            )
        )
        correct_result_section.add_row(
            TableRow(
                **{
                    "time_observed": "1970-01-01 00:00:03.000",
                    "process_name": "blah (1)",
                    "details": {"protocol": "http", "method": "GET", "uri": "blah", "status_code": None},
                }
            )
        )
        correct_result_section.add_row(
            TableRow(
                **{
                    "time_observed": "1970-01-01 00:00:04.000",
                    "process_name": "blah (1)",
                    "details": {"protocol": "tcp", "domain": "blah", "dest_ip": "1.1.1.1", "dest_port": 123},
                }
            )
        )

        correct_ioc_table = ResultTableSection("Event Log IOCs")
        correct_ioc_table.add_tag("network.dynamic.domain", "blah.com")
        table_data = [{"ioc_type": "domain", "ioc": "blah.com"}]
        for item in table_data:
            correct_ioc_table.add_row(TableRow(**item))
        correct_result_section.add_subsection(correct_ioc_table)
        custom_tree_id_safelist = list()
        process_all_events(al_result, default_so, custom_tree_id_safelist)
        assert check_section_equality(al_result.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "curtain, process_map",
        [
            ({}, {0: {"blah": "blah"}}),
            (
                {"1": {"events": [{"command": {"original": "blah", "altered": "blah"}}], "behaviors": ["blah"]}},
                {0: {"blah": "blah"}},
            ),
            (
                {"1": {"events": [{"command": {"original": "blah", "altered": "No alteration of event"}}], "behaviors": ["blah"]}},
                {0: {"blah": "blah"}},
            ),
            (
                {"1": {"events": [{"command": {"original": "blah", "altered": "No alteration of event"}}], "behaviors": ["blah"]}},
                {1: {"name": "blah.exe"}},
            ),
        ],
    )
    def test_process_curtain(curtain, process_map):
        al_result = ResultSection("blah")

        curtain_body = []
        correct_result_section = ResultSection(title_text="PowerShell Activity")
        for pid in curtain.keys():
            process_name = process_map[int(pid)]["name"] if process_map.get(int(pid)) else "powershell.exe"
            for event in curtain[pid]["events"]:
                for command in event.keys():
                    curtain_item = {"process_name": process_name, "original": event[command]["original"], "reformatted": None}
                    altered = event[command]["altered"]
                    if altered != "No alteration of event.":
                        curtain_item["reformatted"] = altered
                    curtain_body.append(curtain_item)
            for behaviour in curtain[pid]["behaviors"]:
                correct_result_section.add_tag("file.behavior", behaviour)
        correct_result_section.set_body(json.dumps(curtain_body), BODY_FORMAT.TABLE)

        process_curtain(curtain, al_result, process_map)
        if len(al_result.subsections) > 0:
            assert check_section_equality(al_result.subsections[0], correct_result_section)
        else:
            assert al_result.subsections == []

    @staticmethod
    def test_process_hollowshunter():
        hollowshunter = {}
        process_map = {123: {"name": "blah"}}
        al_result = ResultSection("blah")

        process_hollowshunter(hollowshunter, al_result, process_map)
        assert al_result.subsections == []

        hollowshunter = {
            "123": {"scanned": {"modified": {"implanted_pe": 1}}, "scans": [{"workingset_scan": {"has_pe": 1, "module": "400000"}}]}
        }
        hollowshunter_body = [{"Process": "blah (123)", "Indicator": "Implanted PE", "Description": "Modules found: ['400000']"}]
        correct_result_section = ResultTableSection("HollowsHunter Analysis")
        [correct_result_section.add_row(TableRow(**row)) for row in hollowshunter_body]

        process_hollowshunter(hollowshunter, al_result, process_map)
        assert check_section_equality(al_result.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "process_map, correct_buffer_body, correct_tags, correct_body",
        [
            ({0: {"decrypted_buffers": []}}, None, {}, []),
            ({0: {"decrypted_buffers": [{"blah": "blah"}]}}, None, {}, []),
            ({0: {"decrypted_buffers": [{"CryptDecrypt": {"buffer": "blah"}}]}}, '[{"Process": "None (0)", "Source": "Windows API", "Buffer": "blah"}]', {}, []),
            ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "blah"}}]}}, '[{"Process": "None (0)", "Source": "Windows API", "Buffer": "blah"}]', {}, []),
            (
                {0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "127.0.0.1"}}]}},
                '[{"Process": "None (0)", "Source": "Windows API", "Buffer": "127.0.0.1"}]',
                {"network.dynamic.ip": ["127.0.0.1"]},
                [{"ioc_type": "ip", "ioc": "127.0.0.1"}],
            ),
            (
                {0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "blah.ca"}}]}},
                '[{"Process": "None (0)", "Source": "Windows API", "Buffer": "blah.ca"}]',
                {"network.dynamic.domain": ["blah.ca"]},
                [{"ioc_type": "domain", "ioc": "blah.ca"}],
            ),
            (
                {0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "127.0.0.1:999"}}]}},
                '[{"Process": "None (0)", "Source": "Windows API", "Buffer": "127.0.0.1:999"}]',
                {"network.dynamic.ip": ["127.0.0.1"]},
                [{"ioc_type": "ip", "ioc": "127.0.0.1"}],
            ),
            (
                {1: {"name": "blah.exe", "network_calls": [{"send": {"buffer": "blah.com"}}]}, 2: {"name": "yaba.exe", "network_calls": [{"send": {"buffer": "blahblah.ca"}}]}},
                '[{"Process": "blah.exe (1)", "Source": "Network", "Buffer": "blah.com"}, {"Process": "yaba.exe (2)", "Source": "Network", "Buffer": "blahblah.ca"}]',
                {"network.dynamic.domain": ["blah.com", "blahblah.ca"]},
                [{"ioc_type": "domain", "ioc": "blah.com"}, {"ioc_type": "domain", "ioc": "blahblah.ca"}],
            ),
            (
                {1: {"name": "blah.exe", "network_calls": [{"send": {"buffer": "\\x12\\x23\\x34\\x45blah.com\\x45y\\x67o"}}]}},
                '[{"Process": "blah.exe (1)", "Source": "Network", "Buffer": "blah.com"}]',
                {"network.dynamic.domain": ["blah.com"]},
                [{"ioc_type": "domain", "ioc": "blah.com"}],
            ),
        ],
    )
    def test_process_buffers(process_map, correct_buffer_body, correct_tags, correct_body):
        safelist = {}
        parent_section = ResultSection("blah")
        process_buffers(process_map, safelist, parent_section)

        if correct_buffer_body is None:
            assert parent_section.subsections == []
        else:
            correct_result_section = ResultSection(title_text="Buffers", auto_collapse=True)
            correct_result_section.set_body(correct_buffer_body, BODY_FORMAT.TABLE)
            buffer_ioc_table = ResultTableSection("Buffer IOCs")

            for item in correct_body:
                buffer_ioc_table.add_row(TableRow(**item))
            if correct_body:
                correct_result_section.add_subsection(buffer_ioc_table)
                correct_result_section.set_heuristic(1006)
            for tag, values in correct_tags.items():
                for value in values:
                    buffer_ioc_table.add_tag(tag, value)
            assert check_section_equality(parent_section.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "input, output",
        [
            ({}, []),
            ({"payloads": []}, []),
            ({"payloads": [{"sha256": "blah", "pid": 1, "cape_yara": ["hi"]}, {"sha256": "blahblah", "pid": 2, "cape_yara": []}]}, [{"sha256": "blah", "pid": 1, "is_yara_hit": True}, {"sha256": "blahblah", "pid": 2, "is_yara_hit": False}]),
        ]
    )
    def test_process_cape(input, output):
        assert process_cape(input) == output

    @staticmethod
    @pytest.mark.parametrize(
        "processes, correct_process_map",
        [
            ([], {}),
            # We are no longer safelisting by dynamic.process.name tag values. So lsass should be included in the process map
            ([{"module_path": "C:\\windows\\System32\\lsass.exe", "calls": [], "process_id": 1}], {1: {'name': 'C:\\windows\\System32\\lsass.exe', 'network_calls': [], 'decrypted_buffers': []}}),
            (
                [{"module_path": "blah.exe", "calls": [], "process_id": 1}],
                {1: {"name": "blah.exe", "network_calls": [], "decrypted_buffers": []}},
            ),
            (
                [{"module_path": "blah.exe", "calls": [{"api": "blah"}], "process_id": 1}],
                {1: {"name": "blah.exe", "network_calls": [], "decrypted_buffers": []}},
            ),
            (
                [
                    {
                        "module_path": "blah.exe",
                        "calls": [
                            {"category": "network", "api": "getaddrinfo", "arguments": [{"name": "hostname", "value": "blah"}]}
                        ],
                        "process_id": 1,
                    }
                ],
                {1: {"name": "blah.exe", "network_calls": [{"getaddrinfo": {"hostname": "blah"}}], "decrypted_buffers": []}},
            ),
            (
                [
                    {
                        "module_path": "blah.exe",
                        "calls": [
                            {"category": "network", "api": "GetAddrInfoW", "arguments": [{"name": "hostname", "value": "blah"}]}
                        ],
                        "process_id": 1,
                    }
                ],
                {1: {"name": "blah.exe", "network_calls": [{"GetAddrInfoW": {"hostname": "blah"}}], "decrypted_buffers": []}},
            ),
            (
                [
                    {
                        "module_path": "blah.exe",
                        "calls": [
                            {
                                "category": "network",
                                "api": "connect",
                                "arguments": [{"name": "ip_address", "value": "blah"}, {"name": "port", "value": 123}],
                            }
                        ],
                        "process_id": 1,
                    }
                ],
                {
                    1: {
                        "name": "blah.exe",
                        "network_calls": [{"connect": {"ip_address": "blah", "port": 123}}],
                        "decrypted_buffers": [],
                    }
                },
            ),
            (
                [
                    {
                        "module_path": "blah.exe",
                        "calls": [
                            {
                                "category": "network",
                                "api": "InternetConnectW",
                                "arguments": [
                                    {"name": "username", "value": "blah"},
                                    {"name": "service", "value": "blah"},
                                    {"name": "password", "value": "blah"},
                                    {"name": "hostname", "value": "blah"},
                                    {"name": "port", "value": 123},
                                ],
                            }
                        ],
                        "process_id": 1,
                    }
                ],
                {
                    1: {
                        "name": "blah.exe",
                        "network_calls": [
                            {
                                "InternetConnectW": {
                                    "username": "blah",
                                    "service": "blah",
                                    "password": "blah",
                                    "hostname": "blah",
                                    "port": 123,
                                }
                            }
                        ],
                        "decrypted_buffers": [],
                    }
                },
            ),
            (
                [
                    {
                        "module_path": "blah.exe",
                        "calls": [
                            {
                                "category": "network",
                                "api": "InternetConnectA",
                                "arguments": [
                                    {"name": "username", "value": "blah"},
                                    {"name": "service", "value": "blah"},
                                    {"name": "password", "value": "blah"},
                                    {"name": "hostname", "value": "blah"},
                                    {"name": "port", "value": 123},
                                ],
                            }
                        ],
                        "process_id": 1,
                    }
                ],
                {
                    1: {
                        "name": "blah.exe",
                        "network_calls": [
                            {
                                "InternetConnectA": {
                                    "username": "blah",
                                    "service": "blah",
                                    "password": "blah",
                                    "hostname": "blah",
                                    "port": 123,
                                }
                            }
                        ],
                        "decrypted_buffers": [],
                    }
                },
            ),
            (
                [
                    {
                        "module_path": "blah.exe",
                        "calls": [{"category": "network", "api": "send", "arguments": [{"name": "buffer", "value": "blah"}]}],
                        "process_id": 1,
                    }
                ],
                {1: {"name": "blah.exe", "network_calls": [{"send": {"buffer": "blah"}}], "decrypted_buffers": []}},
            ),
            (
                [
                    {
                        "module_path": "blah.exe",
                        "calls": [
                            {"category": "crypto", "api": "CryptDecrypt", "arguments": [{"name": "buffer", "value": "blah"}]}
                        ],
                        "process_id": 1,
                    }
                ],
                {1: {"name": "blah.exe", "network_calls": [], "decrypted_buffers": [{"CryptDecrypt": {"buffer": "blah"}}]}},
            ),
            (
                [
                    {
                        "module_path": "blah.exe",
                        "calls": [
                            {"category": "system", "api": "OutputDebugStringA", "arguments": [{"name": "string", "value": "blah"}]}
                        ],
                        "process_id": 1,
                    }
                ],
                {1: {"name": "blah.exe", "network_calls": [], "decrypted_buffers": []}},
            ),
            (
                [
                    {
                        "module_path": "blah.exe",
                        "calls": [
                            {
                                "category": "system",
                                "api": "OutputDebugStringA",
                                "arguments": [{"name": "string", "value": "cfg:blah"}],
                            }
                        ],
                        "process_id": 1,
                    }
                ],
                {
                    1: {
                        "name": "blah.exe",
                        "network_calls": [],
                        "decrypted_buffers": [{"OutputDebugStringA": {"string": "cfg:blah"}}],
                    }
                },
            ),
            (
                [
                    {
                        "module_path": "blah.exe",
                        "calls": [
                            {
                                "category": "network",
                                "api": "URLDownloadToFileW",
                                "arguments": [{"name": "url", "value": "bad.evil"}],
                            }
                        ],
                        "process_id": 1,
                    }
                ],
                {1: {"name": "blah.exe", "network_calls": [{"URLDownloadToFileW": {"url": "bad.evil"}}], "decrypted_buffers": []}},
            ),
            (
                [
                    {
                        "module_path": "blah.exe",
                        "calls": [
                            {
                                "category": "network",
                                "api": "WSASend",
                                "arguments": [{"name": "buffer", "value": "blahblahblah bad.evil blahblahblah"}],
                            }
                        ],
                        "process_id": 1,
                    }
                ],
                {
                    1: {
                        "name": "blah.exe",
                        "network_calls": [{"WSASend": {"buffer": "blahblahblah bad.evil blahblahblah"}}],
                        "decrypted_buffers": [],
                    }
                },
            ),
        ],
    )
    def test_get_process_map(processes, correct_process_map):
        safelist = {"regex": {"dynamic.process.file_name": [r"C:\\Windows\\System32\\lsass\.exe"]}}
        assert get_process_map(processes, safelist) == correct_process_map

    @staticmethod
    def test_create_signature_result_section():
        # Case 1: Bare minimum
        name = "blah"
        signature = {"data": []}
        translated_score = 0
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO")
        ontres = OntologyResults(service_name="blah")
        process_map = {}
        safelist = {}
        actual_res_sec = _create_signature_result_section(
            name,
            signature,
            translated_score,
            ontres_sig,
            ontres,
            process_map,
            safelist
        )

        assert actual_res_sec.title_text == "Signature: blah"
        assert actual_res_sec.body == '[["TEXT", "No description for signature.", {}]]'
        assert actual_res_sec.heuristic.heur_id == 9999
        assert ontres_sig.as_primitives() == {
            'actors': [],
            'attacks': [],
            'attributes': [],
            'malware_families': [],
            'name': 'blah',
            'objectid': {
                'guid': None,
                'ontology_id': 'blah',
                'processtree': None,
                'service_name': 'blah',
                'session': None,
                'tag': 'blah',
                'time_observed': None,
                'treeid': None
            },
            'type': 'CUCKOO',
        }

        # Case 2: More than 10 marks
        signature = {"data": [{"a": "b"}, {"b": "b"}, {"c": "b"}, {"d": "b"}, {"e": "b"}, {"f": "b"}, {"g": "b"}, {"h": "b"}, {"i": "b"}, {"j": "b"}, {"k": "b"}, {"l": "b"}]}
        actual_res_sec = _create_signature_result_section(name, signature, translated_score, ontres_sig, ontres, process_map, safelist)
        assert actual_res_sec.body == '[["TEXT", "No description for signature.", {}], ["KEY_VALUE", {"a": "b"}, {}], ["KEY_VALUE", {"b": "b"}, {}], ["KEY_VALUE", {"c": "b"}, {}], ["KEY_VALUE", {"d": "b"}, {}], ["KEY_VALUE", {"e": "b"}, {}], ["KEY_VALUE", {"f": "b"}, {}], ["KEY_VALUE", {"g": "b"}, {}], ["KEY_VALUE", {"h": "b"}, {}], ["KEY_VALUE", {"i": "b"}, {}], ["KEY_VALUE", {"j": "b"}, {}], ["TEXT", "There were 2 more marks that were not displayed.", {}]]'
        assert ontres_sig.as_primitives() == {
            'actors': [],
            'attacks': [],
            'attributes': [],
            'malware_families': [],
            'name': 'blah',
            'objectid': {
                'guid': None,
                'ontology_id': 'blah',
                'processtree': None,
                'service_name': 'blah',
                'session': None,
                'tag': 'blah',
                'time_observed': None,
                'treeid': None
            },
            'type': 'CUCKOO',
        }

        # Case 3: Attribute is added
        p = ontres.create_process(
            start_time="1970-01-01 00:00:02",
            pid=1,
            image="blah",
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE")
        )
        ontres.add_process(p)
        signature = {"data": [{"pid": 1, "type": "blah", "cid": "blah", "call": {}}]}
        actual_res_sec = _create_signature_result_section(name, signature, translated_score, ontres_sig, ontres, process_map, safelist)
        assert actual_res_sec.body == '[["TEXT", "No description for signature.", {}]]'
        attr_as_primitives = ontres_sig.attributes[0].as_primitives()
        attr_as_primitives["source"].pop("guid")
        assert attr_as_primitives == {
            'action': None,
            'domain': None,
            'event_record_id': None,
            'file_hash': None,
            'meta': None,
            'source': {
                'ontology_id': 'blah',
                'processtree': None,
                'service_name': 'CAPE',
                'session': None,
                'tag': 'blah',
                'time_observed': '1970-01-01 00:00:02',
                'treeid': None
            },
            'target': None,
            'uri': None
        }

        # Case 4: False Positive Signature with False Positive mark
        signature = {"data": [{"pid": 1, "type": "blah", "cid": "blah", "call": {}}, {"domain": "google.com"}]}
        safelist = {"match": {"network.dynamic.domain": ["google.com"]}}
        actual_res_sec = _create_signature_result_section(name, signature, translated_score, ontres_sig, ontres, process_map, safelist)
        assert actual_res_sec is None

        # Case 5: True Positive Signature with False Positive mark
        signature = {"data": [{"pid": 1, "type": "blah", "cid": "blah", "call": {}}, {"domain": "google.com"}, {"domain": "google.ru"}]}
        safelist = {"match": {"network.dynamic.domain": ["google.com"]}}
        actual_res_sec = _create_signature_result_section(name, signature, translated_score, ontres_sig, ontres, process_map, safelist)
        assert actual_res_sec.body == '[["TEXT", "No description for signature.", {}], ["KEY_VALUE", {"domain": "google.ru"}, {}]]'

    @staticmethod
    def test_set_heuristic_signature():
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

    @staticmethod
    def test_set_attack_ids():
        # Case 1: No Attack IDs
        attack_ids = {}
        sig_res = ResultMultiSection("blah")
        sig_res.set_heuristic(1)
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO")
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

    @staticmethod
    def test_set_families():
        # Case 1: No families
        families = []
        sig_res = ResultMultiSection("blah")
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO")
        _set_families(families, sig_res, ontres_sig)
        assert sig_res.body is None
        assert ontres_sig.malware_families == []

        # Case 2: Multiple families
        families = ["blah", "blahblah", "blahblahblah"]
        _set_families(families, sig_res, ontres_sig)
        assert sig_res.body == '[["TEXT", "\\tFamilies: blah,blahblah,blahblahblah", {}]]'
        assert ontres_sig.malware_families == ['blah', 'blahblah', 'blahblahblah']

        # Case 3: Families in SKIPPED_FAMILIES
        families = ["generic", "wow"]
        sig_res = ResultMultiSection("blah")
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO")
        _set_families(families, sig_res, ontres_sig)
        assert sig_res.body == '[["TEXT", "\\tFamilies: wow", {}]]'
        assert ontres_sig.malware_families == ["wow"]

    @staticmethod
    def test_is_mark_call():
        assert _is_mark_call(["blah"]) is False
        assert _is_mark_call(["type", "pid", "cid", "call"]) is True

    @staticmethod
    def test_handle_mark_call():
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
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE")
        )
        ontres.add_process(p)
        _handle_mark_call(pid, action, attributes, ontres)
        attribute_as_prim = attributes[0].as_primitives()
        attribute_as_prim["source"].pop("guid")
        assert attribute_as_prim == {
            'action': 'blah',
            'domain': None,
            'event_record_id': None,
            'file_hash': None,
            'meta': None,
            'source': {
                'ontology_id': 'blah',
                'processtree': None,
                'service_name': 'CAPE',
                'session': None,
                'tag': 'blah',
                'time_observed': '1970-01-01 00:00:02',
                'treeid': None
            },
            'target': None,
            'uri': None,
        }

        # Case 4: action is None
        action = None
        _handle_mark_call(pid, action, attributes, ontres)
        attribute_as_prim = attributes[1].as_primitives()
        attribute_as_prim["source"].pop("guid")
        assert attribute_as_prim == {
            'action': None,
            'domain': None,
            'event_record_id': None,
            'file_hash': None,
            'meta': None,
            'source': {
                'ontology_id': 'blah',
                'processtree': None,
                'service_name': 'CAPE',
                'session': None,
                'tag': 'blah',
                'time_observed': '1970-01-01 00:00:02',
                'treeid': None
            },
            'target': None,
            'uri': None,
        }

    @staticmethod
    def test_handle_mark_data():
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
        ioc_res = _handle_mark_data(mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres)
        assert mark_body.body is None
        assert ioc_res is None

        # Case 2: Basic mark items
        mark_items = [("a", "b")]
        ioc_res = _handle_mark_data(mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres)
        assert mark_body.body == '{"a": "b"}'
        assert ioc_res is None

        # Case 3: not v, k in MARK_KEYS_TO_NOT_DISPLAY, dumps({k: v}) in sig_res.section_body.body
        mark_items = [("a", None), ("data_being_encrypted", "blah"), ("b", "a")]
        ioc_res = _handle_mark_data(mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres)
        assert mark_body.body == '{"a": "b"}'
        assert ioc_res is None

        # Case 4: mark_count >= 10
        mark_count = 10
        ioc_res = _handle_mark_data(mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres)
        assert mark_body.body == '{"a": "b"}'
        assert ioc_res is None

        # Case 5: Add multiple mark items
        mark_count = 0
        mark_items = [("c", "d"), ("d", "e")]
        ioc_res = _handle_mark_data(mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres)
        assert mark_body.body == '{"a": "b", "c": "d", "d": "e"}'
        assert ioc_res is None

        # Case 6: Add mark item of type bytes
        mark_items = [("f", b"blah")]
        with pytest.raises(TypeError):
            _handle_mark_data(mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres)

        # Case 7: Mark item contains a safelisted value
        safelist = {"match": {"network.dynamic.domain": ["google.com"]}}
        mark_items = [("f", "google.com")]
        ioc_res = _handle_mark_data(mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres)
        assert mark_body.body == '{"a": "b", "c": "d", "d": "e"}'
        assert ioc_res is None

        # Case 8: Mark item value is a list
        mark_items = [("g", [0, 1, 2])]
        ioc_res = _handle_mark_data(mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres)
        assert mark_body.body == '{"a": "b", "c": "d", "d": "e", "g": [0, 1, 2]}'
        assert ioc_res is None

        # Case 8: Mark item value is not a string or a list
        mark_items = [("h", 999)]
        ioc_res = _handle_mark_data(mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres)
        assert mark_body.body == '{"a": "b", "c": "d", "d": "e", "g": [0, 1, 2], "h": 999}'
        assert ioc_res is None

        # Case 9: Add mark item (str) with long value
        mark_items = [("f", "blah"*150)]
        ioc_res = _handle_mark_data(mark_items, sig_res, mark_count, mark_body, attributes, process_map, safelist, ontres)
        assert loads(mark_body.body)["f"] == "blah"*128 + "..."
        assert ioc_res is None

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
    def test_update_process_map():
        process_map = {}
        _update_process_map(process_map, [])
        assert process_map == {}

        default_so = OntologyResults()
        p = default_so.create_process(
            start_time="1970-01-01 00:00:02",
            pid=1,
            image="blah",
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE")
        )

        _update_process_map(process_map, [p])
        assert process_map == {1: {"name": "blah", "network_calls": [], "decrypted_buffers": []}}

    @staticmethod
    @pytest.mark.parametrize(
        "key, value, expected_tags",
        [
            #  Standard key for dynamic.process.file_name, nothing special with value
            ("cookie", "blah", {"dynamic.process.file_name": ["blah"]}),
            # Standard key for dynamic.process.file_name, process: in value
            ("setwindowshookexw", "process: blah", {"dynamic.process.file_name": ["blah"]}),
            # Standard key for dynamic.process.file_name, process: and delimiter in value
            ("setwindowshookexw", "process: blah -> blahblah", {"dynamic.process.file_name": ["blah"]}),
            # Standard key for dynamic.process.file_name, delimiter in value, special case
            ("file", "C:\\blah\\blah\\blah", {"dynamic.process.file_name": ["C:\\blah\\blah\\blah"]}),
            # Standard key for dynamic.process.file_name, delimiter in value, order of delimiters matters
            ("process", "regsrv32.exe, PID 123", {"dynamic.process.file_name": ["regsrv32.exe"]}),
            # Standard key for dynamic.process.command_line, nothing special with value
            ("command", "blah", {"dynamic.process.command_line": ["blah"]}),
            # Standard key for network.dynamic.ip, nothing special with value
            ("ip", "1.1.1.1", {"network.dynamic.ip": ["1.1.1.1"]}),
            # Standard key for network.dynamic.ip, : in value
            ("ip", "1.1.1.1:blah", {"network.dynamic.ip": ["1.1.1.1"], "network.port": ["blah"]}),
            # Standard key for network.dynamic.ip, : and ( in value
            ("ip", "1.1.1.1:blah (blahblah", {"network.dynamic.ip": ["1.1.1.1"], "network.port": ["blah"]}),
            # Standard key for dynamic.registry_key, nothing special with value
            ("regkey", "blah", {"dynamic.registry_key": ["blah"]}),
            # Standard key for network.dynamic.uri, nothing special with value
            ("url", "http://blah.com/blahblah", {"network.dynamic.uri": ["http://blah.com/blahblah"], "network.dynamic.domain": ["blah.com"], "network.dynamic.uri_path": ["/blahblah"]}),
            # Standard key for file.pe.exports.function_name, nothing special with value
            ("dynamicloader", "blah", {"file.pe.exports.function_name": ["blah"]}),
            # Key that ends in _exe for file.pe.exports.function_name, nothing special with value
            ("wscript_exe", "blah", {"dynamic.process.file_name": ["wscript.exe"]}),
            # Standard key for file.rule.yara, nothing special with value
            ("hit", "blah blah blah 'iwantthis'", {"file.rule.yara": ["iwantthis"]}),
            # Standard key for file.rule.yara, value has PID in it
            ("hit", "PID 2392 trigged the Yara rule 'iwantthis'", {"file.rule.yara": ["iwantthis"]}),
            # IOC found in data
            ("data", "Hey you I want to callout to http://blah.com", {}),
        ]
    )
    def test_tag_mark_values(key, value, expected_tags):
        ontres = OntologyResults("CAPE")
        actual_res_sec = ResultSection("blah")
        iocs_res = _tag_mark_values(actual_res_sec, key, value, [], {}, ontres)
        assert actual_res_sec.tags == expected_tags
        if key == "data":
            correct_iocs_res = ResultTableSection("IOCs found in Signature data")
            correct_iocs_res.add_row(TableRow({"ioc_type": "domain", "ioc": "blah.com"}))
            correct_iocs_res.add_row(TableRow({"ioc_type": "uri", "ioc": "http://blah.com"}))
            correct_iocs_res.add_tag("network.static.domain", "blah.com")
            correct_iocs_res.add_tag("network.static.uri", "http://blah.com")
            assert check_section_equality(iocs_res, correct_iocs_res)

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
        ]
    )
    def test_remove_bytes_from_buffer(buffer, expected_output):
        assert _remove_bytes_from_buffer(buffer) == expected_output
