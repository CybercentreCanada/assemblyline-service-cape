import json

import pytest
from assemblyline_v4_service.common.dynamic_service_helper import \
    OntologyResults
from test_cape_main import (check_section_equality, create_tmp_manifest,
                            remove_tmp_manifest)


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
        from ipaddress import ip_network

        from assemblyline_v4_service.common.result import ResultSection
        from cape.cape_result import ANALYSIS_ERRORS, generate_al_result

        correct_process_map = {"blah": "blah"}
        mocker.patch("cape.cape_result.process_info")
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
        machine_info = {}
        custom_tree_id_safelist = list()

        output = generate_al_result(
            api_report, al_result, file_ext, ip_network("192.0.2.0/24"), "blah", safelist, machine_info,
            so, custom_tree_id_safelist
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
                {"started": "blah", "ended": "blah", "duration": "blah", "id": 1, "route": "blah", "version": "blah"},
                '{"CAPE Task ID": 1, "Duration": -1, "Routing": "blah", "CAPE Version": "blah"}',
                {"routing": "blah", "start_time": "blah", "end_time": "blah", "task_id": 1},
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
                '{"CAPE Task ID": 1, "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing":'
                ' "blah", "CAPE Version": "blah"}',
                {"routing": "blah", "start_time": "1970-01-01 00:00:01", "end_time": "1970-01-01 00:00:01", "task_id": 1},
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
                '{"CAPE Task ID": 1, "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing":'
                ' "blah", "CAPE Version": "blah"}',
                {"routing": "blah", "start_time": "1970-01-01 00:00:01", "end_time": "1970-01-01 00:00:01", "task_id": 1},
            ),
        ],
    )
    def test_process_info(info, correct_body, expected_am):
        from assemblyline_v4_service.common.result import (BODY_FORMAT,
                                                           ResultSection)
        from cape.cape_result import process_info

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
        from assemblyline_v4_service.common.result import ResultSection
        from cape.cape_result import process_debug

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
        from cape.cape_result import process_behaviour

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
        from cape.cape_result import get_process_api_sums

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
                    "start_time": "1970-01-01 00:00:01",
                    "end_time": "9999-12-31 23:59:59",
                    "objectid": {
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "tag": "blah",
                        "treeid": None,
                        "time_observed": "1970-01-01 00:00:01",
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
        from cape.cape_result import convert_cape_processes

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
                        "start_time": "1970-01-01 00:00:01",
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
                        "start_time": "1970-01-01 00:00:01",
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
                        "start_time": "1970-01-01 00:00:01",
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
        from assemblyline_v4_service.common.result import (
            ProcessItem, ResultProcessTreeSection, ResultSection)
        from cape.cape_result import build_process_tree

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

    # TODO: complete unit tests for process_network
    @staticmethod
    def test_process_network():
        pass

    @staticmethod
    def test_get_dns_sec():
        from json import dumps

        from assemblyline_v4_service.common.result import (BODY_FORMAT,
                                                           ResultSection)
        from cape.cape_result import _get_dns_sec

        resolved_ips = {}
        safelist = []
        assert _get_dns_sec(resolved_ips, safelist) is None
        resolved_ips = {"1.1.1.1": {"domain": "blah.com"}}
        expected_res_sec = ResultSection(
            "Protocol: DNS", body_format=BODY_FORMAT.TABLE, body=dumps([{"domain": "blah.com", "ip": "1.1.1.1"}])
        )
        expected_res_sec.set_heuristic(1000)
        expected_res_sec.add_tag("network.protocol", "dns")
        expected_res_sec.add_tag("network.dynamic.ip", "1.1.1.1")
        expected_res_sec.add_tag("network.dynamic.domain", "blah.com")
        actual_res_sec = _get_dns_sec(resolved_ips, safelist)
        assert check_section_equality(actual_res_sec, expected_res_sec)

        resolved_ips = {"0": {"domain": "blah.com"}}
        expected_res_sec = ResultSection(
            "Protocol: DNS", body_format=BODY_FORMAT.TABLE, body=dumps([{"domain": "blah.com"}])
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
                    "answer": {
                        "domain": "request",
                        "guid": None,
                        "process_id": None,
                        "process_name": None,
                        "time": None,
                        "type": "dns_type",
                    }
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {},
                "INetSim",
                {
                    "answer": {
                        "domain": "request",
                        "guid": None,
                        "process_id": None,
                        "process_name": None,
                        "time": None,
                        "type": "dns_type",
                    }
                },
            ),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "PTR"}], {}, "INetSim", {}),
            (
                [{"answers": [{"data": "answer"}], "request": "10.10.10.10.in-addr.arpa", "type": "PTR"}],
                {},
                "Internet",
                {"10.10.10.10": {"domain": "answer"}},
            ),
            (
                [
                    {"answers": [{"data": "10.10.10.10"}], "request": "answer", "type": "A"},
                    {"answers": [{"data": "answer"}], "request": "10.10.10.10.in-addr.arpa", "type": "PTR"},
                ],
                {},
                "Internet",
                {
                    "10.10.10.10": {
                        "domain": "answer",
                        "guid": None,
                        "process_id": None,
                        "process_name": None,
                        "time": None,
                        "type": "A",
                    }
                },
            ),
            ([{"answers": [{"data": "answer"}], "request": "ya:ba:da:ba:do:oo.ip6.arpa", "type": "PTR"}], {}, "Internet", {}),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"network_calls": [{"blah": {"hostname": "blah"}}]}},
                "",
                {
                    "answer": {
                        "domain": "request",
                        "guid": None,
                        "process_id": None,
                        "process_name": None,
                        "time": None,
                        "type": "dns_type",
                    }
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"blah": {"hostname": "request"}}]}},
                "",
                {
                    "answer": {
                        "domain": "request",
                        "guid": None,
                        "process_id": None,
                        "process_name": None,
                        "time": None,
                        "type": "dns_type",
                    }
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"getaddrinfo": {"hostname": "request"}}]}},
                "",
                {
                    "answer": {
                        "domain": "request",
                        "process_id": 1,
                        "process_name": "blah",
                        "guid": None,
                        "time": None,
                        "type": "dns_type",
                    }
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"InternetConnectW": {"hostname": "request"}}]}},
                "",
                {
                    "answer": {
                        "domain": "request",
                        "process_id": 1,
                        "process_name": "blah",
                        "guid": None,
                        "time": None,
                        "type": "dns_type",
                    }
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"InternetConnectA": {"hostname": "request"}}]}},
                "",
                {
                    "answer": {
                        "domain": "request",
                        "process_id": 1,
                        "process_name": "blah",
                        "guid": None,
                        "time": None,
                        "type": "dns_type",
                    }
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"GetAddrInfoW": {"hostname": "request"}}]}},
                "",
                {
                    "answer": {
                        "domain": "request",
                        "process_id": 1,
                        "process_name": "blah",
                        "guid": None,
                        "time": None,
                        "type": "dns_type",
                    }
                },
            ),
            (
                [{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}],
                {1: {"name": "blah", "network_calls": [{"gethostbyname": {"hostname": "request"}}]}},
                "",
                {
                    "answer": {
                        "domain": "request",
                        "process_id": 1,
                        "process_name": "blah",
                        "guid": None,
                        "time": None,
                        "type": "dns_type",
                    }
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
                    '0': {
                        'domain': 'request',
                        'guid': None,
                        'process_id': 1,
                        'process_name': 'blah',
                        'time': None,
                        'type': 'dns_type'
                    }
                },
            ),
        ],
    )
    def test_get_dns_map(dns_calls, process_map, routing, expected_return):
        from cape.cape_result import _get_dns_map

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
                {"blah": {"domain": "blah"}},
                {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": 123}]},
                (
                    [
                        {
                            "dest_ip": "blah",
                            "dest_port": 123,
                            "domain": "blah",
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
                {"blah": {"domain": "blah", "process_name": "blah", "process_id": "blah"}},
                {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": 123}]},
                (
                    [
                        {
                            "dest_ip": "blah",
                            "dest_port": 123,
                            "domain": "blah",
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
        from assemblyline_v4_service.common.result import (ResultSection,
                                                           ResultTableSection)
        from cape.cape_result import _get_low_level_flows

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
                        "pid": None,
                    }
                )
            expected_network_flows_table = expected_network_flows_table[:100]

        network_flows_table, netflows_sec = _get_low_level_flows(resolved_ips, flows)
        assert network_flows_table == expected_network_flows_table
        assert check_section_equality(netflows_sec, correct_netflows_sec)

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
        from cape.cape_result import _process_http_calls
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
        resolved_ips = {"1.1.1.1": {"domain": "nope.com"}}
        _process_http_calls(http_level_flows, process_map, dns_servers, resolved_ips, safelist, default_so)
        actual_req_table = []
        for nh in default_so.get_network_http():
            nh_as_prim = nh.__dict__
            actual_req_table.append(nh_as_prim)
        assert expected_req_table == actual_req_table

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
        from cape.cape_result import _handle_http_headers

        assert _handle_http_headers(header_string) == expected_header_dict

    @staticmethod
    def test_process_non_http_traffic_over_http():
        from json import dumps

        from assemblyline_v4_service.common.result import (BODY_FORMAT,
                                                           ResultSection)
        from cape.cape_result import _process_non_http_traffic_over_http

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
        from assemblyline_v4_service.common.result import (ResultSection,
                                                           ResultTableSection,
                                                           TableRow)
        from cape.cape_result import process_all_events

        default_so = OntologyResults()
        al_result = ResultSection("blah")
        p = default_so.create_process(
            pid=1,
            ppid=1,
            guid="{12345678-1234-5678-1234-567812345679}",
            command_line="blah blah.com",
            image="blah",
            start_time="1970-01-01 00:00:01",
            pguid="{12345678-1234-5678-1234-567812345679}",
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE")
        )
        default_so.add_process(p)
        nc = default_so.create_network_connection(
            source_port=1,
            destination_ip="1.1.1.1",
            source_ip="2.2.2.2",
            destination_port=1,
            transport_layer_protocol="udp",
            direction="outbound",
            process=p,
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE", time_observed="1970-01-01 00:00:02")
        )

        default_so.add_network_connection(nc)
        dns = default_so.create_network_dns(domain="blah", resolved_ips=["1.1.1.1"], lookup_type="A")
        default_so.add_network_dns(dns)

        correct_result_section = ResultTableSection(title_text="Event Log")

        correct_result_section.add_tag("dynamic.process.command_line", "blah blah.com")
        correct_result_section.add_tag("dynamic.process.file_name", "blah")

        correct_result_section.add_row(
            TableRow(
                **{
                    "time_observed": "1970-01-01 00:00:01",
                    "process_name": "blah (1)",
                    "details": {"command_line": "blah blah.com"},
                }
            )
        )
        correct_result_section.add_row(
            TableRow(
                **{
                    "time_observed": "1970-01-01 00:00:02",
                    "process_name": "blah (1)",
                    "details": {"protocol": "udp", "domain": "blah", "dest_ip": "1.1.1.1", "dest_port": 1},
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
        from assemblyline_v4_service.common.result import (BODY_FORMAT,
                                                           ResultSection)
        from cape.cape_result import process_curtain

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
                correct_result_section.add_tag("file.powershell.cmdlet", behaviour)
        correct_result_section.set_body(json.dumps(curtain_body), BODY_FORMAT.TABLE)

        process_curtain(curtain, al_result, process_map)
        if len(al_result.subsections) > 0:
            assert check_section_equality(al_result.subsections[0], correct_result_section)
        else:
            assert al_result.subsections == []

    @staticmethod
    def test_process_hollowshunter():
        from assemblyline_v4_service.common.result import (ResultSection,
                                                           ResultTableSection,
                                                           TableRow)
        from cape.cape_result import process_hollowshunter

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
        from assemblyline_v4_service.common.result import (BODY_FORMAT,
                                                           ResultSection,
                                                           ResultTableSection,
                                                           TableRow)
        from cape.cape_result import process_buffers

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
        from cape.cape_result import process_cape
        assert process_cape(input) == output

    @staticmethod
    @pytest.mark.parametrize(
        "processes, correct_process_map",
        [
            ([], {}),
            ([{"module_path": "C:\\windows\\System32\\lsass.exe", "calls": [], "process_id": 1}], {}),
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
        from cape.cape_result import get_process_map

        safelist = {"regex": {"dynamic.process.file_name": [r"C:\\Windows\\System32\\lsass\.exe"]}}
        assert get_process_map(processes, safelist) == correct_process_map

    @staticmethod
    def test_create_signature_result_section():
        from assemblyline_v4_service.common.dynamic_service_helper import (
            ObjectID, OntologyResults, Signature)
        from cape.cape_result import _create_signature_result_section

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
        assert actual_res_sec.body == '[["TEXT", "No description for signature."]]'
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
        assert actual_res_sec.body == '[["TEXT", "No description for signature."], ["KEY_VALUE", {"a": "b"}], ["KEY_VALUE", {"b": "b"}], ["KEY_VALUE", {"c": "b"}], ["KEY_VALUE", {"d": "b"}], ["KEY_VALUE", {"e": "b"}], ["KEY_VALUE", {"f": "b"}], ["KEY_VALUE", {"g": "b"}], ["KEY_VALUE", {"h": "b"}], ["KEY_VALUE", {"i": "b"}], ["KEY_VALUE", {"j": "b"}], ["TEXT", "There were 2 more marks that were not displayed."]]'
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
        assert actual_res_sec.body == '[["TEXT", "No description for signature."]]'
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
        assert actual_res_sec.body == '[["TEXT", "No description for signature."], ["KEY_VALUE", {"domain": "google.ru"}]]'

    @staticmethod
    def test_set_heuristic_signature():
        from assemblyline_v4_service.common.result import ResultMultiSection
        from cape.cape_result import _set_heuristic_signature

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
        from assemblyline_v4_service.common.dynamic_service_helper import (
            ObjectID, Signature)
        from assemblyline_v4_service.common.result import ResultMultiSection
        from cape.cape_result import _set_attack_ids

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
        from assemblyline_v4_service.common.dynamic_service_helper import (
            ObjectID, Signature)
        from assemblyline_v4_service.common.result import ResultMultiSection
        from cape.cape_result import _set_families

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
        assert sig_res.body == '[["TEXT", "\\tFamilies: blah,blahblah,blahblahblah"]]'
        assert ontres_sig.malware_families == ['blah', 'blahblah', 'blahblahblah']

        # Case 3: Families in SKIPPED_FAMILIES
        families = ["generic", "wow"]
        sig_res = ResultMultiSection("blah")
        ontres_sig = Signature(ObjectID("blah", "blah", "blah"), "blah", "CUCKOO")
        _set_families(families, sig_res, ontres_sig)
        assert sig_res.body == '[["TEXT", "\\tFamilies: wow"]]'
        assert ontres_sig.malware_families == ["wow"]

    @staticmethod
    def test_is_mark_call():
        from cape.cape_result import _is_mark_call
        assert _is_mark_call(["blah"]) is False
        assert _is_mark_call(["type", "pid", "cid", "call"]) is True

    @staticmethod
    def test_handle_mark_call():
        from assemblyline_v4_service.common.dynamic_service_helper import \
            OntologyResults
        from cape.cape_result import _handle_mark_call

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
        from json import loads

        from assemblyline_v4_service.common.dynamic_service_helper import \
            OntologyResults
        from assemblyline_v4_service.common.result import (KVSectionBody,
                                                           ResultMultiSection,
                                                           TextSectionBody)
        from cape.cape_result import _handle_mark_data

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
        from cape.cape_result import _remove_network_http_noise

        assert _remove_network_http_noise(sigs) == correct_sigs

    @staticmethod
    def test_update_process_map():
        from cape.cape_result import _update_process_map

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
            ("url", "http://blah.com/blahblah", {"network.dynamic.uri": ["http://blah.com/blahblah"], "network.dynamic.domain": ["blah.com"]}),
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
        from assemblyline_v4_service.common.result import (ResultSection,
                                                           ResultTableSection,
                                                           TableRow)
        from cape.cape_result import _tag_mark_values
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
        from cape.cape_result import _remove_bytes_from_buffer
        assert _remove_bytes_from_buffer(buffer) == expected_output
