import pytest
from test_cape_main import samples, cape_task_class


class TestCuckooTask:
    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_init(sample, cape_task_class):
        from cape.cape_main import CAPE_API_SUBMIT, CAPE_API_QUERY_TASK, CAPE_API_DELETE_TASK, \
            CAPE_API_QUERY_REPORT, CAPE_API_QUERY_PCAP, CAPE_API_QUERY_MACHINES

        kwargs = {"blah": "blah"}
        host_details = {"ip": "blah", "port": "blah", "auth_header": "blah"}
        cape_task_class_instance = cape_task_class(sample["filename"], host_details, **kwargs)
        assert cape_task_class_instance.file == sample["filename"]
        assert cape_task_class_instance.id is None
        assert cape_task_class_instance.report is None
        assert cape_task_class_instance.errors == []
        assert cape_task_class_instance == {"blah": "blah"}
        assert cape_task_class_instance.base_url == f"http://{host_details['ip']}:{host_details['port']}"
        assert cape_task_class_instance.submit_url == f"{cape_task_class_instance.base_url}/{CAPE_API_SUBMIT}"
        assert cape_task_class_instance.query_task_url == f"{cape_task_class_instance.base_url}/{CAPE_API_QUERY_TASK}"
        assert cape_task_class_instance.delete_task_url == f"{cape_task_class_instance.base_url}/{CAPE_API_DELETE_TASK}"
        assert cape_task_class_instance.query_report_url == f"{cape_task_class_instance.base_url}/{CAPE_API_QUERY_REPORT}"
        assert cape_task_class_instance.query_pcap_url == f"{cape_task_class_instance.base_url}/{CAPE_API_QUERY_PCAP}"
        assert cape_task_class_instance.query_machines_url == f"{cape_task_class_instance.base_url}/{CAPE_API_QUERY_MACHINES}"
