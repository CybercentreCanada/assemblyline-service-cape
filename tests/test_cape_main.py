import os
import json
import pytest
import shutil
import requests_mock

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
samples = [
    dict(
        sid=1,
        metadata={},
        service_name='cape',
        service_config={},
        fileinfo=dict(
            magic='ASCII text, with no line terminators',
            md5='fda4e701258ba56f465e3636e60d36ec',
            mime='text/plain',
            sha1='af2c2618032c679333bebf745e75f9088748d737',
            sha256='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
            size=19,
            type='unknown',
        ),
        filename='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
        min_classification='TLP:WHITE',
        max_files=501,  # TODO: get the actual value
        ttl=3600,
        safelist_config={
            "enabled": False,
            "hash_types": ['sha1', 'sha256'],
            "enforce_safelist_service": False
        }
    ),
]


def create_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if not os.path.exists(temp_service_config_path):
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)


def remove_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if os.path.exists(temp_service_config_path):
        os.remove(temp_service_config_path)


@pytest.fixture
def cape_task_class():
    create_tmp_manifest()
    try:
        from cape.cape_main import CapeTask
        yield CapeTask
    finally:
        remove_tmp_manifest()


@pytest.fixture
def cape_class_instance():
    create_tmp_manifest()
    try:
        from cape.cape_main import CAPE
        yield CAPE()
    finally:
        remove_tmp_manifest()


@pytest.fixture
def dummy_task_class():
    class DummyTask:
        def __init__(self):
            self.supplementary = []
            self.extracted = []
    yield DummyTask


@pytest.fixture
def dummy_request_class(dummy_task_class):

    class DummyRequest(dict):
        def __init__(self, **some_dict):
            super(DummyRequest, self).__init__()
            self.task = dummy_task_class()
            self.file_type = None
            self.sha256 = True
            self.deep_scan = False
            self.update(some_dict)

        def add_supplementary(self, path, name, description):
            self.task.supplementary.append({"path": path, "name": name, "description": description})

        def add_extracted(self, path, name, description):
            self.task.extracted.append({"path": path, "name": name, "description": description})

        def get_param(self, key):
            val = self.get(key, None)
            if val is None:
                raise Exception(f"Service submission parameter not found: {key}")
            else:
                return val

        @staticmethod
        def add_image(path, name, description, classification=None, ocr_heuristic_id=None):
            return {
                "img": {"path": path, "name": name, "description": description, "classification": classification},
                "thumb": {"path": path, "name": f"{name}.thumb", "description": description, "classification": classification}
            }

    yield DummyRequest


@pytest.fixture
def dummy_zip_class():
    class DummyZip:
        def __init__(self, members=[]):
            self.supplementary = None
            self.members = members
            self.filelist = self.members

        def namelist(self):
            return [
                "reports/lite.json",
                "hollowshunter/hh_process_123_dump_report.json",
                "hollowshunter/hh_process_123_scan_report.json",
                "hollowshunter/hh_process_123_blah.exe",
                "hollowshunter/hh_process_123_blah.shc",
                "hollowshunter/hh_process_123_blah.dll",
                "shots/0005.jpg",
                "shots/0010.jpg",
                "shots/0001_small.jpg",
                "shots/0001.jpg",
                "network/blahblah",
                "CAPE/ohmy.exe",
                "files/yaba.exe",
                "dump.pcap",
                "sum.pcap",
            ]

        def extract(self, output, path=None):
            pass

        def getnames(self):
            return self.members

        def close(self):
            pass

        def get_artifacts(self):
            return [
                "shots/0005.jpg",
                "shots/0010.jpg",
                "shots/0001_small.jpg",
                "shots/0001.jpg",
                "network/blahblah",
                "CAPE/ohmy.exe",
                "files/yaba.exe",
                "dump.pcap",
                "sum.pcap",
            ]
    yield DummyZip


@pytest.fixture
def dummy_zip_member_class():
    class DummyZipMember:
        def __init__(self, name, size):
            self.filename = name
            self.file_size = size

        def isfile(self):
            return True

        def startswith(self, val):
            return val in self.name
    yield DummyZipMember


@pytest.fixture
def dummy_json_doc_class_instance():
    # This class is just to create a doc to pass to JSONDecodeError for construction
    class DummyJSONDoc:
        def count(self, *args):
            return 0

        def rfind(self, *args):
            return 0
    yield DummyJSONDoc()


@pytest.fixture
def dummy_result_class_instance():
    class DummyResult:
        from assemblyline_v4_service.common.result import ResultSection

        def __init__(self):
            self.sections = []

        def add_section(self, res_sec: ResultSection):
            self.sections.append(res_sec)
    return DummyResult()


@pytest.fixture
def dummy_api_interface_class():
    class DummyApiInterface:
        @staticmethod
        def get_safelist():
            return []
    return DummyApiInterface


def yield_sample_file_paths():
    samples_path = os.path.join(TEST_DIR, "samples")
    # For some reason os.listdir lists the same file twice, but with a trailing space on the second entry
    paths = set([path.rstrip() for path in os.listdir(samples_path)])
    for sample in paths:
        yield os.path.join(samples_path, sample)


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        result_heuristic_equality = this.heuristic.attack_ids == that.heuristic.attack_ids and \
            this.heuristic.frequency == that.heuristic.frequency and \
            this.heuristic.heur_id == that.heuristic.heur_id and \
            this.heuristic.score == that.heuristic.score and \
            this.heuristic.score_map == that.heuristic.score_map and \
            this.heuristic.signatures == that.heuristic.signatures

        if not result_heuristic_equality:
            print("The heuristics are not equal:")
            if this.heuristic.attack_ids != that.heuristic.attack_ids:
                print("The attack_ids are different:")
                print(f"{this.heuristic.attack_ids}")
                print(f"{that.heuristic.attack_ids}")
            if this.heuristic.frequency != that.heuristic.frequency:
                print("The frequencies are different:")
                print(f"{this.heuristic.frequency}")
                print(f"{that.heuristic.frequency}")
            if this.heuristic.heur_id != that.heuristic.heur_id:
                print("The heur_ids are different:")
                print(f"{this.heuristic.heur_id}")
                print(f"{that.heuristic.heur_id}")
            if this.heuristic.score != that.heuristic.score:
                print("The scores are different:")
                print(f"{this.heuristic.score}")
                print(f"{that.heuristic.score}")
            if this.heuristic.score_map != that.heuristic.score_map:
                print("The score_maps are different:")
                print(f"{this.heuristic.score_map}")
                print(f"{that.heuristic.score_map}")
            if this.heuristic.signatures != that.heuristic.signatures:
                print("The signatures are different:")
                print(f"{this.heuristic.signatures}")
                print(f"{that.heuristic.signatures}")

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        print("The heuristics are not equal:")
        if this.heuristic:
            print(f"{this.heuristic.__dict__}")
        else:
            print("this.heuristic is None")
        if that.heuristic:
            print(f"{that.heuristic.__dict__}")
        else:
            print("that.heuristic is None")
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = result_heuristic_equality and \
        this.body == that.body and \
        this.body_format == that.body_format and \
        this.classification == that.classification and \
        this.depth == that.depth and \
        len(this.subsections) == len(that.subsections) and \
        this.title_text == that.title_text and \
        this.tags == that.tags and \
        this.auto_collapse == that.auto_collapse

    if not current_section_equality:
        print("The current sections are not equal:")
        if not result_heuristic_equality:
            print("The result heuristics are not equal")
        if this.body != that.body:
            print("The bodies are different:")
            print(f"{this.body}")
            print(f"{that.body}")
        if this.body_format != that.body_format:
            print("The body formats are different:")
            print(f"{this.body_format}")
            print(f"{that.body_format}")
        if this.classification != that.classification:
            print("The classifications are different:")
            print(f"{this.classifications}")
            print(f"{that.classifications}")
        if this.depth != that.depth:
            print("The depths are different:")
            print(f"{this.depths}")
            print(f"{that.depths}")
        if len(this.subsections) != len(that.subsections):
            print("The number of subsections are different:")
            print(f"{len(this.subsections)}")
            print(f"{len(that.subsections)}")
        if this.title_text != that.title_text:
            print("The title texts are different:")
            print(f"{this.title_text}")
            print(f"{that.title_text}")
        if this.tags != that.tags:
            print("The tags are different:")
            print(f"{this.tags}")
            print(f"{that.tags}")
        if this.auto_collapse != that.auto_collapse:
            print("The auto_collapse settings are different:")
            print(f"{this.auto_collapse}")
            print(f"{that.auto_collapse}")
        return False

    for index, subsection in enumerate(this.subsections):
        subsection_equality = check_section_equality(subsection, that.subsections[index])
        if not subsection_equality:
            return False

    return True


class TestModule:
    @staticmethod
    def test_hollowshunter_constants():
        from cape.cape_main import HOLLOWSHUNTER_REPORT_REGEX, HOLLOWSHUNTER_DUMP_REGEX
        assert HOLLOWSHUNTER_REPORT_REGEX == "hollowshunter\/hh_process_[0-9]{3,}_(dump|scan)_report\.json$"
        assert HOLLOWSHUNTER_DUMP_REGEX == "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*(\.*[a-zA-Z0-9]+)+\.(exe|shc|dll)$"

    @staticmethod
    def test_cape_api_constants():
        from cape.cape_main import CAPE_API_SUBMIT, CAPE_API_QUERY_TASK, CAPE_API_DELETE_TASK, \
            CAPE_API_QUERY_REPORT, CAPE_API_QUERY_MACHINES
        assert CAPE_API_SUBMIT == "tasks/create/file/"
        assert CAPE_API_QUERY_TASK == "tasks/view/%s/"
        assert CAPE_API_DELETE_TASK == "tasks/delete/%s/"
        assert CAPE_API_QUERY_REPORT == "tasks/get/report/%s/"
        assert CAPE_API_QUERY_MACHINES == "machines/list/"

    @staticmethod
    def test_retry_constants():
        from cape.cape_main import CAPE_POLL_DELAY, GUEST_VM_START_TIMEOUT, REPORT_GENERATION_TIMEOUT
        assert CAPE_POLL_DELAY == 5
        assert GUEST_VM_START_TIMEOUT == 360
        assert REPORT_GENERATION_TIMEOUT == 420

    @staticmethod
    def test_analysis_constants():
        from cape.cape_main import ANALYSIS_TIMEOUT
        assert ANALYSIS_TIMEOUT == 150

    @staticmethod
    def test_image_tag_constants():
        from cape.cape_main import LINUX_IMAGE_PREFIX, WINDOWS_IMAGE_PREFIX, x86_IMAGE_SUFFIX, x64_IMAGE_SUFFIX, \
            RELEVANT_IMAGE_TAG, ALL_IMAGES_TAG, MACHINE_NAME_REGEX
        assert LINUX_IMAGE_PREFIX == "ub"
        assert WINDOWS_IMAGE_PREFIX == "win"
        assert x86_IMAGE_SUFFIX == "x86"
        assert x64_IMAGE_SUFFIX == "x64"
        assert RELEVANT_IMAGE_TAG == "auto"
        assert ALL_IMAGES_TAG == "all"
        assert MACHINE_NAME_REGEX == f"(?:{('|').join([LINUX_IMAGE_PREFIX, WINDOWS_IMAGE_PREFIX])})(.*)(?:{('|').join([x64_IMAGE_SUFFIX, x86_IMAGE_SUFFIX])})"

    @staticmethod
    def test_file_constants():
        from cape.cape_main import LINUX_x86_FILES, LINUX_x64_FILES, WINDOWS_x86_FILES
        assert set(LINUX_x86_FILES) == {"executable/linux/elf32", "executable/linux/so32", "executable/linux/coff32"}
        assert set(LINUX_x64_FILES) == {"executable/linux/elf64", "executable/linux/so64", "executable/linux/ia/coff64", "executable/linux/coff64"}
        assert set(WINDOWS_x86_FILES) == {'executable/windows/pe32', 'executable/windows/dll32'}

    @staticmethod
    def test_supported_extensions_constant():
        from cape.cape_main import SUPPORTED_EXTENSIONS
        assert SUPPORTED_EXTENSIONS == ['bat', 'bin', 'cpl', 'dll', 'doc', 'docm', 'docx', 'dotm', 'elf', 'eml', 'exe',
                                        'hta', 'htm', 'html', 'hwp', 'jar', 'js', 'lnk', 'mht', 'msg', 'msi', 'pdf',
                                        'potm', 'potx', 'pps', 'ppsm', 'ppsx', 'ppt', 'pptm', 'pptx', 'ps1', 'pub',
                                        'py', 'pyc', 'rar', 'rtf', 'sh', 'swf', 'vbs', 'wsf', 'xls', 'xlsm', 'xlsx']

    @staticmethod
    def test_illegal_filename_chars_constant():
        from cape.cape_main import ILLEGAL_FILENAME_CHARS
        assert ILLEGAL_FILENAME_CHARS == set('<>:"/\|?*')

    @staticmethod
    def test_status_enumeration_constants():
        from cape.cape_main import TASK_MISSING, TASK_STOPPED, INVALID_JSON, REPORT_TOO_BIG, \
            SERVICE_CONTAINER_DISCONNECTED, MISSING_REPORT, TASK_STARTED, TASK_STARTING, TASK_COMPLETED, TASK_REPORTED, \
            ANALYSIS_FAILED, ANALYSIS_EXCEEDED_TIMEOUT
        assert TASK_MISSING == "missing"
        assert TASK_STOPPED == "stopped"
        assert INVALID_JSON == "invalid_json_report"
        assert REPORT_TOO_BIG == "report_too_big"
        assert SERVICE_CONTAINER_DISCONNECTED == "service_container_disconnected"
        assert MISSING_REPORT == "missing_report"
        assert TASK_STARTED == "started"
        assert TASK_STARTING == "starting"
        assert TASK_COMPLETED == "completed"
        assert TASK_REPORTED == "reported"
        assert ANALYSIS_FAILED == "failed_analysis"
        assert ANALYSIS_EXCEEDED_TIMEOUT == "analysis_exceeded_timeout"

    @staticmethod
    def test_exclude_chain_ex():
        from cape.cape_main import _exclude_chain_ex
        from assemblyline.common.exceptions import ChainException
        assert _exclude_chain_ex(ChainException("blah")) is False
        assert _exclude_chain_ex(Exception("blah")) is True

    @staticmethod
    def test_retry_on_none():
        from cape.cape_main import _retry_on_none
        assert _retry_on_none(None) is True
        assert _retry_on_none("blah") is False

    @staticmethod
    def test_generate_random_words():
        from cape.cape_main import generate_random_words
        import re
        pattern = r"[a-zA-Z0-9]+"
        for num_words in [1, 2, 3]:
            test_result = generate_random_words(num_words)
            split_words = test_result.split(" ")
            for word in split_words:
                assert re.match(pattern, word)

    @staticmethod
    def test_tasks_are_similar():
        from cape.cape_main import CapeTask, tasks_are_similar, ANALYSIS_FAILED

        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}

        item_to_find_1 = CapeTask("blahblah", host_to_use, timeout=123, custom="", package="blah", route="blah", options="blah", memory="blah", enforce_timeout="blah", tags="blah", clock="blah")

        item_to_find_2 = CapeTask("blah", host_to_use, timeout=123, custom="", package="blah", route="blah", options="blah", memory="blah", enforce_timeout="blah", tags="blah", clock="blah")

        items = [
            {"status": ANALYSIS_FAILED},
            {"status": "success", "target": "blah", "timeout": 321, "custom": "", "package": "blah", "route": "blah", "options": "blah", "memory": "blah", "enforce_timeout": "blah", "tags": ["blah"], "clock": "blah"},
            {"status": "success", "target": "blah", "timeout": 123, "custom": "", "package": "blah", "route": "blah", "options": "blah", "memory": "blah", "enforce_timeout": "blah", "tags": ["blah"], "clock": "blah"},
        ]

        assert tasks_are_similar(item_to_find_1, items) is False
        assert tasks_are_similar(item_to_find_2, items) is True



class TestCapeMain:
    @classmethod
    def setup_class(cls):
        # Placing the samples in the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            sample_path = os.path.join(samples_path, sample)
            shutil.copyfile(sample_path, os.path.join("/tmp", sample))

    @classmethod
    def teardown_class(cls):
        # Cleaning up the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            temp_sample_path = os.path.join("/tmp", sample)
            os.remove(temp_sample_path)

    @staticmethod
    def test_init(cape_class_instance):
        assert cape_class_instance.file_name is None
        assert cape_class_instance.file_res is None
        assert cape_class_instance.request is None
        assert cape_class_instance.session is None
        assert cape_class_instance.timeout is None
        assert cape_class_instance.allowed_images == []
        assert cape_class_instance.artifact_list is None
        assert cape_class_instance.hosts == []
        assert cape_class_instance.routing == ""

    @staticmethod
    def test_start(cape_class_instance, dummy_api_interface_class, mocker):
        mocker.patch.object(cape_class_instance, "get_api_interface", return_value=dummy_api_interface_class)
        cape_class_instance.start()
        assert cape_class_instance.connection_timeout_in_seconds == cape_class_instance.config.get(
            'connection_timeout_in_seconds',
            30)
        assert cape_class_instance.connection_attempts == cape_class_instance.config.get('connection_attempts', 3)
        assert cape_class_instance.timeout == cape_class_instance.config.get('rest_timeout_in_seconds', 150)
        assert cape_class_instance.allowed_images == cape_class_instance.config.get('allowed_images', [])

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample, cape_class_instance, mocker):
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from cape.cape_main import CAPE, CapeHostsUnavailable

        mocker.patch('cape.cape_main.generate_random_words', return_value="blah")
        mocker.patch.object(CAPE, "_decode_mime_encoded_file_name", return_value=None)
        mocker.patch.object(CAPE, "_remove_illegal_characters_from_file_name", return_value=None)
        mocker.patch.object(CAPE, "query_machines", return_value={})
        mocker.patch.object(CAPE, "_handle_specific_machine", return_value=(False, True))
        mocker.patch.object(CAPE, "_handle_specific_image", return_value=(False, {}))
        mocker.patch.object(CAPE, "_handle_specific_platform", return_value=(False, {}))
        mocker.patch.object(CAPE, "_general_flow")
        # mocker.patch.object(CAPE, "attach_ontological_result")

        service_task = ServiceTask(sample)
        task = Task(service_task)
        cape_class_instance._task = task
        service_request = ServiceRequest(task)

        # Coverage test
        mocker.patch.object(CAPE, "_assign_file_extension", return_value=None)
        with pytest.raises(CapeHostsUnavailable):
            cape_class_instance.execute(service_request)
        cape_class_instance.hosts = [{"ip": "1.1.1.1"}]
        cape_class_instance.execute(service_request)
        assert True

        mocker.patch.object(CAPE, "_assign_file_extension", return_value="blah")

        # Actually executing the sample
        cape_class_instance.execute(service_request)

        # Assert values of the class instance are expected
        assert cape_class_instance.file_res == service_request.result

        with mocker.patch.object(CAPE, "_handle_specific_machine", return_value=(True, False)):
            # Cover that code!
            cape_class_instance.execute(service_request)

        with mocker.patch.object(CAPE, "_handle_specific_machine", return_value=(True, True)):
            # Cover that code!
            cape_class_instance.execute(service_request)

        with mocker.patch.object(CAPE, "_handle_specific_machine", return_value=(False, False)):
            with mocker.patch.object(CAPE, "_handle_specific_image", return_value=(True, {})):
                # Cover that code!
                cape_class_instance.execute(service_request)

        with mocker.patch.object(CAPE, "_handle_specific_image", return_value=(True, {"blah": ["blah"]})):
            # Cover that code!
            cape_class_instance.execute(service_request)

        with mocker.patch.object(CAPE, "_handle_specific_image", return_value=(True, {"blah": ["blah"], "blahblah": ["blah"]})):
            # Cover that code!
            cape_class_instance.execute(service_request)

        with mocker.patch.object(CAPE, "_handle_specific_platform", return_value=(True, {"blah": []})):
            # Cover that code!
            cape_class_instance.execute(service_request)

        with mocker.patch.object(CAPE, "_handle_specific_platform", return_value=(True, {"blah": ["blah"]})):
            # Cover that code!
            cape_class_instance.execute(service_request)

    @staticmethod
    def test_general_flow(cape_class_instance, dummy_request_class, dummy_result_class_instance, mocker):
        from assemblyline_v4_service.common.result import ResultSection
        from assemblyline.common.exceptions import RecoverableError
        from cape.cape_main import CAPE, AnalysisTimeoutExceeded
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

        so = SandboxOntology()
        hosts = []
        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        mocker.patch.object(CAPE, "submit")
        mocker.patch.object(CAPE, "_generate_report")
        mocker.patch.object(CAPE, "delete_task")
        mocker.patch.object(CAPE, "_is_invalid_analysis_timeout", return_value=False)
        mocker.patch.object(CAPE, "_determine_host_to_use", return_value=host_to_use)
        mocker.patch.object(CAPE, "_set_task_parameters")

        cape_class_instance.file_name = "blah"
        cape_class_instance.request = dummy_request_class()
        cape_class_instance.request.file_contents = "blah"
        cape_class_instance.file_res = dummy_result_class_instance
        cape_class_instance.sandbox_ontologies = []

        kwargs = dict()
        file_ext = "blah"
        parent_section = ResultSection("blah")
        # Purely for code coverage
        with pytest.raises(Exception):
            cape_class_instance._general_flow(kwargs, file_ext, parent_section, hosts, so)

        # Reboot coverage
        cape_class_instance.config["reboot_supported"] = True
        cape_class_instance._general_flow(kwargs, file_ext, parent_section, [
                                            {"auth_header": "blah", "ip": "blah", "port": "blah"}], True, 1, so)

        with mocker.patch.object(CAPE, "submit", side_effect=Exception("blah")):
            with pytest.raises(Exception):
                cape_class_instance._general_flow(kwargs, file_ext, parent_section, hosts, so)

        with mocker.patch.object(CAPE, "submit", side_effect=AnalysisTimeoutExceeded("blah")):
            cape_class_instance._general_flow(kwargs, file_ext, parent_section, hosts, so)

        with mocker.patch.object(CAPE, "submit", side_effect=RecoverableError("blah")):
            with pytest.raises(RecoverableError):
                cape_class_instance._general_flow(kwargs, file_ext, parent_section, hosts, so)

        with mocker.patch.object(CAPE, "_is_invalid_analysis_timeout", return_value=True):
            cape_class_instance._general_flow(kwargs, file_ext, parent_section, hosts, so)

    @staticmethod
    @pytest.mark.parametrize(
        "task_id, poll_started_status, poll_report_status",
        [
            (None, None, None),
            (1, None, None),
            (1, "blah", None),
            (1, "missing", None),
            (1, "analysis_failed", None),
            (1, "started", None),
            (1, "started", "blah"),
            (1, "started", "missing"),
            (1, "started", "stopped"),
            (1, "started", "invalid_json"),
            (1, "started", "report_too_big"),
            (1, "started", "service_container_disconnected"),
            (1, "started", "missing_report"),
            (1, "started", "analysis_failed"),
            (1, "started", "processing_failed"),
            (1, "started", "reboot"),
        ]
    )
    def test_submit(task_id, poll_started_status, poll_report_status, cape_class_instance, dummy_request_class, mocker):
        from cape.cape_main import TASK_STARTED, TASK_MISSING, TASK_STOPPED, INVALID_JSON, REPORT_TOO_BIG, \
            SERVICE_CONTAINER_DISCONNECTED, MISSING_REPORT, ANALYSIS_FAILED, ANALYSIS_EXCEEDED_TIMEOUT, PROCESSING_FAILED, CapeTask, \
            AnalysisTimeoutExceeded, AnalysisFailed
        from retrying import RetryError
        from assemblyline.common.exceptions import RecoverableError
        from assemblyline_v4_service.common.result import ResultSection
        all_statuses = [TASK_STARTED, TASK_MISSING, TASK_STOPPED, INVALID_JSON, REPORT_TOO_BIG,
                        SERVICE_CONTAINER_DISCONNECTED, MISSING_REPORT, ANALYSIS_FAILED, ANALYSIS_EXCEEDED_TIMEOUT, PROCESSING_FAILED]
        file_content = b"blah"
        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cape_task = CapeTask("blah", host_to_use, blah="blah")
        cape_task.id = task_id
        parent_section = ResultSection("blah")
        cape_class_instance.request = dummy_request_class()

        mocker.patch.object(cape_class_instance, "sha256_check", return_value=False)
        mocker.patch.object(cape_class_instance, "submit_file", return_value=task_id)
        mocker.patch.object(cape_class_instance, "delete_task", return_value=True)
        if poll_started_status:
            mocker.patch.object(cape_class_instance, "poll_started", return_value=poll_started_status)
        else:
            mocker.patch.object(cape_class_instance, "poll_started", side_effect=RetryError("blah"))
        if poll_report_status:
            mocker.patch.object(cape_class_instance, "poll_report", return_value=poll_report_status)
        else:
            mocker.patch.object(cape_class_instance, "poll_report", side_effect=RetryError("blah"))

        if task_id is None:
            cape_class_instance.submit(file_content, cape_task, parent_section)
            assert cape_task.id is None
            mocker.patch.object(cape_class_instance, "submit_file", side_effect=Exception)
            cape_task.id = 1
            with pytest.raises(Exception):
                cape_class_instance.submit(file_content, cape_task, parent_section)
        elif poll_started_status is None or (poll_started_status == TASK_STARTED and poll_report_status is None):
            with pytest.raises(AnalysisTimeoutExceeded):
                cape_class_instance.submit(file_content, cape_task, parent_section)
            correct_sec = ResultSection("Assemblyline task timeout exceeded.",
                                        body=f"The CAPE task {cape_task.id} took longer than the "
                                        f"Assemblyline's task timeout would allow.\nThis is usually due to "
                                        f"an issue on CAPE's machinery end. Contact the CAPE "
                                        f"administrator for details.")
            check_section_equality(parent_section.subsections[0], correct_sec)
            assert cape_task.id is None
        elif (poll_started_status == TASK_MISSING and poll_report_status is None) or (poll_started_status == TASK_STARTED and poll_report_status == TASK_MISSING):
            with pytest.raises(RecoverableError):
                cape_class_instance.submit(file_content, cape_task, parent_section)
            assert cape_task.id is None
        elif (poll_started_status == ANALYSIS_FAILED and poll_report_status is None) or (poll_report_status in [ANALYSIS_FAILED, PROCESSING_FAILED] and poll_started_status == TASK_STARTED):
            with pytest.raises(AnalysisFailed):
                cape_class_instance.submit(file_content, cape_task, parent_section)
        elif poll_report_status == "reboot":
            from requests import Session
            cape_class_instance.session = Session()
            with requests_mock.Mocker() as m:
                m.get(cape_task.reboot_task_url % task_id, status_code=404)
                cape_class_instance.submit(file_content, cape_task, parent_section, True)
                assert cape_task.id == task_id

                m.get(cape_task.reboot_task_url % task_id, status_code=200, json={"reboot_id": 2, "task_id": task_id})
                cape_class_instance.submit(file_content, cape_task, parent_section, True)
                assert cape_task.id == 2

        elif poll_started_status not in all_statuses or (poll_started_status and poll_report_status):
            cape_class_instance.submit(file_content, cape_task, parent_section)
            assert cape_task.id == task_id

    @staticmethod
    def test_stop(cape_class_instance):
        # Get that coverage!
        cape_class_instance.stop()
        assert True

    @staticmethod
    @pytest.mark.parametrize(
        "return_value",
        [
            None,
            {"id": 2},
            {"id": 1, "guest": {"status": "starting"}},
            {"id": 1, "task": {"status": "missing"}},
            {"id": 1, "errors": ["error"]},
            {"id": 1}
        ]
    )
    def test_poll_started(return_value, cape_class_instance, mocker):
        from cape.cape_main import CAPE, CapeTask
        from retrying import RetryError
        from cape.cape_main import TASK_MISSING, TASK_STARTED, TASK_STARTING

        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cape_task = CapeTask("blah", host_to_use)
        cape_task.id = 1

        # Mocking the time.sleep method that Retry uses, since decorators are loaded and immutable following module import
        with mocker.patch("time.sleep", side_effect=lambda _: None):
            # Mocking the CAPE.query_task method results since we only care about the output
            with mocker.patch.object(CAPE, 'query_task', return_value=return_value):
                if return_value is None:
                    test_result = cape_class_instance.poll_started(cape_task)
                    assert TASK_MISSING == test_result
                # If None is returned, _retry_on_none will cause retry to try again up until we hit the limit and
                # then a RetryError is raised
                elif return_value["id"] != cape_task.id:
                    with pytest.raises(RetryError):
                        cape_class_instance.poll_started(cape_task)
                elif return_value.get("guest", {}).get("status") == TASK_STARTING:
                    with pytest.raises(RetryError):
                        cape_class_instance.poll_started(cape_task)
                elif return_value.get("task", {}).get("status") == TASK_MISSING:
                    with pytest.raises(RetryError):
                        cape_class_instance.poll_started(cape_task)
                elif len(return_value.get("errors", [])) > 0:
                    with pytest.raises(RetryError):
                        cape_class_instance.poll_started(cape_task)
                else:
                    test_result = cape_class_instance.poll_started(cape_task)
                    assert TASK_STARTED == test_result

    @staticmethod
    @pytest.mark.parametrize(
        "return_value",
        [
            None,
            {},
            {"id": 2},
            {"id": 1, "status": "fail", "errors": []},
            {"id": 1, "status": "completed"},
            {"id": 1, "status": "reported"},
            {"id": 1, "status": "still_trucking"},
            {"id": 1, "status": "failed_analysis", "errors": ["blah"]},
            {"id": 1, "status": "failed_processing"},
        ]
    )
    def test_poll_report(return_value, cape_class_instance, mocker):
        from cape.cape_main import CAPE, TASK_MISSING, ANALYSIS_FAILED, TASK_COMPLETED, TASK_REPORTED, \
            CapeTask, ANALYSIS_ERRORS, PROCESSING_FAILED
        from retrying import RetryError
        from assemblyline_v4_service.common.result import ResultSection

        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cape_task = CapeTask("blah", host_to_use)
        cape_task.id = 1
        parent_section = ResultSection("blah")

        # Mocking the time.sleep method that Retry uses, since decorators are loaded and immutable following module import
        with mocker.patch("time.sleep", side_effect=lambda _: None):
            # Mocking the CAPE.query_task method results since we only care about the output
            with mocker.patch.object(CAPE, 'query_task', return_value=return_value):
                if return_value is None or return_value == {}:
                    test_result = cape_class_instance.poll_report(cape_task, parent_section)
                    assert TASK_MISSING == test_result
                elif return_value["id"] != cape_task.id:
                    with pytest.raises(RetryError):
                        cape_class_instance.poll_report(cape_task, parent_section)
                elif ANALYSIS_FAILED == return_value["status"]:
                    test_result = cape_class_instance.poll_report(cape_task, parent_section)
                    correct_result = ResultSection(ANALYSIS_ERRORS, body=return_value["errors"][0])
                    assert check_section_equality(parent_section.subsections[0], correct_result)
                    assert ANALYSIS_FAILED == test_result
                elif PROCESSING_FAILED == return_value["status"]:
                    test_result = cape_class_instance.poll_report(cape_task, parent_section)
                    correct_result = ResultSection(ANALYSIS_ERRORS, body="Processing has failed for task 1.")
                    assert check_section_equality(parent_section.subsections[0], correct_result)
                    assert PROCESSING_FAILED == test_result
                elif return_value["status"] == TASK_COMPLETED:
                    with pytest.raises(RetryError):
                        cape_class_instance.poll_report(cape_task, parent_section)
                elif return_value["status"] == TASK_REPORTED:
                    # Mocking the CAPE.query_report method results since we only care about the output
                    with mocker.patch.object(CAPE, 'query_report', return_value=return_value):
                        test_result = cape_class_instance.poll_report(cape_task, parent_section)
                        assert return_value["status"] == test_result
                else:
                    with pytest.raises(RetryError):
                        cape_class_instance.poll_report(cape_task, parent_section)

    @staticmethod
    def test_sha256_check(cape_class_instance, mocker):
        from requests import Session, exceptions, ConnectionError
        from cape.cape_main import CapeTimeoutException, CAPE, CapeTask

        sha256 = "blah"
        cape_class_instance.session = Session()
        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cape_task = CapeTask("blah", host_to_use, blah="blah")
        correct_rest_response = {"data": [{"id": 1}]}

        with requests_mock.Mocker() as m:
            m.get(cape_task.sha256_search_url % sha256, exc=exceptions.Timeout)
            with pytest.raises(CapeTimeoutException):
                cape_class_instance.sha256_check(sha256, cape_task)
            m.get(cape_task.sha256_search_url % sha256, exc=ConnectionError)
            with pytest.raises(Exception):
                cape_class_instance.sha256_check(sha256, cape_task)

            with mocker.patch('cape.cape_main.tasks_are_similar', return_value=True):
                m.get(cape_task.sha256_search_url % sha256, json=correct_rest_response, status_code=200)
                test_result = cape_class_instance.sha256_check(sha256, cape_task)
                assert test_result is True
                assert cape_task.id == 1

                m.get(cape_task.sha256_search_url % sha256, json=correct_rest_response, status_code=500)
                test_result = cape_class_instance.sha256_check(sha256, cape_task)
                assert test_result is False

    @staticmethod
    @pytest.mark.parametrize(
        "status_code, task_ids",
        [
            (200, None),
            (200, [1]),
            (404, [1]),
            (500, [1]),
            (None, None)
        ]
    )
    def test_submit_file(status_code, task_ids, cape_class_instance, mocker):
        mocker.patch('cape.cape_main.generate_random_words', return_value="blah")

        from requests import Session, exceptions, ConnectionError
        from cape.cape_main import CapeTimeoutException, CAPE, CapeTask
        from assemblyline.common.exceptions import RecoverableError

        # Prerequisites before we can mock query_machines response
        cape_class_instance.session = Session()

        file_content = b"submit me!"
        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cape_task = CapeTask("blah", host_to_use, blah="blah")

        correct_rest_response = {"data": {"task_ids": task_ids}}
        with requests_mock.Mocker() as m:
            if status_code is None and task_ids is None:
                with mocker.patch.object(CAPE, 'delete_task', return_value=True):
                    m.post(cape_task.submit_url, exc=exceptions.Timeout)
                    with pytest.raises(CapeTimeoutException):
                        cape_class_instance.submit_file(file_content, cape_task)
                    m.post(cape_task.submit_url, exc=ConnectionError)
                    with pytest.raises(Exception):
                        cape_class_instance.submit_file(file_content, cape_task)
            else:
                m.post(cape_task.submit_url, json=correct_rest_response, status_code=status_code)
                # IF the status code is 200, then we expect a dictionary
                if status_code == 200:
                    test_result = cape_class_instance.submit_file(file_content, cape_task)
                    if task_ids:
                        assert test_result == task_ids[0]
                    else:
                        assert test_result == 0

                # If the status code is not 200, then we expect an error or None
                elif status_code != 200:
                    if status_code == 500:
                        with pytest.raises(RecoverableError):
                            cape_class_instance.submit_file(file_content, cape_task)
                    else:
                        assert cape_class_instance.submit_file(file_content, cape_task) == 0

    @staticmethod
    @pytest.mark.parametrize(
        "task_id,fmt,status_code,headers,report_data",
        [
            (1, "json", 200, {"Content-Length": "0"}, {"a": "b"}),
            (1, "json", 200, {"Content-Length": "999999999999"}, {"a": "b"}),
            (1, "json", 404, {"Content-Length": "0"}, {"a": "b"}),
            (1, "json", 500, {"Content-Length": "0"}, {"a": "b"}),
            (1, "anything", 200, {"Content-Length": "0"}, {"a": "b"}),
            (1, "anything", 200, {"Content-Length": "0"}, None),
        ]
    )
    def test_query_report(task_id, fmt, status_code, headers, report_data, cape_class_instance, mocker):
        from cape.cape_main import CAPE, MissingCapeReportException, \
            CapeTimeoutException, CapeTask
        from requests import Session, exceptions, ConnectionError
        from json import dumps

        # Prerequisites before we can mock query_report response
        cape_class_instance.session = Session()

        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cape_task = CapeTask("blah", host_to_use, blah="blah")
        cape_task.id = task_id

        with requests_mock.Mocker() as m:
            with mocker.patch.object(CAPE, 'delete_task', return_value=True):
                if task_id is None and fmt is None and status_code is None and headers is None and report_data is None:
                    m.get(cape_task.query_report_url % task_id + fmt + '/zip/', exc=exceptions.Timeout)
                    with pytest.raises(CapeTimeoutException):
                        cape_class_instance.query_report(cape_task, "json")
                    m.get(cape_task.query_report_url % task_id + fmt + '/zip/', exc=ConnectionError)
                    with pytest.raises(Exception):
                        cape_class_instance.query_report(cape_task, "json")
                else:
                    m.get(cape_task.query_report_url % task_id + fmt + '/zip/', headers=headers,
                          json=report_data, status_code=status_code)
                    if status_code == 404:
                        with pytest.raises(MissingCapeReportException):
                            cape_class_instance.query_report(cape_task, fmt)
                    elif status_code != 200:
                        with pytest.raises(Exception):
                            cape_class_instance.query_report(cape_task, fmt)
                    else:
                        if report_data is None:
                            with pytest.raises(Exception):
                                cape_class_instance.query_report(cape_task, fmt)
                        else:
                            test_result = cape_class_instance.query_report(cape_task, fmt)
                            if status_code == 200:
                                correct_result = dumps(report_data).encode()
                                assert correct_result == test_result

    @staticmethod
    @pytest.mark.parametrize(
        "status_code,task_dict",
        [
            (200, None),
            (200, 1),
            (404, None),
            (500, None),
            (None, None)
        ]
    )
    def test_query_task(status_code, task_dict, cape_class_instance, mocker):
        from requests import Session, exceptions, ConnectionError
        from cape.cape_main import CapeTimeoutException, CAPE, TASK_MISSING, CapeTask

        # Prerequisites before we can mock query_machines response
        task_id = 1
        cape_class_instance.session = Session()
        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cape_task = CapeTask("blah", host_to_use, blah="blah")
        cape_task.id = task_id
        correct_rest_response = {"data": {"task": task_dict}}

        with requests_mock.Mocker() as m:
            if status_code is None and task_dict is None:
                m.get(cape_task.query_task_url % task_id, exc=exceptions.Timeout)
                with pytest.raises(CapeTimeoutException):
                    with mocker.patch.object(CAPE, 'delete_task', return_value=True):
                        cape_class_instance.query_task(cape_task)
                m.get(cape_task.query_task_url % task_id, exc=ConnectionError)
                with pytest.raises(Exception):
                    cape_class_instance.query_task(cape_task)
            else:
                m.get(cape_task.query_task_url % task_id, json=correct_rest_response,
                      status_code=status_code)
                test_result = cape_class_instance.query_task(cape_task)
                if status_code == 200:
                    if task_dict is None:
                        assert test_result == {"task": None}
                    elif task_dict:
                        assert test_result == {"task": 1}
                elif status_code == 404:
                    assert {"task": {"status": TASK_MISSING}, "id": task_id} == test_result
                elif status_code == 500:
                    assert test_result is None

    @staticmethod
    @pytest.mark.parametrize(
        "status_code,text",
        [
            (200, ""),
            (500, "{}"),
            (500, "{\"message\":\"The task is currently being processed, cannot delete\"}"),
            (404, ""),
            (None, None)
        ]
    )
    def test_delete_task(status_code, text, cape_class_instance, mocker):
        from cape.cape_main import CapeTimeoutException, CapeTask
        from requests import Session, exceptions, ConnectionError

        # Prerequisites before we can mock query_report response
        cape_class_instance.session = Session()

        task_id = 1
        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cape_task = CapeTask("blah", host_to_use, blah="blah")
        cape_task.id = task_id

        # Mocking the time.sleep method that Retry uses, since decorators are loaded and immutable following module import
        with mocker.patch("time.sleep", side_effect=lambda _: None):
            with requests_mock.Mocker() as m:
                if status_code is None and text is None:
                    # Confirm that the exceptions are raised and handled correctly
                    m.get(cape_task.delete_task_url % task_id, exc=exceptions.Timeout)
                    with pytest.raises(CapeTimeoutException):
                        cape_class_instance.delete_task(cape_task)
                    # Confirm that the exceptions are raised and handled correctly
                    m.get(cape_task.delete_task_url % task_id, exc=ConnectionError)
                    with pytest.raises(Exception):
                        cape_class_instance.delete_task(cape_task)
                else:
                    m.get(cape_task.delete_task_url % task_id, text=text, status_code=status_code)
                    if status_code == 500 and json.loads(text).get(
                            "message") == "The task is currently being processed, cannot delete":
                        with pytest.raises(Exception):
                            cape_class_instance.delete_task(cape_task)
                    elif status_code == 500:
                        cape_class_instance.delete_task(cape_task)
                        assert cape_task.id is not None
                    elif status_code != 200:
                        cape_class_instance.delete_task(cape_task)
                        assert cape_task.id is not None
                    else:
                        cape_class_instance.delete_task(cape_task)
                        assert cape_task.id is None

    @staticmethod
    @pytest.mark.parametrize("status_code", [200, 500, None])
    def test_query_machines(status_code, cape_class_instance):
        from requests import Session, exceptions, ConnectionError
        from cape.cape_main import CapeHostsUnavailable, CAPE_API_QUERY_MACHINES

        # Prerequisites before we can mock query_machines response
        query_machines_url = f"http://1.1.1.1:8000/apiv2/{CAPE_API_QUERY_MACHINES}"
        cape_class_instance.session = Session()
        cape_class_instance.connection_timeout_in_seconds = 30
        cape_class_instance.connection_attempts = 3

        correct_rest_response = {"data": [{"blah": "blahblah"}]}
        with requests_mock.Mocker() as m:
            if status_code is None:
                cape_class_instance.hosts = [{"ip": "1.1.1.1", "port": 8000, "auth_header": {"blah": "blah"}}]
                m.get(query_machines_url, exc=exceptions.Timeout)
                with pytest.raises(CapeHostsUnavailable):
                    cape_class_instance.query_machines()
                cape_class_instance.hosts = [{"ip": "1.1.1.1", "port": 8000, "auth_header": {"blah": "blah"}}]
                m.get(query_machines_url, exc=ConnectionError)
                with pytest.raises(CapeHostsUnavailable):
                    cape_class_instance.query_machines()
            else:
                cape_class_instance.hosts = [{"ip": "1.1.1.1", "port": 8000, "auth_header": {"blah": "blah"}}]
                m.get(query_machines_url, json=correct_rest_response, status_code=status_code)
                # IF the status code is 200, then we expect a dictionary
                if status_code == 200:
                    cape_class_instance.query_machines()
                    assert cape_class_instance.hosts[0]["machines"] == [{"blah": "blahblah"}]

                # If the status code is not 200, then we expect an error
                elif status_code != 200:
                    with pytest.raises(CapeHostsUnavailable):
                        cape_class_instance.query_machines()

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_check_powershell(sample, cape_class_instance):
        from assemblyline_v4_service.common.result import ResultSection
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest

        task_id = 1
        parent_section = ResultSection("blah")
        correct_subsection = ResultSection("PowerShell Activity")
        correct_subsection.set_body(json.dumps([{"original": "blah"}]))
        parent_section.add_subsection(correct_subsection)

        # Creating the required objects for execution
        service_task = ServiceTask(sample)
        task = Task(service_task)
        cape_class_instance._task = task
        cape_class_instance.request = ServiceRequest(task)
        cape_class_instance.artifact_list = []

        cape_class_instance.check_powershell(task_id, parent_section)
        assert cape_class_instance.artifact_list[0]["name"] == "1_powershell_logging.ps1"
        assert cape_class_instance.artifact_list[0]["description"] == 'Deobfuscated PowerShell script from CAPE analysis'
        assert cape_class_instance.artifact_list[0]["to_be_extracted"] == True

    @staticmethod
    @pytest.mark.parametrize(
        "machines",
        [
            [],
            [{"name": "blah", "platform": "blah", "ip": "blah"}],
            [{"name": "blah", "platform": "blah", "ip": "blah", "tags": ["blah", "blah"]}],
        ]
    )
    def test_report_machine_info(machines, cape_class_instance, mocker):
        from cape.cape_main import CapeTask
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT
        from assemblyline.common.str_utils import safe_str

        so = SandboxOntology()
        default_mm = so.analysis_metadata.machine_metadata.as_primitives()
        machine_name = "blah"
        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah", "machines": machines}
        cape_class_instance.hosts = [host_to_use]
        cape_task = CapeTask("blah", host_to_use, blah="blah")
        cape_task.report = {"info": {"machine": {"manager": "blah"}}}
        parent_section = ResultSection("blah")
        mocker.patch.object(cape_class_instance, "query_machines")

        machine_name_exists = False
        machine = None
        for machine in machines:
            if machine['name'] == machine_name:
                machine_name_exists = True
                break
        if machine_name_exists:
            correct_result_section = ResultSection("Machine Information")
            body = {
                'Name': str(machine['name']),
                'Manager': cape_task.report["info"]["machine"]["manager"],
                'Platform': str(machine['platform']),
                'IP': str(machine['ip']),
                'Tags': []
            }
            for tag in machine.get('tags', []):
                body['Tags'].append(safe_str(tag).replace('_', ' '))
            correct_result_section.set_body(json.dumps(body), BODY_FORMAT.KEY_VALUE)
            correct_result_section.add_tag('dynamic.operating_system.platform', 'Blah')
            cape_class_instance.report_machine_info(machine_name, cape_task, parent_section, so)
            assert check_section_equality(correct_result_section, parent_section.subsections[0])
            default_mm["ip"] = str(machine['ip'])
            default_mm["hypervisor"] = cape_task.report["info"]["machine"]["manager"]
            default_mm["hostname"] = str(machine['name'])
            default_mm["platform"] = "Blah"
            assert so.analysis_metadata.machine_metadata.as_primitives() == default_mm
        else:
            cape_class_instance.report_machine_info(machine_name, cape_task, parent_section, so)
            assert parent_section.subsections == []
            assert so.analysis_metadata.machine_metadata.as_primitives() == default_mm

    @staticmethod
    @pytest.mark.parametrize("machine_name, platform, expected_tags, expected_machine_metadata",
                             [("", "", [],
                               {}),
                              ("blah", "blah", [("dynamic.operating_system.platform", "Blah")],
                               {"platform": "Blah"}),
                              ("vmss-udev-win10x64", "windows",
                               [("dynamic.operating_system.platform", "Windows"),
                                ("dynamic.operating_system.processor", "x64"),
                                ("dynamic.operating_system.version", "10")],
                               {"platform": "Windows", "architecture": "x64", "version": "10"}),
                              ("vmss-udev-win7x86", "windows",
                               [("dynamic.operating_system.platform", "Windows"),
                                ("dynamic.operating_system.processor", "x86"),
                                ("dynamic.operating_system.version", "7")],
                               {"platform": "Windows", "architecture": "x86", "version": "7"}),
                              ("vmss-udev-ub1804x64", "linux",
                               [("dynamic.operating_system.platform", "Linux"),
                                ("dynamic.operating_system.processor", "x64"),
                                ("dynamic.operating_system.version", "1804")],
                               {"platform": "Linux", "architecture": "x64", "version": "1804"}), ])
    def test_add_operating_system_tags(
            machine_name, platform, expected_tags, expected_machine_metadata, cape_class_instance):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from assemblyline_v4_service.common.result import ResultSection

        so = SandboxOntology()
        default_mm = so.analysis_metadata.machine_metadata.as_primitives()
        for key, value in expected_machine_metadata.items():
            default_mm[key] = value
        expected_section = ResultSection("blah")
        for tag_name, tag_value in expected_tags:
            expected_section.add_tag(tag_name, tag_value)

        machine_section = ResultSection("blah")
        cape_class_instance._add_operating_system_tags(machine_name, platform, machine_section, so)
        assert check_section_equality(expected_section, machine_section)
        assert so.analysis_metadata.machine_metadata.as_primitives() == default_mm

    @staticmethod
    @pytest.mark.parametrize(
        "test_file_name, correct_file_name",
        [
            ("blah", "blah"),
            ("=?blah?=", "random_blah"),
            ("=?iso-8859-1?q?blah?=", "blah")
        ]
    )
    def test_decode_mime_encoded_file_name(test_file_name, correct_file_name, cape_class_instance, mocker):
        mocker.patch('cape.cape_main.generate_random_words', return_value="random_blah")
        cape_class_instance.file_name = test_file_name
        cape_class_instance._decode_mime_encoded_file_name()
        assert cape_class_instance.file_name == correct_file_name

    @staticmethod
    def test_remove_illegal_characters_from_file_name(cape_class_instance):
        from cape.cape_main import ILLEGAL_FILENAME_CHARS
        test_file_name = ''.join(ch for ch in ILLEGAL_FILENAME_CHARS) + "blah"
        correct_file_name = "blah"

        cape_class_instance.file_name = test_file_name
        cape_class_instance._remove_illegal_characters_from_file_name()
        assert cape_class_instance.file_name == correct_file_name

    @staticmethod
    @pytest.mark.parametrize(
        "file_type, test_file_name, correct_file_extension, correct_file_name",
        [
            ("blah", "blah", None, "blah"),
            ("document/office/unknown", "blah", None, "blah"),
            ("unknown", "blah.blah", None, "blah.blah"),
            ("unknown", "blah.bin", ".bin", "blah.bin"),
            ("code/html", "blah", ".html", "blah.html"),
            ("unknown", "blah.html", ".html", "blah.html"),
        ]
    )
    def test_assign_file_extension(
            file_type, test_file_name, correct_file_extension, correct_file_name, cape_class_instance,
            dummy_request_class):
        from assemblyline.common.identify_defaults import type_to_extension
        from cape.cape_main import SUPPORTED_EXTENSIONS
        kwargs = dict()
        is_bin = False

        cape_class_instance.file_name = test_file_name
        cape_class_instance.request = dummy_request_class()
        cape_class_instance.request.file_type = file_type

        original_ext = cape_class_instance.file_name.rsplit('.', 1)
        tag_extension = type_to_extension.get(file_type)
        if tag_extension is not None and 'unknown' not in file_type:
            file_ext = tag_extension
        elif len(original_ext) == 2:
            submitted_ext = original_ext[1]
            if submitted_ext not in SUPPORTED_EXTENSIONS:
                assert cape_class_instance._assign_file_extension(kwargs) == ""
                assert cape_class_instance.file_name == correct_file_name
                return
            else:
                if submitted_ext == "bin":
                    is_bin = True
                file_ext = '.' + submitted_ext
        else:
            assert cape_class_instance._assign_file_extension(kwargs) == ""
            assert cape_class_instance.file_name == correct_file_name
            return

        if file_ext:
            assert cape_class_instance._assign_file_extension(kwargs) == correct_file_extension
            assert cape_class_instance.file_name == correct_file_name
            if is_bin:
                assert kwargs == {"package": "bin"}
        else:
            assert cape_class_instance._assign_file_extension(kwargs) == ""
            assert cape_class_instance.file_name == correct_file_name

    @staticmethod
    def test_set_hosts_that_contain_image(cape_class_instance, mocker):
        mocker.patch.object(cape_class_instance, "_does_image_exist", return_value=True)
        cape_class_instance.hosts = [{"machines": None, "ip": "blah"}]
        relevant_images = {"blah": []}
        cape_class_instance._set_hosts_that_contain_image("blah", relevant_images)
        assert relevant_images["blah"] == ["blah"]

    @staticmethod
    @pytest.mark.parametrize(
        "guest_image, machines, allowed_images, correct_results",
        [
            ("blah", [], [], False),
            ("blah", [{"name": "blah"}], [], False),
            ("blah", [{"name": "blah"}], ["blah"], True),
            ("win7x86", [{"name": "ub1804x64"}], ["win7x86"], False),
        ]
    )
    def test_does_image_exist(guest_image, machines, allowed_images, correct_results, cape_class_instance):
        cape_class_instance.machines = {"machines": machines}
        cape_class_instance.machines = {"machines": machines}
        assert cape_class_instance._does_image_exist(guest_image, machines, allowed_images) == correct_results

    @staticmethod
    @pytest.mark.parametrize(
        "params",
        [
            {
                "analysis_timeout_in_seconds": 0,
                "dll_function": "",
                "arguments": "",
                "no_monitor": False,
                "custom_options": "",
                "clock": "",
                "force_sleepskip": False,
                "simulate_user": False,
                "deep_scan": False,
                "package": "",
                "dump_memory": False,
                "routing": "none",
            },
            {
                "analysis_timeout_in_seconds": 1,
                "dll_function": "",
                "arguments": "blah",
                "no_monitor": True,
                "custom_options": "blah",
                "clock": "blah",
                "force_sleepskip": True,
                "simulate_user": True,
                "deep_scan": True,
                "package": "doc",
                "dump_memory": True,
                "routing": "tor",
            }
        ]
    )
    def test_set_task_parameters(params, cape_class_instance, dummy_request_class, mocker):
        from cape.cape_main import CAPE, ANALYSIS_TIMEOUT
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch.object(CAPE, '_prepare_dll_submission', return_value=None)
        kwargs = dict()
        correct_task_options = []
        correct_kwargs = dict()

        timeout = params["analysis_timeout_in_seconds"]
        arguments = params["arguments"]
        no_monitor = params["no_monitor"]
        custom_options = params["custom_options"]
        correct_kwargs["clock"] = params["clock"]
        force_sleepskip = params["force_sleepskip"]
        simulate_user = params["simulate_user"]
        package = params["package"]
        dump_memory = params["dump_memory"]
        route = params["routing"]
        if timeout:
            correct_kwargs['enforce_timeout'] = True
            correct_kwargs['timeout'] = timeout
        else:
            correct_kwargs['enforce_timeout'] = False
            correct_kwargs['timeout'] = ANALYSIS_TIMEOUT
        if arguments:
            correct_task_options.append(f"arguments={arguments}")
        if no_monitor:
            correct_task_options.append("free=yes")
        if force_sleepskip:
            correct_task_options.append("force-sleepskip=1")
        if simulate_user not in [True, 'True']:
            correct_task_options.append("nohuman=true")

        deep_scan = params.pop("deep_scan")
        if deep_scan:
            correct_task_options.append("hollowshunter=all")
        if route:
            correct_kwargs["route"] = route

        correct_kwargs['options'] = ','.join(correct_task_options)
        if custom_options is not None:
            correct_kwargs['options'] += f",{custom_options}"
        if package:
            correct_kwargs["package"] = package

        parent_section = ResultSection("blah")

        cape_class_instance.request = dummy_request_class(**params)
        cape_class_instance.request.deep_scan = deep_scan
        cape_class_instance.request.file_type = "blah"
        cape_class_instance.config["machinery_supports_memory_dumps"] = True
        if dump_memory:
            correct_kwargs["memory"] = True
        cape_class_instance._set_task_parameters(kwargs, parent_section)
        assert kwargs == correct_kwargs

    @staticmethod
    @pytest.mark.parametrize(
        "params",
        [
            ({"dll_function": ""}),
            ({"dll_function": "blah"}),
            ({"dll_function": "blah,blah"}),
            ({"dll_function": ""}),
        ]
    )
    def test_prepare_dll_submission(params, cape_class_instance, dummy_request_class):
        kwargs = dict()
        correct_kwargs = dict()
        task_options = []
        correct_task_options = []

        dll_function = params["dll_function"]
        if dll_function:
            correct_task_options.append(f'function={dll_function}')
        correct_task_options.extend(["enable_multi=true", "use_export_name=true", "max_dll_exports=5"])

        cape_class_instance.request = dummy_request_class(**params)
        cape_class_instance._prepare_dll_submission(task_options)
        assert kwargs == correct_kwargs
        assert task_options == correct_task_options

    @staticmethod
    @pytest.mark.parametrize("zip_report", [None, "blah"])
    def test_generate_report(zip_report, cape_class_instance, mocker):
        from cape.cape_main import CAPE, CapeTask
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch.object(CAPE, 'query_report', return_value=zip_report)
        mocker.patch.object(CAPE, '_extract_console_output', return_value=None)
        mocker.patch.object(CAPE, '_extract_injected_exes', return_value=None)
        mocker.patch.object(CAPE, 'check_powershell', return_value=None)
        mocker.patch.object(CAPE, '_unpack_zip', return_value=None)

        so = SandboxOntology()
        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cape_task = CapeTask("blah", host_to_use)
        file_ext = "blah"
        parent_section = ResultSection("blah")

        cape_class_instance._generate_report(file_ext, cape_task, parent_section, so)
        # Get that coverage!
        assert True

    @staticmethod
    def test_unpack_zip(cape_class_instance, dummy_zip_class, mocker):
        from cape.cape_main import CAPE, CapeTask, MissingCapeReportException
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from assemblyline_v4_service.common.result import ResultSection

        so = SandboxOntology()
        zip_report = b"blah"
        file_ext = "blah"
        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cape_task = CapeTask("blah", host_to_use)
        parent_section = ResultSection("blah")

        mocker.patch.object(CAPE, "_add_zip_as_supplementary_file")
        mocker.patch.object(CAPE, "_add_json_as_supplementary_file", return_value=True)
        mocker.patch.object(CAPE, "_build_report")
        mocker.patch.object(CAPE, "_extract_hollowshunter")
        mocker.patch.object(CAPE, "_extract_artifacts")
        mocker.patch("cape.cape_main.ZipFile", return_value=dummy_zip_class())

        cape_class_instance._unpack_zip(zip_report, file_ext, cape_task, parent_section, so)
        assert True

        with mocker.patch.object(CAPE, "_add_json_as_supplementary_file", side_effect=MissingCapeReportException):
            cape_class_instance._unpack_zip(zip_report, file_ext, cape_task, parent_section, so)
            assert True

        # Exception test for _extract_console_output or _extract_hollowshunter or _extract_artifacts
        with mocker.patch.object(CAPE, "_extract_console_output", side_effect=Exception):
            mocker.patch.object(CAPE, "_add_json_as_supplementary_file", return_value=True)
            cape_class_instance._unpack_zip(zip_report, file_ext, cape_task, parent_section, so)
            assert True

    @staticmethod
    def test_add_zip_as_supplementary_file(cape_class_instance, dummy_request_class, mocker):
        from cape.cape_main import CapeTask
        zip_file_name = "blah"
        zip_report_path = f"/tmp/{zip_file_name}"
        zip_report = b"blah"
        cape_class_instance.request = dummy_request_class()
        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cape_class_instance.artifact_list = []
        cape_task = CapeTask("blah", host_to_use)
        cape_task.id = 1
        cape_class_instance._add_zip_as_supplementary_file(
            zip_file_name, zip_report_path, zip_report, cape_task)
        assert cape_class_instance.artifact_list[0]["path"] == zip_report_path
        assert cape_class_instance.artifact_list[0]["name"] == zip_file_name
        assert cape_class_instance.artifact_list[0][
            "description"] == "CAPE Sandbox analysis report archive (zip)"
        assert cape_class_instance.artifact_list[0]["to_be_extracted"] == False

        cape_class_instance.request.task.supplementary = []

        mocker.patch('builtins.open', side_effect=Exception())
        cape_class_instance._add_zip_as_supplementary_file(
            zip_file_name, zip_report_path, zip_report, cape_task)

        # Cleanup
        os.remove(zip_report_path)

    @staticmethod
    def test_add_json_as_supplementary_file(cape_class_instance, dummy_request_class, dummy_zip_class, mocker):
        from cape.cape_main import CapeTask, MissingCapeReportException

        json_file_name = "lite.json"
        json_report_path = f"{cape_class_instance.working_directory}/1/reports/{json_file_name}"
        zip_obj = dummy_zip_class()
        cape_class_instance.request = dummy_request_class()
        cape_class_instance.artifact_list = []
        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cape_task = CapeTask("blah", host_to_use)
        cape_task.id = 1
        report_json_path = cape_class_instance._add_json_as_supplementary_file(zip_obj, cape_task)
        assert cape_class_instance.artifact_list[0]["path"] == json_report_path
        assert cape_class_instance.artifact_list[0]["name"] == f"1_report.json"
        assert cape_class_instance.artifact_list[0]["description"] == "CAPE Sandbox report (json)"
        assert cape_class_instance.artifact_list[0]["to_be_extracted"] == False
        assert report_json_path == json_report_path

        cape_class_instance.artifact_list = []

        with mocker.patch.object(dummy_zip_class, 'namelist', return_value=[]):
            with pytest.raises(MissingCapeReportException):
                cape_class_instance._add_json_as_supplementary_file(zip_obj, cape_task)

        mocker.patch.object(dummy_zip_class, 'namelist', side_effect=Exception())
        report_json_path = cape_class_instance._add_json_as_supplementary_file(zip_obj, cape_task)
        assert cape_class_instance.artifact_list == []
        assert report_json_path == ""

    @staticmethod
    @pytest.mark.parametrize(
        "report_info",
        [
            {},
            {"info": {"machine": {"name": "blah"}}}
        ]
    )
    def test_build_report(report_info, cape_class_instance, dummy_json_doc_class_instance, mocker):
        from cape.cape_main import CAPE, CapeProcessingException, CapeTask
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from sys import getrecursionlimit
        from json import JSONDecodeError
        from assemblyline.common.exceptions import RecoverableError
        from assemblyline_v4_service.common.result import ResultSection

        so = SandboxOntology()
        report_json_path = "blah"
        file_ext = "blah"
        report_json = report_info

        mocker.patch("builtins.open")
        mocker.patch("cape.cape_main.loads", return_value=report_json)
        mocker.patch.object(CAPE, "report_machine_info")
        mocker.patch("cape.cape_main.generate_al_result", return_value={})
        mocker.patch.object(CAPE, "delete_task")

        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cape_task = CapeTask("blah", host_to_use, blah="blah")
        cape_task.id = 1

        cape_class_instance.query_report_url = "%s"

        parent_section = ResultSection("blah")
        results = cape_class_instance._build_report(report_json_path, file_ext, cape_task, parent_section, so)

        assert getrecursionlimit() == int(cape_class_instance.config["recursion_limit"])
        assert cape_task.report == report_info
        assert results == {}

        # Exception tests for generate_al_result
        mocker.patch("cape.cape_main.generate_al_result", side_effect=RecoverableError("blah"))
        with pytest.raises(RecoverableError):
            _ = cape_class_instance._build_report(report_json_path, file_ext, cape_task, parent_section, so)

        mocker.patch("cape.cape_main.generate_al_result", side_effect=CapeProcessingException("blah"))
        with pytest.raises(CapeProcessingException):
            _ = cape_class_instance._build_report(report_json_path, file_ext, cape_task, parent_section, so)

        mocker.patch("cape.cape_main.generate_al_result", side_effect=Exception("blah"))
        with pytest.raises(Exception):
            _ = cape_class_instance._build_report(report_json_path, file_ext, cape_task, parent_section, so)

        # Exception tests for json.loads
        mocker.patch("cape.cape_main.loads", side_effect=JSONDecodeError("blah", dummy_json_doc_class_instance, 1))
        with pytest.raises(JSONDecodeError):
            _ = cape_class_instance._build_report(report_json_path, file_ext, cape_task, parent_section, so)

        mocker.patch("cape.cape_main.loads", side_effect=Exception("blah"))
        with pytest.raises(Exception):
            _ = cape_class_instance._build_report(report_json_path, file_ext, cape_task, parent_section, so)

    @staticmethod
    def test_extract_console_output(cape_class_instance, dummy_request_class, mocker):
        mocker.patch('os.path.exists', return_value=True)
        cape_class_instance.request = dummy_request_class()
        cape_class_instance.artifact_list = []
        task_id = 1
        cape_class_instance._extract_console_output(task_id)
        assert cape_class_instance.artifact_list[0]["path"] == "/tmp/1_console_output.txt"
        assert cape_class_instance.artifact_list[0]["name"] == "1_console_output.txt"
        assert cape_class_instance.artifact_list[0]["description"] == "Console Output Observed"
        assert not cape_class_instance.artifact_list[0]["to_be_extracted"]

    @staticmethod
    def test_extract_injected_exes(cape_class_instance, dummy_request_class, mocker):
        mocker.patch('os.listdir', return_value=["1_injected_memory_0.exe"])
        mocker.patch('os.path.isfile', return_value=True)
        cape_class_instance.request = dummy_request_class()
        cape_class_instance.artifact_list = []
        task_id = 1
        cape_class_instance._extract_injected_exes(task_id)
        assert cape_class_instance.artifact_list[0]["path"] == "/tmp/1_injected_memory_0.exe"
        assert cape_class_instance.artifact_list[0]["name"] == "/tmp/1_injected_memory_0.exe"
        assert cape_class_instance.artifact_list[0]["description"] == "Injected executable was found written to memory"
        assert cape_class_instance.artifact_list[0]["to_be_extracted"]

    @staticmethod
    def test_extract_artifacts(cape_class_instance, dummy_request_class, dummy_zip_class, dummy_zip_member_class, mocker):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from assemblyline_v4_service.common.result import ResultSection, ResultImageSection
        default_so = SandboxOntology()

        parent_section = ResultSection("blah")
        correct_artifact_list = []
        zip_obj = dummy_zip_class()
        [zip_obj.members.append(dummy_zip_member_class(f, 1)) for f in zip_obj.get_artifacts()]
        mocker.patch.object(cape_class_instance.identify, "fileinfo", return_value={"type": "unknown", "mime": "application/octet-stream", "magic": "SQLite Rollback Journal"})
        task_id = 1
        cape_class_instance.artifact_list = []
        cape_class_instance.request = dummy_request_class()
        cape_class_instance.request.deep_scan = True
        cape_class_instance.config["extract_cape_dumps"] = True
        correct_image_section = ResultImageSection(
            dummy_request_class,
            f"Screenshots taken during Task {task_id}",
        )

        correct_image_section.add_image(
            f"{cape_class_instance.working_directory}/{task_id}/shots/0001.jpg", f"{task_id}_shots/0001.jpg", "Screenshot captured during analysis"
        )
        correct_image_section.add_image(
            f"{cape_class_instance.working_directory}/{task_id}/shots/0005.jpg", f"{task_id}_shots/0005.jpg", "Screenshot captured during analysis"
        )
        correct_image_section.add_image(
            f"{cape_class_instance.working_directory}/{task_id}/shots/0010.jpg", f"{task_id}_shots/0010.jpg", "Screenshot captured during analysis"
        )
        correct_artifact_list.append({
            "path": f"{cape_class_instance.working_directory}/{task_id}/CAPE/ohmy.exe",
            "name": f"{task_id}_3_CAPE/ohmy.exe",
            "description": "Memory Dump",
            "to_be_extracted": True
        })
        correct_artifact_list.append({
            "path": f"{cape_class_instance.working_directory}/{task_id}/sum.pcap",
            "name": f"{task_id}_sum.pcap",
            "description": "TCPDUMP captured during analysis",
            "to_be_extracted": True
        })
        correct_artifact_list.append({
            "path": f"{cape_class_instance.working_directory}/{task_id}/dump.pcap",
            "name": f"{task_id}_dump.pcap",
            "description": "TCPDUMP captured during analysis",
            "to_be_extracted": True
        })

        cape_artifact_pids = {"ohmy.exe": 3}
        cape_class_instance._extract_artifacts(zip_obj, task_id, cape_artifact_pids, parent_section, default_so)

        all_files = True
        assert len(cape_class_instance.artifact_list) == len(correct_artifact_list)
        for f in cape_class_instance.artifact_list:
            if f not in correct_artifact_list:
                print(f"Missing {f}")
                all_files = False
                break
        assert all_files

        assert check_section_equality(parent_section.subsections[0], correct_image_section)

    @staticmethod
    def test_extract_hollowshunter(cape_class_instance, dummy_request_class, dummy_zip_class):
        cape_class_instance.request = dummy_request_class()
        zip_obj = dummy_zip_class()
        task_id = 1
        cape_class_instance.artifact_list = []
        cape_class_instance._extract_hollowshunter(zip_obj, task_id)

        assert cape_class_instance.artifact_list[0] == {
            "path": f"{cape_class_instance.working_directory}/{task_id}/hollowshunter/hh_process_123_dump_report.json",
            'name': f'{task_id}_hollowshunter/hh_process_123_dump_report.json',
            "description": 'HollowsHunter report (json)', "to_be_extracted": False}
        assert cape_class_instance.artifact_list[1] == {
            "path": f"{cape_class_instance.working_directory}/{task_id}/hollowshunter/hh_process_123_scan_report.json",
            'name': f'{task_id}_hollowshunter/hh_process_123_scan_report.json',
            "description": 'HollowsHunter report (json)', "to_be_extracted": False}
        assert cape_class_instance.artifact_list[2] == {
            "path": f"{cape_class_instance.working_directory}/{task_id}/hollowshunter/hh_process_123_blah.exe",
            'name': f'{task_id}_hollowshunter/hh_process_123_blah.exe', "description": 'Memory Dump',
            "to_be_extracted": True}
        assert cape_class_instance.artifact_list[3] == {
            "path": f"{cape_class_instance.working_directory}/{task_id}/hollowshunter/hh_process_123_blah.shc",
            'name': f'{task_id}_hollowshunter/hh_process_123_blah.shc', "description": 'Memory Dump',
            "to_be_extracted": True}
        assert cape_class_instance.artifact_list[4] == {
            "path": f"{cape_class_instance.working_directory}/{task_id}/hollowshunter/hh_process_123_blah.dll",
            'name': f'{task_id}_hollowshunter/hh_process_123_blah.dll', "description": 'Memory Dump',
            "to_be_extracted": True}

    @staticmethod
    @pytest.mark.parametrize(
        "param_exists, param, correct_value",
        [
            (True, "blah", "blah"),
            (False, "blah", None)
        ]
    )
    def test_safely_get_param(param_exists, param, correct_value, cape_class_instance, dummy_request_class):
        if param_exists:
            cape_class_instance.request = dummy_request_class(**{param: "blah"})
        else:
            cape_class_instance.request = dummy_request_class()
        assert cape_class_instance._safely_get_param(param) == correct_value

    @staticmethod
    @pytest.mark.parametrize("file_type, possible_images, auto_architecture, all_relevant, correct_result",
                             [("blah", [], {}, False, []),
                              ("blah", ["blah"], {}, False, []),
                              ("blah", ["winblahx64"], {}, False, ["winblahx64"]),
                              ("executable/linux/elf32", [], {}, False, []),
                              ("executable/linux/elf32", ["ubblahx86"], {}, False, ["ubblahx86"]),
                              ("executable/linux/elf32", ["ubblahx64"], {"ub": {"x86": ["ubblahx64"]}}, False, ["ubblahx64"]),
                              ("executable/windows/pe32", ["winblahx86"], {}, False, ["winblahx86"]),
                              ("executable/windows/pe32", ["winblahx86", "winblahblahx86"], {"win": {"x86": ["winblahblahx86"]}}, False, ["winblahblahx86"]),
                              ("executable/windows/pe64", ["winblahx64", "winblahblahx64"], {"win": {"x64": ["winblahx64"]}}, False, ["winblahx64"]),
                              ("executable/windows/pe64", ["winblahx64", "winblahblahx64"], {"win": {"x64": ["winblahx64"]}}, True, ["winblahx64", "winblahblahx64"]),
                              ("executable/windows/pe64", ["winblahx64", "winblahblahx64"], {}, True, ["winblahx64", "winblahblahx64"]),
                              ("executable/linux/elf64", ["winblahx64", "winblahblahx64"], {}, True, []),
                              ("executable/linux/elf64", ["winblahx64", "winblahblahx64", "ub1804x64"], {}, True, ["ub1804x64"]),
                              ("executable/windows/pe64", ["winblahx64", "winblahblahx64", "ub1804x64"], {}, True, ["winblahx64", "winblahblahx64"]), ])
    def test_determine_relevant_images(
            file_type, possible_images, correct_result, auto_architecture, all_relevant, cape_class_instance):
        assert cape_class_instance._determine_relevant_images(
            file_type, possible_images, auto_architecture, all_relevant) == correct_result

    @staticmethod
    @pytest.mark.parametrize(
        "machines, allowed_images, correct_result",
        [
            ([], [], []),
            ([], ["blah"], []),
            ([{"name": "blah"}], [], []),
            ([{"name": "blah"}], ["nope"], []),
            ([{"name": "blah"}], ["blah"], ["blah"]),
            ([{"name": "blah"}, {"name": "blah2"}, {"name": "blah"}], ["blah1", "blah2", "blah3"], ["blah2"]),
        ]
    )
    def test_get_available_images(machines, allowed_images, correct_result, cape_class_instance):
        assert cape_class_instance._get_available_images(machines, allowed_images) == correct_result

    @staticmethod
    @pytest.mark.parametrize(
        "machine_requested, hosts, correct_result, correct_body",
        [("", [{"machines": []}],
          (False, False),
          None),
         ("", [{"machines": []}],
          (False, False),
          None),
         ("True", [{"machines": []}],
          (True, False),
          'The requested machine \'True\' is currently unavailable.\nGeneral Information:\nAt the moment, the current machine options for this CAPE deployment include [].'),
         ("True", [{"machines": [{"name": "True"}]}],
          (True, True),
          None),
         ("True:True", [{"machines": [{"name": "True"}]}],
          (True, True),
          None),
         ("True:True", [{"ip": "True", "machines": [{"name": "True"}]},
                        {"ip": "True", "machines": []}],
          (True, True),
          None),
         ("flag", [{"ip": "True", "machines": [{"name": "True"}]},
                   {"ip": "True", "machines": []}],
          (True, True),
          None), ])
    def test_handle_specific_machine(
            machine_requested, hosts, correct_result, correct_body, cape_class_instance, dummy_result_class_instance,
            mocker):
        from cape.cape_main import CAPE
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch.object(CAPE, "_safely_get_param", return_value=machine_requested)
        kwargs = dict()
        cape_class_instance.hosts = hosts
        cape_class_instance.file_res = dummy_result_class_instance
        if machine_requested == "flag":
            with pytest.raises(ValueError):
                cape_class_instance._handle_specific_machine(kwargs)
            return

        assert cape_class_instance._handle_specific_machine(kwargs) == correct_result
        if correct_body:
            correct_result_section = ResultSection(title_text='Requested Machine Does Not Exist')
            correct_result_section.set_body(correct_body)
            assert check_section_equality(cape_class_instance.file_res.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "platform_requested, expected_return, expected_result_section",
        [("blah", (True, {"blah": []}),
          'The requested platform \'blah\' is currently unavailable.\nGeneral Information:\nAt the moment, the current platform options for this CAPE deployment include [\'linux\', \'windows\'].'),
         ("none", (False, {}),
          None),
         ("windows", (True, {'windows': ['blah']}),
          None),
         ("linux", (True, {'linux': ['blah']}),
          None), ])
    def test_handle_specific_platform(
            platform_requested, expected_return, expected_result_section, cape_class_instance,
            dummy_result_class_instance, mocker):
        from cape.cape_main import CAPE
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch.object(CAPE, "_safely_get_param", return_value=platform_requested)
        kwargs = dict()
        cape_class_instance.hosts = [{"ip": "blah", "machines": [{"platform": "windows"}, {"platform": "linux"}]}]
        cape_class_instance.file_res = dummy_result_class_instance
        assert cape_class_instance._handle_specific_platform(kwargs) == expected_return
        if expected_result_section:
            correct_result_section = ResultSection(title_text='Requested Platform Does Not Exist')
            correct_result_section.set_body(expected_result_section)
            assert check_section_equality(cape_class_instance.file_res.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "image_requested, image_exists, relevant_images, allowed_images, correct_result, correct_body",
        [(False, False, [],
          [],
          (False, {}),
          None),
         (False, True, [],
          [],
          (False, {}),
          None),
         ("blah", False, [],
          [],
          (True, {}),
          'The requested image \'blah\' is currently unavailable.\nGeneral Information:\nAt the moment, the current image options for this CAPE deployment include [].'),
         ("blah", True, [],
          [],
          (True, {"blah": ["blah"]}),
          None),
         ("auto", False, [],
          [],
          (True, {}),
          'The requested image \'auto\' is currently unavailable.\nGeneral Information:\nAt the moment, the current image options for this CAPE deployment include [].'),
         ("auto", False, ["blah"],
          [],
          (True, {}),
          'The requested image \'auto\' is currently unavailable.\nGeneral Information:\nAt the moment, the current image options for this CAPE deployment include [].'),
         ("auto", True, ["blah"],
          [],
          (True, {"blah": ["blah"]}),
          None),
         ("all", True, [],
          ["blah"],
          (True, {"blah": ["blah"]}),
          None),
         ("all", False, [],
          [],
          (True, {}),
          'The requested image \'all\' is currently unavailable.\nGeneral Information:\nAt the moment, the current image options for this CAPE deployment include [].'), ])
    def test_handle_specific_image(
            image_requested, image_exists, relevant_images, allowed_images, correct_result, correct_body,
            cape_class_instance, dummy_request_class, dummy_result_class_instance, mocker):
        from cape.cape_main import CAPE
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch.object(CAPE, "_safely_get_param", return_value=image_requested)
        mocker.patch.object(CAPE, "_does_image_exist", return_value=image_exists)
        mocker.patch.object(CAPE, "_determine_relevant_images", return_value=relevant_images)
        mocker.patch.object(CAPE, "_get_available_images", return_value=[])
        cape_class_instance.request = dummy_request_class()
        cape_class_instance.request.file_type = None
        cape_class_instance.file_res = dummy_result_class_instance
        cape_class_instance.hosts = [{"machines": [], "ip": "blah"}]
        cape_class_instance.allowed_images = allowed_images
        assert cape_class_instance._handle_specific_image() == correct_result
        if correct_body:
            correct_result_section = ResultSection(title_text='Requested Image Does Not Exist')
            correct_result_section.set_body(correct_body)
            assert check_section_equality(cape_class_instance.file_res.sections[0], correct_result_section)

    @staticmethod
    def test_determine_host_to_use(cape_class_instance):
        from cape.cape_main import CAPE_API_QUERY_HOST, CapeVMBusyException
        from requests import Session, exceptions, ConnectionError
        cape_class_instance.session = Session()
        hosts = [
            {"ip": "1.1.1.1", "port": 1111, "auth_header": {"blah": "blah"}},
            {"ip": "2.2.2.2", "port": 2222, "auth_header": {"blah": "blah"}},
            {"ip": "3.3.3.3", "port": 3333, "auth_header": {"blah": "blah"}}
        ]
        with requests_mock.Mocker() as m:
            for host in hosts:
                host_status_url = f"http://{host['ip']}:{host['port']}/apiv2/{CAPE_API_QUERY_HOST}"
                m.get(host_status_url, json={"data": {"tasks": {"pending": 1}}})
            test_result = cape_class_instance._determine_host_to_use(hosts)
            assert any(host == test_result for host in hosts)
            for key, val in [("exc", exceptions.Timeout), ("exc", ConnectionError), ("status_code", 404)]:
                for host in hosts:
                    host_status_url = f"http://{host['ip']}:{host['port']}/apiv2/{CAPE_API_QUERY_HOST}"
                    if key == "exc":
                        m.get(host_status_url, exc=val)
                    elif key == "status_code":
                        m.get(host_status_url, status_code=404)
                with pytest.raises(CapeVMBusyException):
                    cape_class_instance._determine_host_to_use(hosts)

    @staticmethod
    def test_is_invalid_analysis_timeout(cape_class_instance, dummy_request_class):
        from assemblyline_v4_service.common.result import ResultSection
        cape_class_instance.request = dummy_request_class(analysis_timeout_in_seconds=150)
        parent_section = ResultSection("blah")
        assert cape_class_instance._is_invalid_analysis_timeout(parent_section) is False

        parent_section = ResultSection("blah")
        correct_subsection = ResultSection("Invalid Analysis Timeout Requested",
                                           body="The analysis timeout requested was 900, which exceeds the time that "
                                           "Assemblyline will run the service (800). Choose an analysis timeout "
                                           "value < 800 and submit the file again.")
        cape_class_instance.request = dummy_request_class(analysis_timeout_in_seconds=900)
        assert cape_class_instance._is_invalid_analysis_timeout(parent_section) is True
        assert check_section_equality(correct_subsection, parent_section.subsections[0])
        # Reboot test
        cape_class_instance.request = dummy_request_class(analysis_timeout_in_seconds=150)
        assert cape_class_instance._is_invalid_analysis_timeout(parent_section, True) is False

    @staticmethod
    @pytest.mark.parametrize(
        "title_heur_tuples, correct_section_heur_map",
        [
            ([("blah1", 1), ("blah2", 2)], {'blah1': 1, 'blah2': 2}),
            ([("blah1", 1), ("blah1", 2)], {'blah1': 1}),
            ([("blah1", 1), ("blah2", 2), ("blah3", 3)], {'blah1': 1, 'blah2': 2, 'blah3': 3}),
        ]
    )
    def test_get_subsection_heuristic_map(title_heur_tuples, correct_section_heur_map, cape_class_instance):
        from assemblyline_v4_service.common.result import ResultSection
        subsections = []
        for title, heur_id in title_heur_tuples:
            subsection = ResultSection(title)
            subsection.set_heuristic(heur_id)
            if title == "blah3":
                subsections[0].add_subsection(subsection)
            else:
                subsections.append(subsection)
        actual_section_heur_map = {}
        cape_class_instance._get_subsection_heuristic_map(subsections, actual_section_heur_map)
        assert actual_section_heur_map == correct_section_heur_map
        if len(correct_section_heur_map) == 1:
            assert subsections[1].heuristic is None

    @staticmethod
    def test_determine_if_reboot_required(cape_class_instance, dummy_request_class):
        from assemblyline_v4_service.common.result import ResultSection
        parent_section = ResultSection("blah")
        assert cape_class_instance._determine_if_reboot_required(parent_section) is False

        cape_class_instance.request = dummy_request_class(reboot=True)
        assert cape_class_instance._determine_if_reboot_required(parent_section) is True

        cape_class_instance.request = dummy_request_class(reboot=False)
        for sig, result in [("persistence_autorun", True), ("creates_service", True), ("blah", False)]:
            parent_section = ResultSection("blah")
            signature_section = ResultSection("Signatures")
            signature_subsection = ResultSection(sig)
            signature_section.add_subsection(signature_subsection)
            parent_section.add_subsection(signature_section)
            assert cape_class_instance._determine_if_reboot_required(parent_section) is result

    @staticmethod
    def test_cleanup_leftovers(cape_class_instance):
        temp_dir = "/tmp"
        number_of_files_in_tmp_pre_call = len(os.listdir(temp_dir))
        with open("/tmp/blah_console_output.txt", "w") as f:
            f.write("blah")
        with open("/tmp/blah_injected_memory_blah.exe", "w") as f:
            f.write("blah")
        number_of_files_in_tmp_post_write = len(os.listdir(temp_dir))
        assert number_of_files_in_tmp_post_write == number_of_files_in_tmp_pre_call + 2
        cape_class_instance._cleanup_leftovers()
        number_of_files_in_tmp_post_call = len(os.listdir(temp_dir))
        assert number_of_files_in_tmp_post_call == number_of_files_in_tmp_pre_call

    @staticmethod
    @pytest.mark.parametrize(
        "name, hosts, expected_result",
        [
            ("blah", [{"machines": []}], None),
            ("blah", [{"machines": [{"name": "blah"}]}], {"name": "blah"}),
            ("blah", [{"machines": [{"name": "nah"}]}], None),
        ]
    )
    def test_get_machine_by_name(name, hosts, expected_result, cape_class_instance):
        cape_class_instance.hosts = hosts
        test_result = cape_class_instance._get_machine_by_name(name)
        assert test_result == expected_result
