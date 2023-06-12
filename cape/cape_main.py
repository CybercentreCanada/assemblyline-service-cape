import os
from email.header import decode_header
from json import JSONDecodeError, loads
from math import ceil
from random import choice, random
from re import compile, match
from sys import maxsize, setrecursionlimit
from tempfile import SpooledTemporaryFile
from threading import Thread
from time import sleep
from typing import Any, Dict, List, Optional, Set, Tuple
from zipfile import ZipFile

import requests
from assemblyline.common.exceptions import RecoverableError
from assemblyline.common.forge import get_identify
from assemblyline.common.identify_defaults import magic_patterns, trusted_mimes, type_to_extension
from assemblyline.common.str_utils import safe_str
from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults, attach_dynamic_ontology
from assemblyline_service_utilities.common.tag_helper import add_tag
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultImageSection,
    ResultKeyValueSection,
    ResultSection,
    ResultTextSection,
)
from cape.cape_result import (
    ANALYSIS_ERRORS,
    GUEST_CANNOT_REACH_HOST,
    LINUX_IMAGE_PREFIX,
    MACHINE_NAME_REGEX,
    SIGNATURES_SECTION_TITLE,
    SUPPORTED_EXTENSIONS,
    WINDOWS_IMAGE_PREFIX,
    convert_processtree_id_to_tree_id,
    generate_al_result,
    x64_IMAGE_SUFFIX,
    x86_IMAGE_SUFFIX,
)
from cape.safe_process_tree_leaf_hashes import SAFE_PROCESS_TREE_LEAF_HASHES
from pefile import PE, PEFormatError
from retrying import RetryError, retry
from SetSimilaritySearch import SearchIndex

APIv2_BASE_ENDPOINT = "apiv2"

HOLLOWSHUNTER_REPORT_REGEX = (
    r"hollowshunter\/hh_process_[0-9]{3,}_(dump|scan)_report\.json$"
)
HOLLOWSHUNTER_DUMP_REGEX = r"hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*(\.*[a-zA-Z0-9]+)+\.(exe|shc|dll)$"
INJECTED_EXE_REGEX = r"^\/tmp\/%s_injected_memory_[0-9]{1,2}\.exe$"

CAPE_API_SUBMIT = "tasks/create/file/"
CAPE_API_QUERY_TASK = "tasks/view/%s/"
CAPE_API_DELETE_TASK = "tasks/delete/%s/"
CAPE_API_QUERY_REPORT = "tasks/get/report/%s/"
CAPE_API_QUERY_MACHINES = "machines/list/"
CAPE_API_QUERY_HOST = "cuckoo/status/"
CAPE_API_REBOOT_TASK = "tasks/reboot/%s/"
CAPE_API_SHA256_SEARCH = "tasks/search/sha256/%s/"

CAPE_POLL_DELAY = 5
GUEST_VM_START_TIMEOUT = 360  # Give the VM at least 6 minutes to start up
REPORT_GENERATION_TIMEOUT = (
    420  # Give the analysis at least 7 minutes to generate the report
)
ANALYSIS_TIMEOUT = 150
DEFAULT_REST_TIMEOUT = 120
DEFAULT_CONNECTION_TIMEOUT = 120
DEFAULT_CONNECTION_ATTEMPTS = 3

RELEVANT_IMAGE_TAG = "auto"
ALL_IMAGES_TAG = "all"
ALL_RELEVANT_IMAGES_TAG = "auto_all"
NO_PLATFORM = "none"
WINDOWS_PLATFORM = "windows"
LINUX_PLATFORM = "linux"


# TODO: RECOGNIZED_TYPES does not exist anymore and there a no static ways we can generate this because it can be
#       modified on the fly by administrators. I will fake a RECOGNIZED_TYPES variable but this code should be removed
#       and the checks to determine the architecture should be self contained in the _determine_relevant_images function
RECOGNIZED_TYPES = set(trusted_mimes.values())
RECOGNIZED_TYPES = RECOGNIZED_TYPES.union(set([x["al_type"] for x in magic_patterns]))

LINUX_x86_FILES = [
    file_type
    for file_type in RECOGNIZED_TYPES
    if all(val in file_type for val in ["linux", "32"])
]
LINUX_x64_FILES = [
    file_type
    for file_type in RECOGNIZED_TYPES
    if all(val in file_type for val in ["linux", "64"])
]
WINDOWS_x86_FILES = [
    file_type
    for file_type in RECOGNIZED_TYPES
    if all(val in file_type for val in ["windows", "32"])
]

ILLEGAL_FILENAME_CHARS = set('<>:"/\\|?*')

# Enumeration for statuses
TASK_MISSING = "missing"
TASK_STOPPED = "stopped"
INVALID_JSON = "invalid_json_report"
REPORT_TOO_BIG = "report_too_big"
SERVICE_CONTAINER_DISCONNECTED = "service_container_disconnected"
MISSING_REPORT = "missing_report"
TASK_STARTED = "started"
TASK_STARTING = "starting"
TASK_COMPLETED = "completed"
TASK_REPORTED = "reported"
ANALYSIS_FAILED = "failed_analysis"
PROCESSING_FAILED = "failed_processing"

MACHINE_INFORMATION_SECTION_TITLE = "Machine Information"

PE_INDICATORS = [b"MZ", b"This program cannot be run in DOS mode"]

DEFAULT_TOKEN_KEY = "Token"

CONNECTION_ERRORS = ["RemoteDisconnected", "ConnectionResetError"]
# Ontology Result Constants
SANDBOX_NAME = "CAPE Sandbox"
SERVICE_NAME = "CAPE"


class MissingCapeReportException(Exception):
    """Exception class for missing reports"""

    pass


class CapeProcessingException(Exception):
    """Exception class for processing errors"""

    pass


class CapeVMBusyException(Exception):
    """Exception class for busy VMs"""

    pass


class InvalidCapeRequest(Exception):
    """Exception class for when every CAPE host's REST API returns a 200 status code with errors"""

    pass


class AnalysisFailed(Exception):
    """Exception class for when CAPE is not able to analyze the task"""

    pass


def _exclude_invalid_req_ex(ex) -> bool:
    """Use this with some of the @retry decorators to only retry if the exception
    ISN'T a InvalidCapeRequest"""
    return not isinstance(ex, InvalidCapeRequest)


def _retry_on_none(result) -> bool:
    return result is None


"""
    The following parameters are available for customization before sending a task to the CAPE server:

    * ``file`` *(required)* - sample file (multipart encoded file content)
    * ``package`` *(optional)* - analysis package to be used for the analysis
    * ``timeout`` *(optional)* *(int)* - analysis timeout (in seconds)
    * ``options`` *(optional)* - options to pass to the analysis package
    * ``custom`` *(optional)* - custom string to pass over the analysis and the processing/reporting modules
    * ``memory`` *(optional)* - enable the creation of a full memory dump of the analysis machine
    * ``enforce_timeout`` *(optional)* - enable to enforce the execution for the full timeout value
"""


class CapeTask(dict):
    def __init__(self, sample: str, host_details: Dict[str, Any], **kwargs) -> None:
        super(CapeTask, self).__init__()
        self.file = sample
        self.update(kwargs)
        self.id: Optional[int] = None
        self.report: Optional[Dict[str, Dict]] = None
        self.errors: List[str] = []
        self.auth_header = host_details["auth_header"]
        self.base_url = (
            f"http://{host_details['ip']}:{host_details['port']}/{APIv2_BASE_ENDPOINT}"
        )
        self.submit_url = f"{self.base_url}/{CAPE_API_SUBMIT}"
        self.query_task_url = f"{self.base_url}/{CAPE_API_QUERY_TASK}"
        self.delete_task_url = f"{self.base_url}/{CAPE_API_DELETE_TASK}"
        self.query_report_url = f"{self.base_url}/{CAPE_API_QUERY_REPORT}"
        self.reboot_task_url = f"{self.base_url}/{CAPE_API_REBOOT_TASK}"
        self.sha256_search_url = f"{self.base_url}/{CAPE_API_SHA256_SEARCH}"


class SubmissionThread(Thread):
    # Code sourced from https://stackoverflow.com/questions/2829329/
    # catch-a-threads-exception-in-the-caller-thread-in-python/31614591
    def run(self) -> None:
        self.exc: Optional[BaseException] = None
        try:
            self.ret = self._target(*self._args, **self._kwargs)
        except BaseException as e:
            self.exc = e

    def join(self, **kwargs) -> None:
        super(SubmissionThread, self).join()
        if self.exc:
            raise self.exc
        return self.ret


# noinspection PyBroadException
# noinspection PyGlobalUndefined
class CAPE(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(CAPE, self).__init__(config)
        self.file_name: Optional[str] = None
        self.file_res: Optional[Result] = None
        self.request: Optional[ServiceRequest] = None
        self.session: Optional[requests.sessions.Session] = None
        self.connection_timeout_in_seconds: Optional[int] = None
        self.timeout: Optional[int] = None
        self.connection_attempts: Optional[int] = None
        self.allowed_images: List[str] = []
        self.artifact_list: Optional[List[Dict[str, str]]] = None
        self.hosts: List[Dict[str, Any]] = []
        self.routing = ""
        self.safelist: Dict[str, Dict[str, List[str]]] = {}
        self.identify = get_identify(use_cache=os.environ.get('PRIVILEGED', 'false').lower() == 'true')
        self.retry_on_no_machine = False
        self.uwsgi_with_recycle = False

    def start(self) -> None:
        self.log.debug("CAPE service started...")
        token_key = self.config.get("token_key", DEFAULT_TOKEN_KEY)
        for host in self.config["remote_host_details"]["hosts"]:
            host["auth_header"] = {'Authorization': f"{token_key} {host['token']}"}
        self.hosts = self.config["remote_host_details"]["hosts"][:]
        self.connection_timeout_in_seconds = self.config.get(
            "connection_timeout_in_seconds", DEFAULT_CONNECTION_TIMEOUT
        )
        self.timeout = self.config.get("rest_timeout_in_seconds", DEFAULT_REST_TIMEOUT)
        self.connection_attempts = self.config.get(
            "connection_attempts", DEFAULT_CONNECTION_ATTEMPTS
        )
        self.allowed_images = self.config.get("allowed_images", [])
        self.retry_on_no_machine = self.config.get("retry_on_no_machine", False)
        self.uwsgi_with_recycle = self.config.get("uwsgi_with_recycle", False)

        try:
            self.safelist = self.get_api_interface().get_safelist()
        except ServiceAPIError as e:
            self.log.warning(
                f"Couldn't retrieve safelist from service: {e}. Continuing without it.."
            )

    # noinspection PyTypeChecker
    def execute(self, request: ServiceRequest) -> None:
        self.request = request
        self.session = requests.Session()
        self.artifact_list = []
        # self.sandbox_ontologies = []
        request.result = Result()
        ontres = OntologyResults(service_name=SERVICE_NAME)

        # Setting working directory for request
        request._working_directory = self.working_directory

        self.file_res = request.result

        # Poorly name var to track keyword arguments to pass into CAPE's 'submit' function
        kwargs: Dict[str, Any] = {}

        # Remove leftover files in the /tmp dir from previous executions
        self._cleanup_leftovers()

        # File name related methods
        self.file_name = os.path.basename(request.task.file_name)
        self._decode_mime_encoded_file_name()
        self._remove_illegal_characters_from_file_name()
        file_ext = self._assign_file_extension()
        if not file_ext:
            # File extension or bust!
            return

        self.query_machines()

        machine_requested, machine_exists = self._handle_specific_machine(kwargs)
        if machine_requested and not machine_exists:
            # If specific machine, then we are "specific_machine" or bust!
            return

        platform_requested = None
        hosts_with_platform: Dict[str, List[str]] = {}
        if not (machine_requested and machine_exists):
            platform_requested, hosts_with_platform = self._handle_specific_platform(
                kwargs
            )
            if (
                platform_requested
                and len(hosts_with_platform[next(iter(hosts_with_platform))]) == 0
            ):
                # If a specific platform is requested, then we are specific platform or bust!
                return

        image_requested = False
        relevant_images: Dict[str, List[str]] = {}
        relevant_images_keys: List[str] = []
        if not machine_requested and not platform_requested:
            image_requested, relevant_images = self._handle_specific_image()
            if image_requested and not relevant_images:
                # If specific image, then we are "specific_image" or bust!
                return
            relevant_images_keys = list(relevant_images.keys())

        # Set this up since we are about to enter the general flow
        custom_tree_id_safelist = list(SAFE_PROCESS_TREE_LEAF_HASHES.values())
        custom_tree_id_safelist.extend(
            [
                convert_processtree_id_to_tree_id(item)
                for item in self.config.get("custom_processtree_id_safelist", list())
                if item not in custom_tree_id_safelist
            ]
        )

        # If an image has been requested, and there is more than 1 image to send the file to, then use threads
        if image_requested and len(relevant_images_keys) > 1:
            submission_threads: List[SubmissionThread] = []
            for relevant_image, host_list in relevant_images.items():
                hosts = [host for host in self.hosts if host["ip"] in host_list]
                submission_specific_kwargs = kwargs.copy()
                parent_section = ResultSection(
                    f"Analysis Environment Target: {relevant_image}"
                )
                self.file_res.add_section(parent_section)

                submission_specific_kwargs["tags"] = relevant_image
                thr = SubmissionThread(
                    target=self._general_flow,
                    args=(
                        submission_specific_kwargs,
                        file_ext,
                        parent_section,
                        hosts,
                        ontres,
                        custom_tree_id_safelist,
                    ),
                )
                submission_threads.append(thr)
                thr.start()

            for thread in submission_threads:
                thread.join()
        elif image_requested and len(relevant_images_keys) == 1:
            parent_section = ResultSection(
                f"Analysis Environment Target: {relevant_images_keys[0]}"
            )
            self.file_res.add_section(parent_section)

            kwargs["tags"] = relevant_images_keys[0]
            hosts = [
                host
                for host in self.hosts
                if host["ip"] in relevant_images[relevant_images_keys[0]]
            ]
            self._general_flow(kwargs, file_ext, parent_section, hosts, ontres, custom_tree_id_safelist)
        elif (
            platform_requested
            and len(hosts_with_platform[next(iter(hosts_with_platform))]) > 0
        ):
            parent_section = ResultSection(
                f"Analysis Environment Target: {next(iter(hosts_with_platform))}"
            )
            self.file_res.add_section(parent_section)

            hosts = [
                host
                for host in self.hosts
                if host["ip"] in hosts_with_platform[next(iter(hosts_with_platform))]
            ]
            self._general_flow(kwargs, file_ext, parent_section, hosts, ontres, custom_tree_id_safelist)
        else:
            if kwargs.get("machine"):
                specific_machine = self._safely_get_param("specific_machine")
                if ":" in specific_machine:
                    host_ip, _ = specific_machine.split(":")
                    hosts = [host for host in self.hosts if host["ip"] == host_ip]
                else:
                    hosts = self.hosts
                parent_section = ResultSection(
                    f"Analysis Environment Target: {kwargs['machine']}"
                )
            else:
                parent_section = ResultSection(
                    "Analysis Environment Target: First Machine Available"
                )
                hosts = self.hosts
            self.file_res.add_section(parent_section)

            self._general_flow(kwargs, file_ext, parent_section, hosts, ontres, custom_tree_id_safelist)

        # Adding sandbox artifacts using the OntologyResults helper class
        artifact_section = OntologyResults.handle_artifacts(
            self.artifact_list, self.request, collapsed=True, injection_heur_id=32
        )
        if artifact_section:
            self.file_res.add_section(artifact_section)

        # Remove empty sections
        for section in self.file_res.sections[:]:
            if not section.subsections:
                self.file_res.sections.remove(section)

        if len(self.file_res.sections) > 1:
            section_heur_map = {}
            for section in self.file_res.sections:
                self._get_subsection_heuristic_map(
                    section.subsections, section_heur_map
                )

        self.log.debug("Preprocessing the ontology")
        ontres.preprocess_ontology(safelist=custom_tree_id_safelist)
        self.log.debug("Attaching the ontological result")
        attach_dynamic_ontology(self, ontres)

    def _general_flow(
        self,
        kwargs: Dict[str, Any],
        file_ext: str,
        parent_section: ResultSection,
        hosts: List[Dict[str, Any]],
        ontres: OntologyResults,
        custom_tree_id_safelist: List[str],
        reboot: bool = False,
        parent_task_id: int = 0,
        resubmit: bool = False,
    ) -> None:
        """
        This method contains the general flow of a task: submitting a file to CAPE and generating an Assemblyline
        report
        :param kwargs: The keyword arguments that will be sent to CAPE when submitting the file, detailing specifics
        about the run
        :param file_ext: The file extension of the file to be submitted
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param hosts: The hosts that the file could be sent to
        :param ontres: The ontology results class object
        :param custom_tree_id_safelist: A list of hashes used for safelisting process tree IDs
        :param reboot: A boolean representing if we want to reboot the sample post initial analysis
        :param parent_task_id: The ID of the parent task which the reboot analysis will be based on
        :param resubmit: A boolean representing if we are about to resubmit a file
        :return: None
        """
        if self._is_invalid_analysis_timeout(parent_section, reboot):
            return

        if reboot:
            host_to_use = hosts[0]
            parent_section = ResultSection(
                f"Reboot Analysis -> {parent_section.title_text}"
            )
            self.file_res.add_section(parent_section)
        else:
            self._set_task_parameters(kwargs, parent_section)
            host_to_use = self._determine_host_to_use(hosts)

        cape_task = CapeTask(self.file_name, host_to_use, **kwargs)

        if parent_task_id:
            cape_task.id = parent_task_id

        try:
            self.submit(self.request.file_contents, cape_task, parent_section, reboot)

            if cape_task.id:
                self._generate_report(file_ext, cape_task, parent_section, ontres, custom_tree_id_safelist)
            else:
                raise Exception(f"Task ID is None. File failed to be submitted to the CAPE nest at "
                                f"{host_to_use['ip']}.")
        except AnalysisFailed:
            pass
        except Exception as e:
            self.log.error(repr(e))
            if cape_task and cape_task.id is not None:
                self.delete_task(cape_task)
            raise

        # If first submission, reboot is always false
        if not reboot and self.config.get("reboot_supported", False):
            reboot = self._determine_if_reboot_required(parent_section)
            if reboot:
                self._general_flow(
                    kwargs,
                    file_ext,
                    parent_section,
                    [host_to_use],
                    ontres,
                    custom_tree_id_safelist,
                    reboot,
                    cape_task.id,
                )

        # Delete and exit
        if cape_task and cape_task.id is not None:
            self.delete_task(cape_task)

        # Two submissions is enough I'd say
        if resubmit:
            return

        for subsection in parent_section.subsections:
            if (
                subsection.title_text == ANALYSIS_ERRORS
                and GUEST_CANNOT_REACH_HOST in subsection.body
            ):
                self.log.debug(
                    "The first submission was sent to a machine that had difficulty communicating with "
                    "the nest. Will try to resubmit again."
                )
                parent_section = ResultSection(
                    f"Resubmit -> {parent_section.title_text}"
                )
                self.file_res.add_section(parent_section)
                host_to_use = self._determine_host_to_use(hosts)
                self._general_flow(
                    kwargs,
                    file_ext,
                    parent_section,
                    [host_to_use],
                    ontres,
                    custom_tree_id_safelist,
                    resubmit=True,
                )
                break

    def submit(
        self,
        file_content: bytes,
        cape_task: CapeTask,
        parent_section: ResultSection,
        reboot: bool = False,
    ) -> None:
        """
        This method contains the submitting, polling, and report retrieving logic
        :param file_content: The content of the file to be submitted
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param reboot: A boolean indicating that we will be resubmitting a task for reboot analysis
        :return: None
        """
        if not reboot:
            if self._safely_get_param("ignore_cape_cache") or not self.sha256_check(
                self.request.sha256, cape_task
            ):
                try:
                    """Submits a new file to CAPE for analysis"""
                    task_id = self.submit_file(file_content, cape_task)
                    if not task_id:
                        self.log.error("Failed to get task for submitted file.")
                        return
                    else:
                        cape_task.id = task_id
                except Exception as e:
                    self.log.error(f"Error submitting to CAPE: {safe_str(e)}")
                    raise
        else:
            resp = self.session.get(
                cape_task.reboot_task_url % cape_task.id,
                headers=cape_task.auth_header,
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                self.log.warning(
                    "Reboot selected, but task could not be rebooted. Moving on..."
                )
                return
            else:
                reboot_resp = resp.json()
                cape_task.id = reboot_resp["reboot_id"]
                self.log.debug(
                    f"Reboot selected, task {reboot_resp['task_id']} marked for"
                    f" reboot {reboot_resp['reboot_id']}."
                )

        self.log.debug(
            f"Submission succeeded. File: {cape_task.file} -- Task {cape_task.id}"
        )

        self.poll_started(cape_task)

        try:
            status = self.poll_report(cape_task, parent_section)
        except RetryError:
            self.log.error(f"Unable to get report via {cape_task.base_url}. Indicator: 'Max retries exceeded for report status.' Try submission again!")
            if cape_task and cape_task.id is not None:
                self.delete_task(cape_task)
            raise RecoverableError(f"Unable to complete analysis and processing in time. Try again.")

        if status in [ANALYSIS_FAILED, PROCESSING_FAILED]:
            # Add a subsection detailing what's happening and then moving on
            analysis_failed_sec = ResultTextSection("CAPE Analysis/Processing Failed.")
            analysis_failed_sec.add_line(
                f"The analysis/processing of CAPE task {cape_task.id} has failed."
                " Contact the CAPE administrator for details."
            )
            parent_section.add_subsection(analysis_failed_sec)
            raise AnalysisFailed()

    def stop(self) -> None:
        self.log.debug("CAPE service stopped...")

    @retry(wait_fixed=CAPE_POLL_DELAY * 1000,
           retry_on_result=_retry_on_none,
           retry_on_exception=_exclude_invalid_req_ex)
    def poll_started(self, cape_task: CapeTask) -> Optional[str]:
        """
        This method queries the task on the CAPE server, and determines if the task has started
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :return: A string representing the status
        """
        task_info = self.query_task(cape_task)

        if task_info.get("guest", {}).get("status") == TASK_STARTING:
            return None

        if task_info.get("task", {}).get("status") == TASK_MISSING:
            return None

        return TASK_STARTED

    @retry(wait_fixed=CAPE_POLL_DELAY * 1000,
           stop_max_attempt_number=((GUEST_VM_START_TIMEOUT + REPORT_GENERATION_TIMEOUT)/CAPE_POLL_DELAY),
           retry_on_result=_retry_on_none,
           retry_on_exception=_exclude_invalid_req_ex)
    def poll_report(self, cape_task: CapeTask, parent_section: ResultSection) -> Optional[str]:
        """
        This method polls the CAPE server for the status of the task, doing so until a report has been generated
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: A string representing the status
        """
        task_info = self.query_task(cape_task)

        # Check for errors first to avoid parsing exceptions
        status = task_info["status"]
        if status == ANALYSIS_FAILED:
            self.log.error(
                f"Analysis has failed for task {cape_task.id} due to {task_info['errors']}."
            )
            analysis_errors_sec = ResultTextSection(ANALYSIS_ERRORS)
            analysis_errors_sec.add_lines(task_info["errors"])
            parent_section.add_subsection(analysis_errors_sec)
            return ANALYSIS_FAILED
        elif status == PROCESSING_FAILED:
            self.log.error(f"Processing has failed for task {cape_task.id}.")
            processing_errors_sec = ResultTextSection(ANALYSIS_ERRORS)
            processing_errors_sec.add_line(
                f"Processing has failed for task {cape_task.id}."
            )
            parent_section.add_subsection(processing_errors_sec)
            return PROCESSING_FAILED
        elif status == TASK_COMPLETED:
            self.log.debug(
                f"Analysis has completed for task {cape_task.id}, waiting on report to be produced."
            )
        elif status == TASK_REPORTED:
            self.log.debug(
                f"CAPE report generation has completed for task {cape_task.id}."
            )
            return status
        else:
            self.log.debug(
                f"Waiting for task {cape_task.id} to finish. Current status: {status}."
            )

        return None

    def sha256_check(self, sha256: str, cape_task: CapeTask) -> bool:
        """
        This method was inspired by/grabbed from https://github.com/NVISOsecurity/assemblyline-service-cape/blob/main/cape.py#L21:L37
        Check in CAPE if an analysis already exists for the corresponding sha256
            - If an analysis already exists, we set the ID of the analysis and return true
            - If not, we just return false

        NOTE: This method is used on a per-host basis, and will only return True if the most of the submision
        parameters line up
        :param sha256: A string of the SHA256 for the submitted file
        :return: A boolean indicating that the task ID was set
        """
        self.log.debug(f"Searching for the file's SHA256 at {cape_task.sha256_search_url % sha256}")
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            # For timeouts and connection errors, we will try for all eternity.
            sha256_url = cape_task.sha256_search_url % sha256
            try:
                resp = self.session.get(sha256_url, headers=cape_task.auth_header, timeout=self.timeout)
            except requests.exceptions.Timeout:
                if not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{sha256_url} timed out after {self.timeout}s "
                        "trying to search a SHA256.'"
                    )
                    logged = True
                sleep(5)
                continue
            except requests.ConnectionError as e:
                if self.is_connection_error_worth_logging(repr(e)) and not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{sha256_url} failed to search for the SHA256 {sha256} due to {e}.'"
                    )
                    logged = True
                sleep(5)
                continue

            if resp.status_code != 200:
                if not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{sha256_url} failed with status code {resp.status_code} "
                        f"trying to search for {sha256}.'"
                    )
                    logged = True
                sleep(5)
                continue
            else:
                resp_json = resp.json()
                if "error" in resp_json and resp_json['error']:
                    self.log.error(
                        f"Failed to search for SHA256 with {sha256_url} due "
                        f"to '{resp_json['error_value']}'."
                    )
                    raise InvalidCapeRequest("There is most likely an issue with how the service is configured to interact with CAPE's REST API. Check the service logs for more details.")
                elif "data" in resp_json:
                    if tasks_are_similar(cape_task, resp_json["data"]):
                        cape_task.id = resp_json["data"][0]["id"]
                        self.log.debug(f"Cache hit for {sha256} with ID {cape_task.id}. No need to submit.")
                        return True
                    else:
                        return False
                else:
                    if not logged:
                        self.log.error(
                            "The cape-web.service is most likely down. "
                            f"Indicator: '{sha256_url} failed with status code {resp.status_code} "
                            f"trying to search for {sha256}. Data returned was: {resp_json}'.'"
                        )
                        logged = True
                    sleep(5)
                    continue

    def submit_file(self, file_content: bytes, cape_task: CapeTask) -> int:
        """
        This method submits the file to the CAPE server
        :param file_content: the contents of the file to be submitted
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :return: an integer representing the task ID
        """
        self.log.debug(
            f"Submitting file: {cape_task.file} to server {cape_task.submit_url}"
        )
        files = {"file": (cape_task.file, file_content)}
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            # For timeouts and connection errors, we will try for all eternity.
            try:
                cape_task_data = {k: cape_task[k] for k in cape_task.keys()}
                resp = self.session.post(
                    cape_task.submit_url,
                    files=files,
                    data=cape_task_data,
                    headers=cape_task.auth_header,
                    timeout=self.timeout
                )
            except requests.exceptions.Timeout:
                if not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{cape_task.submit_url} timed out after {self.timeout}s "
                        f"trying to submit a file {cape_task.file}.'"
                    )
                    logged = True
                sleep(5)
                continue
            except requests.ConnectionError as e:
                if self.is_connection_error_worth_logging(repr(e)) and not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{cape_task.submit_url} failed to submit a file {cape_task.file} due to {e}.'"
                    )
                    logged = True
                sleep(5)
                continue
            except requests.exceptions.ChunkedEncodingError as e:
                if not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{cape_task.submit_url} failed to submit a file {cape_task.file} due to {e}.'"
                    )
                    logged = True
                sleep(5)
                continue
            if resp.status_code != 200:
                if not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{cape_task.submit_url} failed with status code {resp.status_code} "
                        f"trying to submit a file {cape_task.file}.'"
                    )
                    logged = True
                sleep(5)
                continue
            else:
                resp_json = resp.json()
                if "error" in resp_json and resp_json['error']:
                    self.log.error(f"Failed to submit the file with {cape_task.submit_url} due to '{resp_json['error_value']}'.")
                    incorrect_tag = False
                    if "errors" in resp_json and resp_json["errors"]:
                        try:
                            for error in resp_json["errors"]:
                                for error_dict in error.values():
                                    for k, v in error_dict.items():
                                        if k == "error":
                                            self.log.error(f'Further details about the error are: {v}')
                                            incorrect_tag = "Check Tags help, you have introduced incorrect tag(s)." in v
                        except Exception:
                            pass

                    if self.retry_on_no_machine and incorrect_tag:
                        # No need to log here because the log.error above containing further details about the error has happened
                        sleep(self.timeout)
                        raise RecoverableError("Retrying since the specific image was missing...")
                    else:
                        raise InvalidCapeRequest("There is most likely an issue with how the service is configured to interact with CAPE's REST API. Check the service logs for more details.")
                elif "data" in resp_json and resp_json["data"]:
                    task_ids = resp_json["data"].get("task_ids", [])
                    if isinstance(task_ids, list) and len(task_ids) > 0:
                        return task_ids[0]
                    else:
                        if not logged:
                            self.log.error(
                                "The cape-web.service is most likely down. "
                                f"Indicator: '{cape_task.submit_url} failed with status code {resp.status_code} "
                                f"trying to submit a file {cape_task.file}. Data returned was: {resp_json['data']}'."
                            )
                            logged = True
                        sleep(5)
                        continue
                else:
                    if not logged:
                        self.log.error(
                            "The cape-web.service is most likely down. "
                            f"Indicator: '{cape_task.submit_url} failed with status code {resp.status_code} "
                            f"trying to submit a file {cape_task.file}. Data returned was: {resp_json}'."
                        )
                        logged = True
                    sleep(5)
                    continue

    def query_report(self, cape_task: CapeTask) -> Any:
        """
        This method retrieves the report from the CAPE server
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :return: Depending on what is requested, will return a string representing that a JSON report has been
        generated or the bytes of a tarball
        """
        self.log.debug(f"Querying report for task {cape_task.id} - format: 'lite'")
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            # For timeouts and connection errors, we will try for all eternity.
            report_url = cape_task.query_report_url % cape_task.id + "lite" + '/zip/'
            try:
                # There are edge cases that require us to stream the report to disk
                temp_report = SpooledTemporaryFile()
                with self.session.get(report_url,
                                    headers=cape_task.auth_header, timeout=self.timeout, stream=True) as resp:
                    if resp.status_code == 200:
                        for chunk in resp.iter_content(chunk_size=8192):
                            temp_report.write(chunk)
                    else:
                        if not logged:
                            self.log.error(
                                "The cape-web.service is most likely down. "
                                f"Indicator: '{report_url} failed with status code {resp.status_code} "
                                f"trying to get the report for task {cape_task.id}.'"
                            )
                            logged = True
                        sleep(5)
                        continue
            except requests.exceptions.Timeout:
                if not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{report_url} timed out after {self.timeout}s "
                        f"trying to get the report for task {cape_task.id}.'"
                    )
                    logged = True
                sleep(5)
                continue
            except requests.ConnectionError as e:
                if self.is_connection_error_worth_logging(repr(e)) and not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{report_url} failed to get the report for task {cape_task.id} due to {e}.'"
                    )
                    logged = True
                sleep(5)
                continue

            try:
                # Setting the pointer in the temp file
                temp_report.seek(0)
                # Reading as bytes
                report_data = temp_report.read()
            finally:
                # Removing the temp file
                temp_report.close()

            if report_data in [None, "", b"", b'{}', b'""']:
                if not logged:
                    self.log.error(
                        "The cape-processor.service is most likely down. "
                        f"Indicator: 'Empty 'lite' report data for task {cape_task.id} from {report_url}.'"
                    )
                    logged = True
                sleep(5)
                continue

            return report_data

    def query_task(self, cape_task: CapeTask) -> Dict[str, Any]:
        """
        This method queries the task on the CAPE server
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :return: a dictionary containing details about the task, such as its status
        """
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            # For timeouts and connection errors, we will try for all eternity.
            task_url = cape_task.query_task_url % cape_task.id
            try:
                resp = self.session.get(
                    task_url,
                    headers=cape_task.auth_header,
                    timeout=self.timeout
                )
            except requests.exceptions.Timeout:
                if not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{task_url} timed out after {self.timeout}s "
                        f"trying to query the task {cape_task.id}.'"
                    )
                    logged = True
                sleep(5)
                continue
            except requests.ConnectionError as e:
                if self.is_connection_error_worth_logging(repr(e)) and not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{task_url} failed to query the task {cape_task.id} due to {e}.'"
                    )
                    logged = True
                sleep(5)
                continue

            if resp.status_code != 200:
                if resp.status_code == 404:
                    # Just because the query returns 404 doesn't mean the task doesn't exist, it just hasn't been
                    # added to the DB yet
                    self.log.warning(f"Task not found for task {cape_task.id}")
                    return {"task": {"status": TASK_MISSING}, "id": cape_task.id}
                else:
                    if not logged:
                        self.log.error(
                            "The cape-web.service is most likely down. "
                            f"Indicator: '{task_url} failed with status code {resp.status_code} "
                            f"trying to query the task {cape_task.id}.'"
                        )
                        logged = True
                    sleep(5)
                    continue
            else:
                resp_json = resp.json()
                if "error" in resp_json and resp_json['error']:
                    self.log.error(
                        f"Failed to query the task {cape_task.id} with {task_url} due "
                        f"to '{resp_json['error_value']}'."
                    )
                    raise InvalidCapeRequest("There is most likely an issue with how the service is configured to interact with CAPE's REST API. Check the service logs for more details.")
                elif "data" in resp_json and resp_json["data"]:
                    return resp_json["data"]
                else:
                    if not logged:
                        self.log.error(
                            "The cape-web.service is most likely down. "
                            f"Indicator: '{task_url} failed with status code {resp.status_code} "
                            f"trying to query the task {cape_task.id}. Data returned was: {resp_json}'"
                        )
                        logged = True
                    sleep(5)
                    continue

    def delete_task(self, cape_task: CapeTask) -> None:
        """
        This method tries to delete the task from the CAPE server
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :return: None
        """
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            # For timeouts and connection errors, we will try for all eternity.
            delete_url = cape_task.delete_task_url % cape_task.id
            try:
                resp = self.session.get(
                    delete_url,
                    headers=cape_task.auth_header,
                    timeout=self.timeout
                )
            except requests.exceptions.Timeout:
                if not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{delete_url} timed out after {self.timeout}s "
                        f"trying to delete task {cape_task.id}'."
                    )
                    logged = True
                sleep(5)
                continue
            except requests.ConnectionError as e:
                if self.is_connection_error_worth_logging(repr(e)) and not logged:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{delete_url} failed to delete task {cape_task.id} due to {e}'."
                    )
                    logged = True
                sleep(5)
                continue
            if resp.status_code != 200:
                if resp.status_code == 500:
                    try:
                        message = loads(resp.text).get("message")
                    except Exception:
                        if resp.text:
                            self.log.error(f"Failed to delete task {cape_task.id} due to {resp.text}.")
                        message = None

                    if message == "The task is currently being processed, cannot delete":
                        self.log.error(
                            f"The task {cape_task.id} is currently being processed, cannot delete."
                        )
                else:
                    if not logged:
                        self.log.error(
                            "The cape-web.service is most likely down. "
                            f"Indicator: '{delete_url} failed with status code {resp.status_code} trying to delete task {cape_task.id}'."
                        )
                        logged = True
                sleep(5)
                continue
            else:
                self.log.debug(f"Deleted task {cape_task.id}.")
                cape_task.id = None
                break

    def query_machines(self) -> None:
        """
        This method queries what machines exist in the CAPE configuration on the CAPE server
        This is the initial request to each CAPE host.
        :return: None
        """
        # We will get a connection with a host REST API.. NO MATTER WHAT (or we need to fail fast or it was a success)
        fail_fast_count = 0
        success = False
        while not success and fail_fast_count != len(self.hosts):
            # Cycle through each host
            for host in self.hosts:
                # Try a host up until the number of connection attempts
                # For timeouts and connection errors, we will try for all eternity. If there is an error response with a 200 status code from the REST API, then we will fail fast because this is most likely a configuration problem with the
                # CAPE service
                host["machines"]: List[Dict[str, Any]] = []

                for _ in range(self.connection_attempts):
                    query_machines_url = f"http://{host['ip']}:{host['port']}/{APIv2_BASE_ENDPOINT}/{CAPE_API_QUERY_MACHINES}"
                    try:
                        resp = self.session.get(
                            query_machines_url, headers=host["auth_header"],
                            timeout=self.connection_timeout_in_seconds)
                    except requests.exceptions.Timeout:
                        self.log.error(
                            "The cape-web.service is most likely down. "
                            f"Indicator: '{query_machines_url} timed out after {self.connection_timeout_in_seconds}s "
                            "trying to query machines.'"
                        )
                        if len(self.hosts) == 1:
                            sleep(self.connection_timeout_in_seconds)
                        continue
                    except requests.ConnectionError as e:
                        if self.is_connection_error_worth_logging(repr(e)):
                            self.log.error(
                                f"Unable to reach {query_machines_url} due to '{e}'. "
                                "Follow the README and ensure that you have a CAPE nest setup outside of Assemblyline "
                                "before running the service.")
                        if len(self.hosts) == 1:
                            sleep(self.connection_timeout_in_seconds)
                        continue

                    if resp.status_code != 200:
                        self.log.error(
                            "The cape-web.service is most likely down. "
                            f"Indicator: '{query_machines_url} failed with status code {resp.status_code} "
                            "trying to query machines.'"
                        )
                        if len(self.hosts) == 1:
                            sleep(self.connection_timeout_in_seconds)
                        continue
                    else:
                        resp_json = resp.json()

                        if "error" in resp_json and resp_json['error']:
                            self.log.error(
                                f"Failed to query machines for {query_machines_url} due "
                                f"to '{resp_json['error_value']}'."
                            )
                            fail_fast_count += 1
                            break

                        host["machines"] = resp_json["data"]
                        success = True
                        break

        if fail_fast_count == len(self.hosts):
            raise InvalidCapeRequest("There is most likely an issue with how the service is configured to interact with CAPE's REST API. Check the service logs for more details.")

    def check_powershell(self, task_id: int, parent_section: ResultSection) -> None:
        """
        This method adds powershell files as extracted.
        :param task_id: An integer representing the CAPE Task ID
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: None
        """
        # If there is a Powershell Activity section, create an extracted file from it
        for section in parent_section.subsections:
            if section.title_text == "PowerShell Activity":
                ps1_file_name = f"{task_id}_powershell_logging.ps1"
                ps1_path = os.path.join(self.working_directory, ps1_file_name)
                with open(ps1_path, "a") as fh:
                    for item in loads(section.body):
                        fh.write(item["original"] + "\n")
                fh.close()
                self.log.debug(
                    f"Adding extracted file for task {task_id}: {ps1_file_name}"
                )
                artifact = {
                    "name": ps1_file_name,
                    "path": ps1_path,
                    "description": "Deobfuscated PowerShell script from CAPE analysis",
                    "to_be_extracted": True,
                }
                self.artifact_list.append(artifact)
                break

    def report_machine_info(
        self,
        machine_name: str,
        cape_task: CapeTask,
        parent_section: ResultSection,
    ) -> Optional[Dict[str, Any]]:
        """
        This method reports details about the machine that was used for detonation.
        :param machine_name: The name of the machine that the task ran on.
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: A dictionary containing the machine info
        """
        # The machines here are the machines that were loaded prior to the file being submitted.
        machine = self._get_machine_by_name(machine_name)

        if not machine:
            self.query_machines()
            # The machines here are the machines that are loaded post the file being analyzed.
            machine = self._get_machine_by_name(machine_name)
            # NOTE: There is still a possibility of the machine not existing at either point of time.
            # So we will only try once.
            if not machine:
                return None

        manager = cape_task.report["info"]["machine"]["manager"]
        platform = machine["platform"]
        body = {
            "Name": machine_name,
            "Manager": manager,
            "Platform": platform,
            "IP": machine["ip"],
            "Tags": [],
        }
        for tag in machine.get("tags", []):
            body["Tags"].append(safe_str(tag).replace("_", " "))

        machine_section = ResultKeyValueSection(MACHINE_INFORMATION_SECTION_TITLE)
        machine_section.update_items(body)

        self._add_operating_system_tags(machine_name, platform, machine_section)
        m = compile(MACHINE_NAME_REGEX).search(machine_name)
        if m and len(m.groups()) == 1:
            version = m.group(1)
            _ = add_tag(machine_section, "dynamic.operating_system.version", version)

        parent_section.add_subsection(machine_section)
        return body

    @staticmethod
    def _add_operating_system_tags(
        machine_name: str,
        platform: str,
        machine_section: ResultKeyValueSection,
    ) -> None:
        """
        This method adds tags to the ResultKeyValueSection related
        to the operating system of the machine that a task was ran on
        :param machine_name: The name of the machine that the task was ran on
        :param platform: The platform of the machine that the task was ran on
        :param machine_section: The ResultKeyValueSection containing details about the machine
        :return: None
        """
        if platform:
            _ = add_tag(
                machine_section,
                "dynamic.operating_system.platform",
                platform.capitalize(),
            )
        if any(
            processor_tag in machine_name
            for processor_tag in [x64_IMAGE_SUFFIX, x86_IMAGE_SUFFIX]
        ):
            if x86_IMAGE_SUFFIX in machine_name:
                _ = add_tag(
                    machine_section,
                    "dynamic.operating_system.processor",
                    x86_IMAGE_SUFFIX,
                )
            elif x64_IMAGE_SUFFIX in machine_name:
                _ = add_tag(
                    machine_section,
                    "dynamic.operating_system.processor",
                    x64_IMAGE_SUFFIX,
                )

    def _decode_mime_encoded_file_name(self) -> None:
        """
        This method attempts to decode a MIME-encoded file name
        :return: None
        """
        # Check the filename to see if it's mime encoded
        mime_re = compile(r"^=\?.*\?=$")
        if mime_re.match(self.file_name):
            self.log.debug("Found a mime encoded filename, will try and decode")
            try:
                decoded_filename = decode_header(self.file_name)
                new_filename = decoded_filename[0][0].decode(decoded_filename[0][1])
                self.log.debug(f"Using decoded filename {new_filename}")
                self.file_name = new_filename
            except Exception as e:
                new_filename = generate_random_words(1)
                self.log.warning(
                    f"Problem decoding filename. Using randomly "
                    f"generated filename {new_filename}. Error: {e}"
                )
                self.file_name = new_filename

    def _remove_illegal_characters_from_file_name(self) -> None:
        """
        This method removes any illegal characters from a file name
        :return: None
        """
        if any(ch in self.file_name for ch in ILLEGAL_FILENAME_CHARS):
            self.log.debug(
                f"Renaming {self.file_name} because it contains one of {ILLEGAL_FILENAME_CHARS}"
            )
            self.file_name = "".join(
                ch for ch in self.file_name if ch not in ILLEGAL_FILENAME_CHARS
            )

    def _assign_file_extension(self) -> str:
        """
        This method determines the correct file extension to the file to be submitted
        :return: The file extension of the file to be submitted
        """
        # Check the file extension
        original_ext = self.file_name.rsplit(".", 1)
        tag_extension = type_to_extension.get(self.request.file_type)

        # NOTE: CAPE still tries to identify files itself, so we only force the extension/package
        # if the user specifies one. However, we go through the trouble of renaming the file because
        # the only way to have certain modules run is to use the appropriate suffix (.jar, .vbs, etc.)

        # Check for a valid tag
        # TODO: this should be more explicit in terms of "unknown" in file_type
        if tag_extension is not None and "unknown" not in self.request.file_type:
            file_ext = tag_extension
        # Check if the file was submitted with an extension
        elif len(original_ext) == 2:
            submitted_ext = original_ext[1]
            if submitted_ext not in SUPPORTED_EXTENSIONS:
                # This is the case where the submitted file was NOT identified, and  the provided extension
                # isn't in the list of extensions that we explicitly support.
                self.log.debug(
                    "CAPE is exiting because it doesn't support the provided file type."
                )
                return ""
            else:
                # This is a usable extension. It might not run (if the submitter has lied to us).
                file_ext = "." + submitted_ext
        else:
            # This is unknown without an extension that we accept/recognize.. no scan!
            self.log.debug(
                f"The file type of '{self.request.file_type}' could "
                f"not be identified. Tag extension: {tag_extension}"
            )
            return ""

        # Rename based on the found extension.
        self.file_name = original_ext[0] + file_ext
        return file_ext

    def _set_task_parameters(
        self, kwargs: Dict[str, Any], parent_section: ResultSection
    ) -> None:
        """
        This method sets the specific details about the run, through the kwargs and the task_options
        :param kwargs: The keyword arguments that will be sent to CAPE when submitting the file, detailing specifics
        about the run
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: None
        """
        # the 'options' kwargs
        task_options: List[str] = []

        # Parse user args
        timeout = self.request.get_param("analysis_timeout_in_seconds")
        # If user specifies the timeout, then enforce it
        if timeout:
            kwargs["enforce_timeout"] = True
            kwargs["timeout"] = timeout
        else:
            kwargs["enforce_timeout"] = False
            kwargs["timeout"] = self.config.get(
                "default_analysis_timeout_in_seconds", ANALYSIS_TIMEOUT
            )
        arguments = self.request.get_param("arguments")
        dump_memory = self._safely_get_param("dump_memory")
        no_monitor = self.request.get_param("no_monitor")

        # If the user didn't select no_monitor, but at the service level we want no_monitor on Windows 10x64, then:
        if (
            not no_monitor
            and self.config.get("no_monitor_for_win10x64", False)
            and kwargs.get("tags", {}) == "win10x64"
        ):
            no_monitor = True

        custom_options = self.request.get_param("custom_options")
        kwargs["clock"] = self.request.get_param("clock")
        force_sleepskip = self.request.get_param("force_sleepskip")
        simulate_user = self.request.get_param("simulate_user")
        package = self.request.get_param("package")
        route = self.request.get_param("routing")

        if "dll" in self.request.file_type:
            self._prepare_dll_submission(task_options, parent_section)

        # This is a CAPE workaround because otherwise CAPE will extract an archive
        # into extracted files and submit each as a separate task
        elif self.request.file_type in ["archive/iso", "archive/rar", "archive/vhd", "archive/udf", "archive/zip"]:
            task_options.append("file=")

        # Package-related logic
        # If the user requests a package, give it to them
        if package:
            kwargs["package"] = package
        # If the user wants to use antivm packages and the file type makes sense, give it to them
        elif self.config.get("use_antivm_packages", False) and self.request.file_type in ["code/javascript", "document/office/word"]:
            # Assign the appropriate package based on file type. As of 2022-11-25, there are only two.
            kwargs["package"] = "doc_antivm" if self.request.file_type == "document/office/word" else "js_antivm"
        # Force the "archive" package instead of the "rar" package since it is more feature-full, and 7zip can extract rar files too.
        elif self.request.file_type == "archive/rar":
            kwargs["package"] = "archive"

        if arguments:
            task_options.append(f"arguments={arguments}")

        if self.config.get("machinery_supports_memory_dumps", False) and dump_memory:
            kwargs["memory"] = True
        elif dump_memory:
            parent_section.add_subsection(
                ResultSection("CAPE Machinery Cannot Generate Memory Dumps.")
            )

        if no_monitor:
            task_options.append("free=yes")

        if force_sleepskip:
            task_options.append("force-sleepskip=1")

        if not simulate_user:
            task_options.append("nohuman=true")

        # If deep_scan, then get 100 HH files of all types
        if self.request.deep_scan:
            task_options.append("hollowshunter=all")

        hollowshunter_args = self._safely_get_param("hh_args")
        if hollowshunter_args:
            task_options.append(f"hh_args={hollowshunter_args}")

        if route:
            kwargs["route"] = route.lower()
            self.routing = route
        else:
            self.routing = "None"

        if self.config.get("limit_monitor_apis", False):
            task_options.append("api-cap=1000")

        kwargs["options"] = ",".join(task_options)
        if custom_options is not None:
            kwargs["options"] += f",{custom_options}"

    def _set_hosts_that_contain_image(self, specific_image: str, relevant_images: Dict[str, List[str]]) -> None:
        """
        This method maps the specific image with a list of hosts that have that image available
        :param specific_image: The specific image requested for the task
        :param relevant_images: Dictionary containing a map between the image and the list of hosts that contain the
        image
        :return: None
        """
        host_list: List[str] = []
        for host in self.hosts:
            if self._does_image_exist(
                specific_image, host["machines"], self.allowed_images
            ):
                host_list.append(host["ip"])
        if host_list:
            relevant_images[specific_image] = host_list

    @staticmethod
    def _does_image_exist(
        specific_image: str, machines: List[Dict[str, Any]], allowed_images: List[str]
    ) -> bool:
        """
        This method checks if the specific image exists in a list of machines
        :param specific_image: The specific image requested for the task
        :param machines: A list of machines on a CAPE server
        :param allowed_images: A list of images that are allowed to be selected on Assemblyline
        :return: A boolean representing if the image exists
        """
        if specific_image not in allowed_images:
            return False

        machine_names = [machine["name"] for machine in machines]
        if any(specific_image in machine for machine in machine_names):
            return True
        else:
            return False

    @staticmethod
    def _get_available_images(
        machines: List[Dict[str, Any]], allowed_images: List[str]
    ) -> List[str]:
        """
        This method gets a list of available images given a list of machines
        :param machines: A list of machines on a CAPE server
        :param allowed_images: A list of images that are allowed to be selected on Assemblyline
        :return: A list of available images
        """
        machine_names = [machine["name"] for machine in machines]
        if not machine_names or not allowed_images:
            return []

        available_images: Set[str] = set()
        for image in allowed_images:
            if any(image in machine_name for machine_name in machine_names):
                available_images.add(image)
        return list(available_images)

    def _prepare_dll_submission(self, task_options: List[str], parent_section: ResultSection) -> None:
        """
        This method handles if a specific function was requested to be run for a DLL, or what functions to run for a DLL
        :param task_options: A list of parameters detailing the specifics of the task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: None
        """
        dll_function = self.request.get_param("dll_function")
        # Do DLL specific stuff
        if dll_function:
            task_options.append(f"function={dll_function}")

            # Check to see if there are pipes in the dll_function
            # This is reliant on analyzer/windows/modules/packages/dll.py
            if ":" in dll_function:
                task_options.append("enable_multi=true")

        if not dll_function:
            self._parse_dll(task_options, parent_section)

    def _parse_dll(self, task_options: List[str], parent_section: ResultSection) -> None:
        """
        This method parses a DLL file and determines which functions to try and run with the DLL
        :param task_options: A list of parameters detailing the specifics of the task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: None
        """
        exports_available: List[str] = []
        exports_to_run: List[str] = []
        # We have a DLL file, but no user specified function(s) to run. let's try to pick a few...
        # This is reliant on analyzer/windows/modules/packages/dll_multi.py
        dll_parsed = self._create_pe_from_file_contents()

        # Do we have any exports?
        if hasattr(dll_parsed, "DIRECTORY_ENTRY_EXPORT"):
            for export_symbol in dll_parsed.DIRECTORY_ENTRY_EXPORT.symbols:
                if export_symbol.name is not None:
                    if type(export_symbol.name) == str:
                        exports_available.append(export_symbol.name)
                    elif type(export_symbol.name) == bytes:
                        exports_available.append(export_symbol.name.decode())
                else:
                    exports_available.append(f"#{export_symbol.ordinal}")
        else:
            # No Exports available? Try DllMain and DllRegisterServer
            exports_available.append("DllMain")
            exports_available.append("DllRegisterServer")

        max_dll_exports = self.config.get("max_dll_exports_exec", 5)

        # If the number of available exports is greater than the maximum number of
        # exports that we want to run, we will be prioritizing by the following:
        # 1. well known exports (dllRegisterServer, etc)
        # 2. first exports (10%)
        # 3. last exports (10%)
        # 4. least common exports (80% - 2 exports for DllRegisterServer and DllMain)
        if len(exports_available) > max_dll_exports:
            ten_percent_of_exports = ceil(max_dll_exports * 0.1)

            # add well-known exports
            exports_to_run.extend(["DllMain", "DllRegisterServer"])

            # first exports
            exports_to_run.extend(exports_available[:ten_percent_of_exports])

            # last exports
            exports_to_run.extend(exports_available[-1*ten_percent_of_exports:])

            # This code runs at O(n^2), so if there are a lot of exports, don't run
            if len(exports_available) <= 300:
                # least common exports
                index = SearchIndex(exports_available, similarity_func_name='jaccard', similarity_threshold=0.1)
                similarity_scores = []
                for exp in exports_available:
                    if not exp:
                        continue
                    res = index.query(exp)
                    avg_sim = sum(x[1] for x in res)/len(res)
                    similarity_scores.append((avg_sim, exp))

                for _, name in sorted(similarity_scores):
                    if len(exports_to_run) < max_dll_exports:
                        if name not in exports_to_run:
                            exports_to_run.append(name)
                    else:
                        break
            else:
                # We'll take the next n after the first 10% of max_dll_exports to fill up the remaining exports to run
                number_of_middle_exports_to_run = max_dll_exports - len(exports_to_run)
                exports_to_run.extend(
                    exports_available[ten_percent_of_exports:ten_percent_of_exports+number_of_middle_exports_to_run]
                )

        else:
            exports_to_run = exports_available

        task_options.append(f"function={':'.join(exports_to_run)}")
        task_options.append("enable_multi=true")

        self.log.debug(
            f"Trying to run DLL with following function(s): {':'.join(exports_to_run)}")

        if len(exports_available) > 0:
            dll_multi_section = ResultTextSection("Executed Multiple DLL Exports")
            dll_multi_section.add_line(
                f"The following exports were executed: {', '.join(exports_to_run)}")
            remaining_exports = set(exports_available) - set(exports_to_run)
            if len(remaining_exports) > 0:
                available_exports_str = ", ".join(sorted(list(remaining_exports)))
                dll_multi_section.add_line(f"There were {len(remaining_exports)} other exports: {available_exports_str}")

            parent_section.add_subsection(dll_multi_section)

    # Isolating this sequence out because I can't figure out how to mock PE construction
    def _create_pe_from_file_contents(self) -> PE:
        """
        This file parses a DLL file and handles PEFormatErrors
        :return: An optional parsed PE
        """
        # TODO: What is this type?
        dll_parsed = None
        try:
            dll_parsed = PE(data=self.request.file_contents)
        except (PEFormatError, AttributeError) as e:
            self.log.warning(f"Could not parse PE file due to {safe_str(e)}")
        return dll_parsed

    def _generate_report(
        self,
        file_ext: str,
        cape_task: CapeTask,
        parent_section: ResultSection,
        ontres: OntologyResults,
        custom_tree_id_safelist: List[str],
    ) -> None:
        """
        This method generates the report for the task
        :param file_ext: The file extension of the file to be submitted
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param ontres: The sandbox ontology class object
        :param custom_tree_id_safelist: A list of hashes used for safelisting process tree IDs
        :return: None
        """
        # Retrieve artifacts from analysis
        self.log.debug(f"Generating CAPE report .zip for {cape_task.id}.")

        # Submit CAPE analysis report archive as a supplementary file
        zip_report = self.query_report(cape_task)
        if zip_report is not None:
            self._unpack_zip(zip_report, file_ext, cape_task, parent_section, ontres, custom_tree_id_safelist)

        # Submit dropped files and pcap if available:
        self._extract_console_output(cape_task.id)
        self._extract_injected_exes(cape_task.id)
        self.check_powershell(cape_task.id, parent_section)

    def _unpack_zip(
        self,
        zip_report: bytes,
        file_ext: str,
        cape_task: CapeTask,
        parent_section: ResultSection,
        ontres: OntologyResults,
        custom_tree_id_safelist: List[str],
    ) -> None:
        """
        This method unpacks the zipfile, which contains the report for the task
        :param zip_report: The zipfile in bytes which contains all artifacts from the analysis
        :param file_ext: The file extension of the file to be submitted
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param ontres: The sandbox ontology class object
        :param custom_tree_id_safelist: A list of hashes used for safelisting process tree IDs
        :return: None
        """
        zip_file_name = f"{cape_task.id}_cape_report.zip"
        zip_report_path = os.path.join(self.working_directory, zip_file_name)

        self._add_zip_as_supplementary_file(
            zip_file_name, zip_report_path, zip_report, cape_task
        )
        zip_obj = ZipFile(zip_report_path)

        try:
            report_json_path = self._add_json_as_supplementary_file(zip_obj, cape_task)
        except MissingCapeReportException:
            report_json_path = None
            no_json_res_sec = ResultTextSection("The CAPE JSON Report Is Missing!")
            no_json_res_sec.add_line("Please alert your CAPE administrators.")
            parent_section.add_subsection(no_json_res_sec)
        if report_json_path:
            cape_artifact_pids, main_process_tuples = self._build_report(
                report_json_path, file_ext, cape_task, parent_section, ontres, custom_tree_id_safelist
            )
        else:
            cape_artifact_pids: List[Dict[str, str]] = list()
            main_process_tuples: List[Tuple[int, str]] = []

        # Check for any extra files in full report to add as extracted files
        try:
            self._extract_hollowshunter(zip_obj, cape_task.id, main_process_tuples)
            self._extract_artifacts(
                zip_obj, cape_task.id, cape_artifact_pids, parent_section, ontres
            )

        except Exception as e:
            self.log.exception(
                f"Unable to add extra file(s) for "
                f"task {cape_task.id}. Exception: {e}"
            )
        zip_obj.close()

    def _add_zip_as_supplementary_file(
        self,
        zip_file_name: str,
        zip_report_path: str,
        zip_report: bytes,
        cape_task: CapeTask,
    ) -> None:
        """
        This method adds the zipfile report as a supplementary file to Assemblyline
        :param zip_file_name: The name of the zipfile
        :param zip_report_path: The path where the zipfile is located
        :param zip_report: The zipfile report in bytes
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :return: None
        """
        try:
            report_file = open(zip_report_path, "wb")
            report_file.write(zip_report)
            report_file.close()
            artifact = {
                "name": zip_file_name,
                "path": zip_report_path,
                "description": "CAPE Sandbox analysis report archive (zip)",
                "to_be_extracted": False,
            }
            self.artifact_list.append(artifact)
            self.log.debug(
                f"Adding supplementary file {zip_file_name} for task {cape_task.id}"
            )
        except Exception as e:
            self.log.exception(
                f"Unable to add tar of complete report for "
                f"task {cape_task.id} due to {e}"
            )

    def _add_json_as_supplementary_file(
        self, zip_obj: ZipFile, cape_task: CapeTask
    ) -> str:
        """
        This method adds the JSON report as a supplementary file to Assemblyline
        :param zip_obj: The tarball object, containing the analysis artifacts for the task
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :return: A string representing the path of the report in JSON format
        """
        report_json_path = ""
        try:
            member_name = "reports/lite.json"
            if member_name in zip_obj.namelist():
                task_dir = os.path.join(self.working_directory, f"{cape_task.id}")
                report_json_path = os.path.join(task_dir, member_name)
                report_name = f"{cape_task.id}_report.json"

                zip_obj.extract(member_name, path=task_dir)
                artifact = {
                    "name": report_name,
                    "path": report_json_path,
                    "description": "CAPE Sandbox report (json)",
                    "to_be_extracted": False,
                }
                self.artifact_list.append(artifact)
                self.log.debug(
                    f"Adding supplementary file {report_name} for task {cape_task.id}"
                )
            else:
                raise MissingCapeReportException
        except MissingCapeReportException:
            raise
        except Exception as e:
            self.log.exception(
                f"Unable to add report.json for task {cape_task.id}. Exception: {e}"
            )
        return report_json_path

    def _build_report(
        self,
        report_json_path: str,
        file_ext: str,
        cape_task: CapeTask,
        parent_section: ResultSection,
        ontres: OntologyResults,
        custom_tree_id_safelist: List[str],
    ) -> Tuple[List[Dict[str, str]], List[Tuple[int, str]]]:
        """
        This method loads the JSON report into JSON and generates the Assemblyline result from this JSON
        :param report_json_path: A string representing the path of the report in JSON format
        :param file_ext: The file extension of the file to be submitted
        :param cape_task: The CapeTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param ontres: The sandbox ontology class object
        :param custom_tree_id_safelist: A list of hashes used for safelisting process tree IDs
        :return: A list of dictionaries with details about the payloads and the pids that they were hollowed out of, and a list of tuples representing both the PID of
        the initial process and the process name
        """
        try:
            # Setting environment recursion limit for large JSONs
            setrecursionlimit(int(self.config["recursion_limit"]))
            # Reading, decoding and converting to JSON
            cape_task.report = loads(
                open(report_json_path, "rb").read().decode("utf-8")
            )
        except JSONDecodeError as e:
            self.log.exception(f"Failed to decode the json: {str(e)}")
            raise e
        except Exception as e:
            url = cape_task.query_report_url % cape_task.id + "/" + "all"
            raise Exception(
                f"Exception converting extracted CAPE report into json from zip file: "
                f"report url: {url}, file_name: {self.file_name} due to {e}"
            )
        try:
            machine_name: Optional[str] = None
            report_info = cape_task.report.get("info", {})
            machine = report_info.get("machine", {})

            if isinstance(machine, dict):
                machine_name = machine.get("name")

            machine_info: Dict[str, Any] = {}
            if machine_name is None:
                self.log.warning("Unable to retrieve machine name from result.")
            else:
                machine_info = self.report_machine_info(
                    machine_name, cape_task, parent_section
                )
            self.log.debug(
                f"Generating AL Result from CAPE results for task {cape_task.id}."
            )
            cape_artifact_pids, main_process_tuples = generate_al_result(
                cape_task.report,
                parent_section,
                file_ext,
                self.config.get("random_ip_range"),
                self.routing,
                self.safelist,
                machine_info,
                ontres,
                custom_tree_id_safelist,
                self.config.get("inetsim_dns_servers", []),
            )
            return cape_artifact_pids, main_process_tuples
        except RecoverableError as e:
            self.log.error(f"Recoverable error. Error message: {repr(e)}")
            if cape_task and cape_task.id is not None:
                self.delete_task(cape_task)
            raise
        except CapeProcessingException:
            # Catching the CapeProcessingException, attempting to delete the file, and then carrying on
            self.log.error("Processing error occurred generating report")
            if cape_task and cape_task.id is not None:
                self.delete_task(cape_task)
            raise
        except Exception as e:
            self.log.error(f"Error generating report: {repr(e)}")
            if cape_task and cape_task.id is not None:
                self.delete_task(cape_task)
            raise

    def _extract_console_output(self, task_id: int) -> None:
        """
        This method adds a file containing console output, if it exists
        :param task_id: An integer representing the CAPE Task ID
        :return: None
        """
        # Check if there are any files consisting of console output from detonation
        console_output_file_name = f"{task_id}_console_output.txt"
        console_output_file_path = os.path.join("/tmp", console_output_file_name)
        if os.path.exists(console_output_file_path):
            artifact = {
                "name": console_output_file_name,
                "path": console_output_file_path,
                "description": "Console Output Observed",
                "to_be_extracted": False,
            }
            self.artifact_list.append(artifact)
            self.log.debug(f"Adding supplementary file {console_output_file_name}")

    def _extract_injected_exes(self, task_id: int) -> None:
        """
        This method adds files containing injected exes, if they exist
        :param task_id: An integer representing the CAPE Task ID
        :return: None
        """
        # Check if there are any files consisting of injected exes
        temp_dir = "/tmp"
        injected_exes: List[str] = []
        for f in os.listdir(temp_dir):
            file_path = os.path.join(temp_dir, f)
            if os.path.isfile(file_path) and match(
                INJECTED_EXE_REGEX % task_id, file_path
            ):
                injected_exes.append(file_path)

        for injected_exe in injected_exes:
            artifact = {
                "name": injected_exe,
                "path": injected_exe,
                "description": "Injected executable was found written to memory",
                "to_be_extracted": True,
            }
            self.artifact_list.append(artifact)
            self.log.debug(f"Adding extracted file for task {task_id}: {injected_exe}")

    def _extract_artifacts(
        self,
        zip_obj: ZipFile,
        task_id: int,
        cape_artifact_pids: List[Dict[str, str]],
        parent_section: ResultSection,
        ontres: OntologyResults,
    ) -> None:
        """
        This method extracts certain artifacts from that zipfile
        :param zip_obj: The zipfile object, containing the analysis artifacts for the task
        :param task_id: An integer representing the CAPE Task ID
        :param cape_artifact_pids: A list of dictionaries with details about the payloads and the pids that they were hollowed out of
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param ontres: The sandbox ontology class object
        :return: None
        """
        image_section = ResultImageSection(
            self.request, f"Screenshots taken during Task {task_id}"
        )

        # Extract buffers, screenshots and anything else
        zip_file_map = {
            "shots": "Screenshot captured during analysis",
            "dump.pcap": "TCPDUMP captured during analysis",
            # This description is relevant to the evtx files within the zip
            "evtx/evtx.zip": "EVTX generated during analysis",
            "network": None,  # These are only used for updating the sandbox ontology
            "files/": "File extracted during analysis",
            "sum.pcap": "TCPDUMP captured during analysis",
            # These keys will only be accessed if deep scan is on or if a CAPE payload
            # has a YARA rule associated with it
            "CAPE": "Memory Dump",
            "procdump": "Memory Dump",
        }
        if self.request.deep_scan:
            zip_file_map["macros"] = "Macros found during analysis"

        task_dir = os.path.join(self.working_directory, f"{task_id}")
        for key, value in zip_file_map.items():
            key_hits = [
                x.filename for x in zip_obj.filelist if x.filename.startswith(key)
            ]
            key_hits.sort()

            # We are going to get a snippet of the first 256 bytes of these files and
            # update the HTTP call details with them
            if key == "network":
                for f in key_hits:
                    nh = ontres.get_network_http_by_path(f)
                    if not nh:
                        continue
                    destination_file_path = os.path.join(task_dir, f)
                    zip_obj.extract(f, path=task_dir)
                    contents = str(open(destination_file_path, "rb").read(256))
                    if contents == "b''":
                        continue
                    if nh.request_body_path == f:
                        nh.update(request_body=contents)
                    elif nh.response_body_path == f:
                        nh.update(response_body=contents)
                continue
            # We receive the evtx.zip file and want to extract the files found inside
            elif key == "evtx/evtx.zip" and len(key_hits) == 1:
                destination_file_path = os.path.join(task_dir, key)
                zip_obj.extract(key, path=task_dir)
                evtx_zip_obj = ZipFile(destination_file_path)
                for x in evtx_zip_obj.filelist:
                    evtx_file_path = os.path.join(task_dir, x.filename)
                    evtx_zip_obj.extract(x.filename, path=task_dir)
                    artifact = {
                        "name": f"{task_id}_{x.filename}",
                        "path": evtx_file_path,
                        "description": value,
                        "to_be_extracted": True,
                    }
                    self.artifact_list.append(artifact)
                    self.log.debug(
                        f"Adding extracted file for task {task_id}: {task_id}_{x.filename}"
                    )
                os.remove(destination_file_path)
                continue

            for f in key_hits:
                # No empty files!
                if (
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    in f
                ):
                    continue
                destination_file_path = os.path.join(task_dir, f)
                zip_obj.extract(f, path=task_dir)
                file_name = None

                # If we are here, we really want to make sure we want these dumps
                if key in ["CAPE", "procdump"]:
                    # If extract_cape_dumps or deep_scan is set to true, we want them all!
                    if not self.config["extract_cape_dumps"] or not self.request.deep_scan:
                        yara_hit = False
                        # If we don't want them all, we only want those with yara hits
                        for artifact_dict in cape_artifact_pids:
                            if artifact_dict["sha256"] in f and artifact_dict["is_yara_hit"]:
                                yara_hit = True
                                break

                        # We don't want this
                        if not yara_hit:
                            continue

                    pid = next(
                        (
                            artifact_dict.get("pid")
                            for artifact_dict in cape_artifact_pids
                            if artifact_dict.get("sha256") and artifact_dict["sha256"] in f
                        ),
                        None,
                    )
                    if pid:
                        file_name = f"{task_id}_{pid}_{f}"
                # The majority of files extracted by CAPE are junk and follow a similar file type pattern
                elif key in ["files/"]:
                    file_type_details = self.identify.fileinfo(destination_file_path)
                    if file_type_details["type"] == "unknown":
                        self.log.debug(
                            f"We are not extracting {destination_file_path} for task {task_id} "
                            "because we suspect it is garbage.")
                        continue
                    # If the initial file is an HTML file and there is the possibility that Internet Explorer could
                    # have run, we should check if any of the extracted files are RecoveryStore files
                    elif file_type_details["type"] == "document/office/recoverystore" and self.request.file_type == "code/html":
                        self.log.debug(
                            f"We are not extracting {destination_file_path} for task {task_id} "
                            "because we suspect it is garbage generated by Internet Explorer.")
                        continue

                if not file_name:
                    file_name = f"{task_id}_{f}"

                if key in ["shots"]:
                    to_be_extracted = False
                    # AL generates thumbnails already
                    if "_small" not in f:
                        try:
                            image_section.add_image(destination_file_path, file_name, value)
                        except OSError as e:
                            self.log.debug(f"Unable to add image due to {e}")
                    continue
                else:
                    to_be_extracted = True

                artifact = {
                    "name": file_name,
                    "path": destination_file_path,
                    "description": value,
                    "to_be_extracted": to_be_extracted,
                }
                self.artifact_list.append(artifact)
                self.log.debug(f"Adding extracted file for task {task_id}: {file_name}")
        if image_section.body:
            parent_section.add_subsection(image_section)

    def _extract_hollowshunter(
        self, zip_obj: ZipFile, task_id: int, main_process_tuples: List[Tuple[int, str]]
    ) -> None:
        """
        This method extracts HollowsHunter dumps from the tarball
        :param zip_obj: The tarball object, containing the analysis artifacts for the task
        :param task_id: An integer representing the CAPE Task ID
        :param main_process_tuple: A list of tuples representing both the PID of
        the initial process and the process name
        :return: None
        """
        task_dir = os.path.join(self.working_directory, f"{task_id}")
        report_pattern = compile(HOLLOWSHUNTER_REPORT_REGEX)
        dump_pattern = compile(HOLLOWSHUNTER_DUMP_REGEX)
        report_list = list(filter(report_pattern.match, zip_obj.namelist()))
        dump_list = list(filter(dump_pattern.match, zip_obj.namelist()))

        hh_tuples = [
            (report_list, "HollowsHunter report (json)", False),
            (dump_list, "Memory Dump", True),
        ]
        for hh_tuple in hh_tuples:
            paths, desc, to_be_extracted = hh_tuple
            for path in paths:
                # CAPE injects the initial process with the monitor in a way that causes HollowsHunter to always
                # dump the initial process. Therefore we want to avoid extracting this dump.
                if ".exe" in path:
                    hit = False
                    for main_process_tuple in main_process_tuples:
                        pid, image = main_process_tuple
                        if f"hh_process_{pid}_" in path and image in path:
                            hit = True
                            break

                    if hit:
                        continue

                full_path = os.path.join(task_dir, path)
                file_name = f"{task_id}_{path}"
                zip_obj.extract(path, path=task_dir)
                # Confirm that file is indeed a PE
                if ".dll" in path or ".exe" in path:
                    if os.path.exists(full_path):
                        with open(full_path, "rb") as f:
                            file_contents = f.read(256)
                        if not any(
                            PE_indicator in file_contents
                            for PE_indicator in PE_INDICATORS
                        ):
                            self.log.debug(
                                f"{path} is not a valid PE. Will not upload."
                            )
                            os.remove(full_path)
                            continue
                artifact = {
                    "name": file_name,
                    "path": full_path,
                    "description": desc,
                    "to_be_extracted": to_be_extracted,
                }
                self.artifact_list.append(artifact)
                self.log.debug(
                    f"Adding HollowsHunter file {file_name} for task {task_id}"
                )

    def _safely_get_param(self, param: str) -> Optional[Any]:
        """
        This method provides a safe way to grab a parameter that may or may not exist in the service configuration
        :param param: The name of the parameter
        :return: The value of the parameter, if it exists
        """
        param_value: Optional[Any] = None
        try:
            param_value = self.request.get_param(param)
        except Exception:
            pass
        return param_value

    @staticmethod
    def _determine_relevant_images(
        file_type: str,
        possible_images: List[str],
        auto_architecture: Dict[str, Dict[str, List]],
        all_relevant: bool = False,
    ) -> List[str]:
        """
        This method determines the relevant images that a file should be sent to based on its type
        :param file_type: The type of file to be submitted
        :param possible_images: A list of images available
        :param auto_architecture: A dictionary indicating an override to relevant images selected
        :param all_relevant: A boolean representing if we want all relevant images
        :return: A list of images that the file should be sent to
        """
        if auto_architecture == {}:
            auto_architecture = {
                WINDOWS_IMAGE_PREFIX: {x64_IMAGE_SUFFIX: [], x86_IMAGE_SUFFIX: []},
                LINUX_IMAGE_PREFIX: {x64_IMAGE_SUFFIX: [], x86_IMAGE_SUFFIX: []},
            }
        if file_type in LINUX_x64_FILES:
            platform = LINUX_IMAGE_PREFIX
            arch = x64_IMAGE_SUFFIX
        elif file_type in LINUX_x86_FILES:
            platform = LINUX_IMAGE_PREFIX
            arch = x86_IMAGE_SUFFIX
        elif file_type in WINDOWS_x86_FILES:
            platform = WINDOWS_IMAGE_PREFIX
            arch = x86_IMAGE_SUFFIX
        else:
            # If any other file is submitted than what is listed below, then send it to a 64-bit Windows image
            platform = WINDOWS_IMAGE_PREFIX
            arch = x64_IMAGE_SUFFIX

        if not all_relevant and len(auto_architecture[platform][arch]) > 0:
            images_to_send_file_to = [
                image
                for image in auto_architecture[platform][arch]
                if image in possible_images
            ]
        else:
            images_to_send_file_to = [
                image
                for image in possible_images
                if all(item in image for item in [platform, arch])
            ]
        return images_to_send_file_to

    def _handle_specific_machine(self, kwargs: Dict[str, Any]) -> Tuple[bool, bool]:
        """
        This method handles if a specific machine was requested
        :param kwargs: The keyword arguments that will be sent to CAPE when submitting the file, detailing specifics
        about the run
        :return: A tuple containing if a machine was requested, and if that machine exists
        """
        machine_requested = False
        machine_exists = False

        specific_machine = self._safely_get_param("specific_machine")
        if specific_machine:
            machine_names: List[str] = []
            if len(self.hosts) > 1:
                try:
                    host_ip, specific_machine = specific_machine.split(":")
                except ValueError:
                    self.log.error(
                        "If more than one host is specified in the service_manifest.yml, "
                        "then the specific_machine value must match the format '<host-ip>:<machine-name>'"
                    )
                    raise
                for host in self.hosts:
                    if host_ip == host["ip"]:
                        machine_names = [
                            machine["name"] for machine in host["machines"]
                        ]
                        break
            else:
                if ":" in specific_machine:
                    _, specific_machine = specific_machine.split(":")
                machine_names = [
                    machine["name"] for machine in self.hosts[0]["machines"]
                ]
            machine_requested = True
            if any(specific_machine == machine_name for machine_name in machine_names):
                machine_exists = True
                kwargs["machine"] = specific_machine
            elif self.retry_on_no_machine:
                self.log.warning(f"The requested machine '{specific_machine}' is currently unavailable. Sleep and retry!")
                sleep(self.timeout)
                raise RecoverableError("Retrying since the specific machine was missing...")
            else:
                self.log.error(f"The requested machine '{specific_machine}' is currently unavailable.")
                no_machine_sec = ResultTextSection('Requested Machine Does Not Exist')
                no_machine_sec.add_line(f"The requested machine '{specific_machine}' is currently unavailable.")
                no_machine_sec.add_line("General Information:")
                no_machine_sec.add_line(
                    f"At the moment, the current machine options for this CAPE deployment include {machine_names}."
                )
                self.file_res.add_section(no_machine_sec)
        return machine_requested, machine_exists

    def _handle_specific_platform(
        self, kwargs: Dict[str, Any]
    ) -> Tuple[bool, Dict[str, List[str]]]:
        """
        This method handles if a specific platform was requested
        :param kwargs: The keyword arguments that will be sent to CAPE when submitting the file, detailing specifics
        about the run
        :return: A tuple containing if a platform was requested, and where that platform exists
        """
        platform_requested = False
        hosts_with_platform: Dict[str, List[str]] = {}
        machine_platform_set = set()
        specific_platform = self._safely_get_param("platform")
        hosts_with_platform[specific_platform] = []
        if specific_platform == NO_PLATFORM:
            return platform_requested, {}
        else:
            platform_requested = True

        # Check every machine on every host
        for host in self.hosts:
            machine_platforms = set(
                [machine["platform"] for machine in host["machines"]]
            )
            machine_platform_set = machine_platform_set.union(machine_platforms)
            if specific_platform in machine_platforms:
                hosts_with_platform[specific_platform].append(host["ip"])
                continue
        kwargs["platform"] = specific_platform

        if platform_requested and not hosts_with_platform[specific_platform]:
            if self.retry_on_no_machine:
                self.log.warning(f"The requested platform '{specific_platform}' is currently unavailable. Sleep and retry!")
                sleep(self.timeout)
                raise RecoverableError("Retrying since the specific platform was missing...")
            else:
                self.log.error(f"The requested platform '{specific_platform}' is currently unavailable.")
                no_platform_sec = ResultSection(title_text='Requested Platform Does Not Exist')
                no_platform_sec.add_line(f"The requested platform '{specific_platform}' is currently unavailable.")
                no_platform_sec.add_line("General Information:")
                no_platform_sec.add_line(
                    "At the moment, the current platform options for "
                    f"this CAPE deployment include {sorted(machine_platform_set)}.")
                self.file_res.add_section(no_platform_sec)
        else:
            kwargs["platform"] = specific_platform
        return platform_requested, hosts_with_platform

    def _handle_specific_image(self) -> Tuple[bool, Dict[str, List[str]]]:
        """
        This method handles if a specific image was requested
        :return: A tuple containing if a specific image was requested, and a map of images with hosts that contain
        that image
        """
        image_requested = False
        # This will follow the format {"<image-tag>": ["<host-ip>"]}
        relevant_images: Dict[str, List[str]] = {}

        specific_image = self._safely_get_param("specific_image")
        if specific_image:
            image_requested = True
            if specific_image in [RELEVANT_IMAGE_TAG, ALL_RELEVANT_IMAGES_TAG]:
                all_relevant = specific_image == ALL_RELEVANT_IMAGES_TAG
                relevant_images_list = self._determine_relevant_images(
                    self.request.file_type,
                    self.allowed_images,
                    self.config.get("auto_architecture", {}),
                    all_relevant,
                )
                for relevant_image in relevant_images_list:
                    self._set_hosts_that_contain_image(relevant_image, relevant_images)
            elif specific_image == ALL_IMAGES_TAG:
                for image in self.allowed_images:
                    self._set_hosts_that_contain_image(image, relevant_images)
            else:
                self._set_hosts_that_contain_image(specific_image, relevant_images)
            if not relevant_images:
                msg = specific_image if specific_image not in [RELEVANT_IMAGE_TAG, ALL_RELEVANT_IMAGES_TAG] else f"{specific_image} ({relevant_images_list})"
                if self.retry_on_no_machine:
                    self.log.warning(f"The requested image '{msg}' is currently unavailable. Sleep and retry!")
                    sleep(self.timeout)
                    raise RecoverableError("Retrying since the specific image was missing...")
                else:
                    self.log.error(f"The requested image '{msg}' is currently unavailable.")
                    all_machines = [machine for host in self.hosts for machine in host["machines"]]
                    available_images = self._get_available_images(all_machines, self.allowed_images)
                    no_image_sec = ResultSection('Requested Image Does Not Exist')
                    no_image_sec.add_line(f"The requested image '{msg}' is currently unavailable.")
                    no_image_sec.add_line("General Information:")
                    no_image_sec.add_line(
                        f"At the moment, the current image options for this CAPE deployment include {available_images}.")
                    self.file_res.add_section(no_image_sec)
        return image_requested, relevant_images

    def _determine_host_to_use(self, hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        This method determines which host to send a file to, based on randomness and the length of the host's pending
        task queue
        :param hosts: The hosts that the file could be sent to
        :return: The host that the file will be sent to
        """
        # This method will be used to determine the host to use for a submission
        # Key aspect that we are using to make a decision is the # of pending tasks, aka the queue size
        host_details: List[Dict[str, Any], int] = []
        min_queue_size = maxsize

        success = False
        while not success:
            # Cycle through each host
            for host in hosts:
                host_status_url = f"http://{host['ip']}:{host['port']}/{APIv2_BASE_ENDPOINT}/{CAPE_API_QUERY_HOST}"
                try:
                    resp = self.session.get(host_status_url, headers=host["auth_header"], timeout=self.timeout)
                except requests.exceptions.Timeout:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{host_status_url} timed out after {self.timeout}s "
                        "trying to query the host.'"
                    )
                    if len(hosts) == 1:
                        sleep(5)
                    continue
                except requests.ConnectionError as e:
                    if self.is_connection_error_worth_logging(repr(e)):
                        self.log.error(
                            "The cape-web.service is most likely down. "
                            f"Indicator: '{host_status_url} failed to query the host due to {e}.'"
                        )
                    if len(hosts) == 1:
                        sleep(5)
                    continue
                if resp.status_code != 200:
                    self.log.error(
                        "The cape-web.service is most likely down. "
                        f"Indicator: '{host_status_url} failed with status code {resp.status_code} "
                        "trying to query the host.'"
                    )
                    if len(hosts) == 1:
                        sleep(5)
                    continue
                else:
                    resp_json = resp.json()
                    if "error" in resp_json and resp_json['error']:
                        self.log.error(
                            f"Failed to query the host for {host_status_url} due "
                            f"to '{resp_json['error_value']}'."
                        )
                        raise InvalidCapeRequest("There is most likely an issue with how the service is configured to interact with CAPE's REST API. Check the service logs for more details.")
                    elif "data" in resp_json and resp_json["data"]:
                        queue_size = resp_json["data"]["tasks"]["pending"]
                        host_details.append({"host": host, "queue_size": queue_size})
                        if queue_size < min_queue_size:
                            min_queue_size = queue_size
                        success = True
                    else:
                        self.log.error(
                            "The cape-web.service is most likely down. "
                            f"Indicator: '{host_status_url} failed with status code {resp.status_code} "
                            f"trying to query the host. Data returned was: {resp_json}'"
                        )
                        if len(hosts) == 1:
                            sleep(5)
                        continue

        # If the minimum queue size is shared by multiple hosts, choose a random one.
        min_queue_hosts = [
            host_detail["host"]
            for host_detail in host_details
            if host_detail["queue_size"] == min_queue_size
        ]
        if len(min_queue_hosts) > 0:
            return choice(min_queue_hosts)
        else:
            raise CapeVMBusyException(
                f"No host available for submission between {[host['ip'] for host in hosts]}"
            )

    def _is_invalid_analysis_timeout(
        self, parent_section: ResultSection, reboot: bool = False
    ) -> bool:
        """
        This method determines if the requested analysis timeout is valid
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param reboot: A boolean representing if we want to reboot the sample post initial analysis
        :return: A boolean representing if the analysis timeout is invalid
        """
        requested_timeout = int(self.request.get_param("analysis_timeout_in_seconds"))
        # If we are considering rebooting, we want to ensure that the service won't time out before we're done. The
        # assumption here is that the reboot will take approximately the same time as the initial submission
        if reboot:
            requested_timeout *= 2
        service_timeout = int(self.service_attributes["timeout"])
        if requested_timeout > service_timeout:
            invalid_timeout_res_sec = ResultTextSection(
                "Invalid Analysis Timeout Requested"
            )
            invalid_timeout_res_sec.add_line(
                f"The analysis timeout requested was {requested_timeout}, which exceeds the time that Assemblyline "
                f"will run the service ({service_timeout}). Choose an analysis timeout value < {service_timeout} and "
                "submit the file again."
            )
            parent_section.add_subsection(invalid_timeout_res_sec)
            return True
        return False

    def _get_subsection_heuristic_map(
        self, subsections: List[ResultSection], section_heur_map: Dict[str, int]
    ) -> None:
        """
        This method uses recursion to eliminate duplicate heuristics
        :param subsections: The subsections which we will iterate through, searching for heuristics
        :param section_heur_map: The heuristic map which is used for heuristic deduplication
        :return: None
        """
        for subsection in subsections:
            if subsection.heuristic:
                if subsection.title_text in section_heur_map:
                    # If more than one subsection exists with the same title text, then there should be no heuristic
                    # associated with the second subsection, as this will artificially inflate the overall score
                    subsection.set_heuristic(None)
                else:
                    section_heur_map[
                        subsection.title_text
                    ] = subsection.heuristic.heur_id
            if subsection.subsections:
                self._get_subsection_heuristic_map(
                    subsection.subsections, section_heur_map
                )

    def _determine_if_reboot_required(self, parent_section) -> bool:
        """
        This method determines if we should create a reboot task for the original task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: A boolean indicating if we should create a reboot task
        """
        # If the user has requested a reboot analysis, then make it happen
        reboot = self._safely_get_param("reboot")
        if reboot:
            return True

        # If a sample has raised a signature that would indicate that it will behave differently upon reboot,
        # then make it happen
        for subsection in parent_section.subsections:
            if subsection.title_text == SIGNATURES_SECTION_TITLE:
                for subsubsection in subsection.subsections:
                    if any(
                        item in subsubsection.title_text
                        for item in ["persistence_autorun", "creates_service"]
                    ):
                        return True
        return False

    @staticmethod
    def _cleanup_leftovers() -> None:
        """
        This method cleans up any leftover files that were written to the /tmp dir by previous runs
        :return: None
        """
        temp_dir = "/tmp"
        for file in os.listdir(temp_dir):
            file_path = os.path.join(temp_dir, file)
            if any(
                leftover_file_name in file_path
                for leftover_file_name in ["_console_output", "_injected_memory_"]
            ):
                os.remove(file_path)

    def _get_machine_by_name(self, machine_name) -> Optional[Dict[str, Any]]:
        """
        This method grabs the machine info (if it exists) of a machine that matches the requested name
        :param machine_name: The name of the machine that we want the information for
        :return: The information about the requested machine
        """
        machine_name_exists = False
        machine: Optional[Dict[str, Any]] = None
        machines = [machine for host in self.hosts for machine in host["machines"]]
        for machine in machines:
            if machine["name"] == machine_name:
                machine_name_exists = True
                break
        if machine_name_exists:
            return machine
        else:
            self.log.info(f"Machine {machine_name} does not exist in {machines}.")
            return None

    def is_connection_error_worth_logging(self, error: str) -> bool:
        """
        This method checks if an error is worth logging
        :param error: The string representation of the error
        :return: The boolean flag indicating that the error is worth logging
        """
        if self.uwsgi_with_recycle:
            return not any(e in error for e in CONNECTION_ERRORS)
        else:
            return True


def generate_random_words(num_words: int) -> str:
    """
    This method generates a bunch of random words
    :param num_words: The number of random words to be generated
    :return: A bunch of random words
    """
    alpha_nums = (
        [chr(x + 65) for x in range(26)]
        + [chr(x + 97) for x in range(26)]
        + [str(x) for x in range(10)]
    )
    return " ".join(
        [
            "".join([choice(alpha_nums) for _ in range(int(random() * 10) + 2)])
            for _ in range(num_words)
        ]
    )


def tasks_are_similar(
    task_to_be_submitted: CapeTask, tasks_that_have_been_submitted: List[Dict[str, Any]]
) -> bool:
    """
    This method looks for "cache hits" for tasks, based on their submission parameters
    :param task_to_be_submitted: The task to be submitted
    :param tasks_that_have_been_submitted: A list of tasks that have already been submitted
    :return: A boolean representing if this task to be submitted is similar enough to another task that has been
    submitted to represent a "cache hit"
    """
    for task_that_has_been_submitted in tasks_that_have_been_submitted:
        if task_that_has_been_submitted["status"] == ANALYSIS_FAILED:
            continue
        same_file_name = (
            task_that_has_been_submitted["target"] == task_to_be_submitted.file
        )
        same_timeout = (
            task_that_has_been_submitted["timeout"] == task_to_be_submitted["timeout"]
        )
        same_custom = task_that_has_been_submitted[
            "custom"
        ] == task_to_be_submitted.get("custom", "")
        same_package = task_that_has_been_submitted[
            "package"
        ] == task_to_be_submitted.get("package", "")
        same_route = task_that_has_been_submitted["route"] == task_to_be_submitted.get(
            "route", ""
        )
        same_options = task_that_has_been_submitted[
            "options"
        ] == task_to_be_submitted.get("options", "")
        same_memory = task_that_has_been_submitted[
            "memory"
        ] == task_to_be_submitted.get("memory", False)
        # TODO: This value is somehow set to True when we want it to be false
        same_enforce_timeout = task_that_has_been_submitted[
            "enforce_timeout"
        ] == task_to_be_submitted.get("enforce_timeout", False)
        # The recommended architecture tag is automatically added based on file type
        # https://github.com/kevoreilly/CAPEv2/blob/master/lib/cuckoo/core/database.py#L1297:L1314
        same_tags = [
            tag
            for tag in task_that_has_been_submitted["tags"]
            if tag not in [x64_IMAGE_SUFFIX, x86_IMAGE_SUFFIX]
        ] == [task_to_be_submitted.get("tags", "")]
        same_clock = (
            task_to_be_submitted["clock"] == task_that_has_been_submitted["clock"]
        )
        if (
            same_file_name
            and same_timeout
            and same_custom
            and same_package
            and same_route
            and same_options
            and same_memory
            and same_enforce_timeout
            and same_tags
            and same_clock
        ):
            return True
    return False
