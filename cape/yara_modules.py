import yara
import os
import logging
import re
from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.client import UpdaterClient
from plyara import Plyara, utils


yara.set_config(max_strings_per_rule=40000, stack_size=65536)

DEFAULT_STATUS = "DEPLOYED"
Classification = forge.get_classification()
YARA_EXTERNALS = {f"al_{x}": x for x in ["submitter", "mime", "file_type", "tag"]}

LIST_OF_VALID_ACTIONS = [
    "run_script",
    "add_file",
    "add_directory",
    "create_registry",
    "modify_registry",
    "create_scheduled_task",
    "create_xml_scheduled_task",
    "modify_scheduled_task",
    "change_execution_dir"
]

ACTIONS_PARAMETERS = {
    "run_script": ["path", "params", "timeout"],
    "add_file": ["src_path", "dst_path", "overwrite"],
    "add_directory": ["path"],
    "create_registry": ["path", "key", "value"],
    "modify_registry": ["path", "key", "value"],
    "create_scheduled_task": ["task_name", "application_name", "priority", "working_directory", "flags", "parameters", "comment", "creator", "account_information", "path", "trigger_type", "start_time", "duration", "interval", "expiration_time", "additional_trigger_params"],
    "create_xml_scheduled_task": ["task_name", "xml"],
    "modify_scheduled_task": ["task_name", "path", "new_task_name", "comment", "action_id", "application_name", "priority", "parameters", "working_directory", "creator", "account_information", "flags", "trigger"],
    "change_execution_dir": ["path"],
}

def yara_scan(rules, raw_data):
    #Add fast mode for possible error ? 
    rules_matched = []
    matches = rules.match(data=raw_data)
    for match in matches:
        rules_matched.append(match)
    return rules_matched


def validate_rule(rulefile):
    valid = True
    try:
        yara.compile(filepath=rulefile).match(data="")
        return valid
    except yara.SyntaxError as e:
        error = str(e)
        e_message = error.split("): ", 1)
        if "identifier" in error:
            # Problem with a rule associated to the identifier (unknown, duplicated)
            invalid_rule_name = e_message.split('"')
        else:
            invalid_rule_name = ""
        return f"Invalid rule: {invalid_rule_name}"

class YaraImporter(object):
    def __init__(self, importer_type: str, al_client: UpdaterClient, logger=None):
        if not logger:
            from assemblyline.common import log as al_log

            al_log.init_logging("cape_yara_importer")
            logger = logging.getLogger("assemblyline.cape_yara_importer")
            logger.setLevel(logging.INFO)

        self.importer_type: str = importer_type
        self.update_client: UpdaterClient = al_client
        self.parser = Plyara()
        self.parser.STRING_ESCAPE_CHARS.add("r")
        self.classification = forge.get_classification()
        self.log = logger

    def _save_signatures(self, signatures, source, default_status=DEFAULT_STATUS, default_classification=None):
        if len(signatures) == 0:
            self.log.info(f"There are no signatures for {source}, skipping...")
            return False

        order = 1
        upload_list = []
        for signature in signatures:
            classification = default_classification or self.classification.UNRESTRICTED
            signature_id = None
            version = 1
            status = default_status

            for meta in signature.get("metadata", {}):
                for k, v in meta.items():
                    if k in ["classification", "sharing"]:
                        classification = v
                    elif k in ["id", "rule_id", "signature_id"]:
                        signature_id = v
                    elif k in ["version", "rule_version", "revision"]:
                        if isinstance(
                            v,
                            (
                                int,
                                bool,
                            ),
                        ):
                            # Handle integer or boolean revisions
                            version = str(v)
                        elif "." in v:
                            # Maintain version schema (M.m)
                            version_split = v.split(".", 1)
                            major = "".join(filter(str.isdigit, version_split[0]))
                            minor = "".join(filter(str.isdigit, version_split[1]))
                            version = f"{major}.{minor}"
                        else:
                            # Fair to assume number found is the major only
                            version = "".join(filter(str.isdigit, v))
                    elif k in ["status", "al_status"]:
                        status = v

            if not version:
                # If there is a null value for a version, then default to original value
                version = 1

            signature_id = signature_id or signature.get("rule_name")

            # Convert CCCS YARA status to AL signature status
            if status == "RELEASED":
                status = "DEPLOYED"
            elif status == "DEPRECATED":
                status = "DISABLED"

            # Fallback status
            if status not in ["DEPLOYED", "NOISY", "DISABLED", "STAGING", "TESTING", "INVALID"]:
                status = default_status

            # Fix imports and remove cuckoo
            signature["imports"] = utils.detect_imports(signature)
            if "cuckoo" not in signature["imports"]:
                sig = Signature(
                    dict(
                        classification=classification,
                        data=utils.rebuild_yara_rule(signature),
                        name=signature.get("rule_name"),
                        order=order,
                        revision=int(float(version)),
                        signature_id=signature_id,
                        source=source,
                        status=status,
                        type=self.importer_type,
                    )
                )
                upload_list.append(sig.as_primitives())
            else:
                self.log.warning(f"Signature '{signature.get('rule_name')}' skipped because it uses cuckoo module.")

            order += 1

        r = self.update_client.signature.add_update_many(source, self.importer_type, upload_list)
        self.log.info(f"Imported {r['success']}/{order - 1} signatures from {source} into Assemblyline")

        return r["success"]

    def _split_signatures(self, data):
        self.parser = Plyara()
        self.parser.STRING_ESCAPE_CHARS.add("r")
        return self.parser.parse_string(data)

    def import_data(self, yara_bin, source, default_status=DEFAULT_STATUS, default_classification=None):
        return self._save_signatures(
            self._split_signatures(yara_bin),
            source,
            default_status=default_status,
            default_classification=default_classification,
        )

    def import_file(self, file_path: str, source: str, default_status=DEFAULT_STATUS, default_classification=None):
        self.log.info(f"Importing file: {file_path}")
        cur_file = os.path.expanduser(file_path)
        if os.path.exists(cur_file):
            with open(cur_file, "r") as yara_file:
                yara_bin = yara_file.read()
                return self.import_data(
                    yara_bin,
                    source or os.path.basename(cur_file),
                    default_status=default_status,
                    default_classification=default_classification,
                )
        else:
            raise Exception(f"File {cur_file} does not exists.")


class YaraValidator(object):
    def __init__(self, externals=None, logger=None):
        if not logger:
            from assemblyline.common import log as al_log

            al_log.init_logging("CapeYaraValidator")
            logger = logging.getLogger("assemblyline.cape_yara_validator")
            logger.setLevel(logging.WARNING)
        if not externals:
            externals = {"dummy": ""}
        self.log = logger
        self.externals = externals
        self.rulestart = re.compile(r"^(?:global )?(?:private )?(?:private )?rule ", re.MULTILINE)
        self.rulename = re.compile("rule ([^{^:]+)")

    def clean(self, rulefile, eline, message, invalid_rule_name):
        with open(rulefile, "r") as f:
            f_lines = f.readlines()
        # List will start at 0 not 1
        error_line = eline - 1

        if invalid_rule_name and "duplicated identifier" in message:
            f_lines[error_line] = f_lines[error_line].replace(invalid_rule_name, f"{invalid_rule_name}_1")
            self.log.warning(
                f"Yara rule '{invalid_rule_name}' was renamed '{invalid_rule_name}_1' because it's "
                f"rule name was used more then once."
            )
        else:
            # First loop to find start of rule
            start_idx = 0
            while True:
                find_start = error_line - start_idx
                if find_start == -1:
                    raise Exception(
                        "Yara Validator failed to find invalid rule start. " f"Yara Error: {message} Line: {eline}"
                    )
                line = f_lines[find_start]
                if re.match(self.rulestart, line):
                    invalid_rule_name = re.search(self.rulename, line).group(1).strip()

                    # Second loop to find end of rule
                    end_idx = 0
                    while True:
                        find_end = error_line + end_idx
                        if find_end >= len(f_lines):
                            raise Exception(
                                "Yara Validator failed to find invalid rule end. "
                                f"Yara Error: {message} Line: {eline}"
                            )
                        line = f_lines[find_end]
                        if re.match(self.rulestart, line) or find_end == len(f_lines) - 1:
                            # Now we have the start and end, strip from file
                            if find_end == len(f_lines) - 1:
                                f_lines = f_lines[:find_start]
                            else:
                                f_lines = f_lines[:find_start] + f_lines[find_end:]
                            break
                        end_idx += 1
                    # Send the error output to AL logs
                    error_message = (
                        f"Yara rule '{invalid_rule_name}' removed from rules file because of an error "
                        f"at line {eline} [{message}]."
                    )
                    self.log.warning(error_message)
                    break
                start_idx += 1

        with open(rulefile, "w") as f:
            f.writelines(f_lines)

        return invalid_rule_name

    def validate_rules(self, rulefile, al_client: UpdaterClient = None):
        change = False
        while True:
            try:
                yara.compile(filepath=rulefile, externals=self.externals).match(data="")
                return change

            # If something goes wrong, clean rules until valid file given
            except yara.SyntaxError as e:
                try:
                    if al_client:
                        # Disable offending rule from Signatures API
                        sig_id = al_client.datastore.signature.search(
                            f"type:yara AND source:{os.path.basename(rulefile)} AND name:{rulefile}",
                            rows=1, fl="id", as_obj=False)['items'][0]["id"]
                        self.log.warning(f"Disabling rule with signature_id {sig_id} because of: {e}")
                        al_client.signature.change_status(sig_id, "DISABLED")
                except Exception as ve:
                    raise ve

                continue