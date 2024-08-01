import os
import shutil
import tempfile
from typing import Any
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.updater import ServiceUpdater
from assemblyline.common import forge
from cape.yara_modules import *
log = logging.getLogger(__name__)
#level = logging.DEBUG
#log.setLevel(level)
logging.basicConfig(filename='example.log', encoding='utf-8', level=logging.DEBUG)

classification = forge.get_classification()

def replace_include(include, dirname, processed_files: set[str], cur_logger: logging.Logger):
    include_path = re.match(r"include [\'\"](.{4,})[\'\"]", include)
    if not include_path:
        return [], processed_files
    include_path = include_path.group(1)
    full_include_path = os.path.normpath(os.path.join(dirname, include_path))
    if not os.path.exists(full_include_path):
        cur_logger.info(f"File doesn't exist: {full_include_path}")
        return [], processed_files

    temp_lines = ["\n"]  # Start with a new line to separate rules
    if full_include_path not in processed_files:
        processed_files.add(full_include_path)
        with open(full_include_path, "r") as include_f:
            lines = include_f.readlines()

        for i, line in enumerate(lines):
            if line.startswith("include"):
                new_dirname = os.path.dirname(full_include_path)
                lines, processed_files = replace_include(line, new_dirname, processed_files, cur_logger)
                temp_lines.extend(lines)
            else:
                temp_lines.append(line)

    return temp_lines, processed_files

class CapeYaraUpdateServer(ServiceUpdater):
    def __init__(self, *args, externals: dict[str, str], **kwargs):
        super().__init__(*args, **kwargs)
        self.externals = externals
        self.log = log

    def import_update(self, files_sha256, source_name: str, default_classification=classification.UNRESTRICTED) -> None:
        # Purpose:  Used to import a set of signatures from a source into a reserved directory
        # Inputs:
        #   files_sha256:           A list of tuples containing file paths and their respective sha256
        #   client:                 An Assemblyline client used to interact with the API on behalf of a service account
        #   source:                 The name of the source
        #   default_classification: The default classification given to a signature if none is provided

        # You'll want to write your files to self.latest_updates_dir which should hold all your downloaded files.
        # The contents in this directory will then be used by prepare_output_directory().

        # Organize files by source
        processed_files: set[str] = set()
        parser = Plyara()
        parser.STRING_ESCAPE_CHARS.add("r")
        if source_name in ["internal-cape-yara", "internal-cape-community-yara"]:
            upload_list = []
            for file, _ in files_sha256:
                self.log.info(f"Processing file: {file}")
                try:
                    valid = validate_rule(file)
                except Exception as e:
                    self.log.error(f"Error validating {file}: {e}")
                    raise e
                if valid:
                    with open(file, 'r') as fh:
                        upload_list.append(parser.parse_string(fh))
                else:
                    self.log.info(f"Invalid file {file}")
            yara_importer = YaraImporter(self.updater_type, self.client, logger=self.log)
            yara_importer._save_signatures(signatures=upload_list, source=source_name)
        else:
            with tempfile.NamedTemporaryFile(mode="a+", suffix=source_name) as compiled_file:
                # Aggregate files into one major source file
                for file, _ in files_sha256:
                    # File has already been processed before, skip it to avoid duplication of rules
                    if file in processed_files:
                        continue
                    if os.path.splitext(file)[1] not in  [".yar", ".yara"]:
                        continue

                    self.log.info(f"Processing file: {file}")

                    file_dirname = os.path.dirname(file)
                    processed_files.add(os.path.normpath(file))
                    with open(file, "r", errors="surrogateescape") as f:
                        f_lines = f.readlines()

                    temp_lines: list[str] = []
                    for _, f_line in enumerate(f_lines):
                        if f_line.startswith("include"):
                            lines, processed_files = replace_include(f_line, file_dirname, processed_files, self.log)
                            temp_lines.extend(lines)
                        else:
                            temp_lines.append(f_line)

                    # guess the type of files that we have in the current file
                    parser = Plyara()
                    parser.STRING_ESCAPE_CHARS.add("r")
                    # Try parsing the ruleset; on fail, move onto next set
                    try:
                        signatures: list[dict[str, Any]] = parser.parse_string("\n".join(temp_lines))

                        # Save all rules from source into single file
                        for s in signatures:
                            # Fix imports and remove cuckoo
                            s["imports"] = utils.detect_imports(s)
                            compiled_file.write(utils.rebuild_yara_rule(s))
                    except Exception as e:
                        self.log.error(f"Problem parsing {file}: {e}")
                        continue
                yara_importer = YaraImporter(self.updater_type, self.client, logger=self.log)
                try:
                    compiled_file.seek(0)
                    try:
                        validate = YaraValidator(externals=self.externals, logger=self.log)
                        validate.validate_rules(compiled_file.name)
                    except Exception as e:
                        self.log.error(f"Error validating {compiled_file.name}: {e}")
                        raise e
                    yara_importer.import_file(
                        compiled_file.name, source_name, default_classification=default_classification
                    )
                except Exception as e:
                    raise e


    def is_valid(self, file_path) -> bool:
        # Purpose:  Used to determine if the file associated is 'valid' to be processed as a signature
        # Inputs:
        #   file_path:  Path to a signature file from an external source
        validation = validate_rule(file_path)
        if isinstance(validation, bool):
            return validation
        return super().is_valid(file_path) #Returns true always

if __name__ == '__main__':
    with CapeYaraUpdateServer(externals=YARA_EXTERNALS, default_pattern=".*\.yar(a)?") as server:
        server.serve_forever()