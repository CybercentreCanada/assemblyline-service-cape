import os
import shutil
import tempfile
from io import BytesIO
from typing import Any
from zipfile import ZipFile

from assemblyline.common import forge
from assemblyline_v4_service.updater.updater import ServiceUpdater, UPDATER_DIR
from assemblyline.common.isotime import epoch_to_iso

from cape.yara_modules import *

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

    def import_update(self, files_sha256, source_name: str, default_classification=classification.UNRESTRICTED) -> None:
        # Purpose:  Used to import a set of signatures from a source into a reserved directory
        # Inputs:
        #   files_sha256:           A list of tuples containing file paths and their respective sha256
        #   client:                 An Assemblyline client used to interact with the API on behalf of a service account
        #   source:                 The name of the source
        #   default_classification: The default classification given to a signature if none is provided

        processed_files: set[str] = set()
        parser = Plyara()
        parser.STRING_ESCAPE_CHARS.add("r")
        with tempfile.NamedTemporaryFile(mode="a+", suffix=source_name) as compiled_file:
            # Aggregate files into one major source file
            upload_list = []
            yara_importer = YaraImporter(self.updater_type, self.client, logger=self.log)
            for file, _ in files_sha256:
                # File has already been processed before, skip it to avoid duplication of rules
                if file in processed_files:
                    continue

                self.log.info(f"Processing file: {file}")

                file_dirname = os.path.dirname(file)
                processed_files.add(os.path.normpath(file))
                try:
                    valid = validate_rule(file)
                except Exception as e:
                    self.log.error(f"Error validating {file}: {e}")
                    raise e
                if valid:
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
                    # Try parsing the ruleset; on fail, move onto next set
                    try:
                        signatures: list[dict[str, Any]] = parser.parse_string("\n".join(temp_lines))
                        upload_list.extend(signatures)
                    except Exception as e:
                        self.log.error(f"Problem parsing {file}: {e}")
                        continue
            yara_importer._save_signatures(
                signatures=upload_list, source=source_name, default_classification=default_classification
            )

    def is_valid(self, file_path) -> bool:
        # Purpose:  Used to determine if the file associated is 'valid' to be processed as a signature
        # Inputs:
        #   file_path:  Path to a signature file from an external source
        if os.path.isdir(file_path):
            return False
        if not (file_path.endswith(".yar") or file_path.endswith(".yara")):
            return False
        validation = validate_rule(file_path)
        if isinstance(validation, bool):
            return validation
        return super().is_valid(file_path)  # Returns true always

    def do_local_update(self) -> None:
        old_update_time = self.get_local_update_time()
        if not os.path.exists(UPDATER_DIR):
            os.makedirs(UPDATER_DIR)

        # Create a temporary file for the time keeper
        time_keeper = tempfile.NamedTemporaryFile(prefix="time_keeper_", dir=UPDATER_DIR, delete=False)
        time_keeper.close()
        time_keeper = time_keeper.name

        output_directory = tempfile.mkdtemp(prefix="update_dir_", dir=UPDATER_DIR)
        sources_removed_locally = False
        if self._update_dir:
            current_update_dir = os.path.join(self._update_dir, self.updater_type)

            if os.path.exists(current_update_dir):
                sources_removed_locally = set(os.listdir(current_update_dir)) - set(
                    [s.name for s in self._service.update_config.sources]
                )

        # Check if new signatures have been added (or it there's been a local change since the last update)
        self.log.info("Check for new signatures.")
        if sources_removed_locally or self.client.signature.update_available(
            since=epoch_to_iso(old_update_time) or None, sig_type=self.updater_type
        ):
            self.log.info("An update is available for download from the datastore")

            self.log.debug(f"{self.updater_type} update available since {epoch_to_iso(old_update_time) or ''}")
            prescript_CAPE_sources = self._service.config.get("updater", {}).get("prescript_CAPE", [])
            prescript_query = f"{self.signatures_query} AND source:{' OR '.join(prescript_CAPE_sources)}"
            if (
                prescript_CAPE_sources
                and self.client.datastore.signature.search(prescript_query, rows=0, track_total_hits=True)["total"]
            ):
                # Pull the set of YARA signatures related to prescript CAPE
                with ZipFile(BytesIO(self.client.signature.download(prescript_query)), "r") as zip_f:
                    zip_f.extractall(output_directory)
                    self.log.info("New ruleset successfully downloaded and ready to use")
            else:
                self.log.info("No prescript CAPE rules to download")
            self.serve_directory(output_directory, time_keeper)
        else:
            self.log.info("No signature updates available.")
            shutil.rmtree(output_directory, ignore_errors=True)
            if os.path.exists(time_keeper):
                os.unlink(time_keeper)


if __name__ == "__main__":
    with CapeYaraUpdateServer(externals=YARA_EXTERNALS, default_pattern=".*\.yar(a)?") as server:
        server.serve_forever()
