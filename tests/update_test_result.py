import os
import shutil
import sys
sys.path.append('.')
from cape.cape_result import main as main_cape_result

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


for sample in SAMPLES:
    main_cape_result([
        "cape_result.py",
        sample["Report_path"],
        "html",
        "169.254.128.0/24",
        "internet",
        "al_config/system_safelist.yaml",
        "{}",
        "\"169.254.128.2\"",
        False,
        "\"us\""
    ])
    shutil.move("result.json", sample["Result_path"])
    shutil.move("result_ontology.json", sample["Ontology_path"])
    shutil.move("Section.json", sample["Sandbox_section"])

