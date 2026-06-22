from hashlib import sha256

def convert_processtree_id_to_tree_id(processtree_id: str) -> str:
    possible_sha256 = ""
    for proc in processtree_id.split("|"):
        value_to_create_hash_from = (possible_sha256 + proc).encode()
        tree_id = sha256(value_to_create_hash_from).hexdigest()
        possible_sha256 = tree_id

    return tree_id


print(convert_processtree_id_to_tree_id("?pf\\WindowsApps\\Microsoft.WindowsCalculator_11.2405.2.0_x64__8wekyb3d8bbwe\\CalculatorApp.exe"))