import copy
import json
from venv import create

from src.classes import Vulnerabilities

from collections import OrderedDict

def order_keys(data, key_order):
    """
    Ordena as chaves de um JSON com base numa lista de ordem personalizada.
    
    Args:
        data (dict): Dicionário Python que representa o JSON.
        key_order (list): Lista de chaves na ordem desejada.

    Returns:
        OrderedDict: JSON ordenado com base na ordem especificada.
    """
    # Cria um OrderedDict com a ordem personalizada
    ordered_data = OrderedDict((key, data[key]) for key in key_order if key in data)

    # Adiciona as chaves restantes que não estão na lista de ordem
    ordered_data.update({key: value for key, value in data.items() if key not in key_order})

    return ordered_data

def json_to_file(file_path, vulnerabilities: Vulnerabilities):
    """
    Create JSON output file with vulnerability findings
    """
    try:
        with open(file_path, 'w') as f:
            f.write(create_json(vulnerabilities))
    except Exception as e:
        raise Exception(f"Failed to create output file: {str(e)}")

def print_json(vulnerabilities):
    print(create_json(vulnerabilities))

def create_json(vulnerabilities: Vulnerabilities) -> str:
    key_order = [
        "vulnerability",
        "source",
        "sink",
        "unsanitized_flows",
        "sanitized_flows",
        "implicit"
    ]

    dataArray = []
    for key, value in vulnerabilities.get_report().items():
        for idx, event in enumerate(value):
            pre_json = copy.deepcopy(event)

            pre_json["vulnerability"] = f"{key+"_"+str(idx+1)}"
            dataArray.append(order_keys(pre_json, key_order))

    return json.dumps(dataArray, indent=4)