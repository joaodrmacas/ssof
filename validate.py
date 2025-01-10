#!/bin/python3

import sys, json
import argparse


class bcolors:
    # https://stackoverflow.com/questions/4842424/list-of-ansi-color-escape-sequences
    GREEN =     '\033[92m'
    YELLOW =    '\033[93m'
    RED =       '\033[91m'
    ENDC =      '\033[0m'
    BOLD =      '\033[1m'
    UNDERLINE = '\033[4m'


def match_keys(keys: list, json_object: list) -> bool:
    return set(keys) == set(json_object.keys())


def is_list_of_strings(ll: list) -> bool:
    return all(map(lambda x: isinstance(x, str), ll))


### a flow is a list of tuples (string, int)
def is_flow(flow) -> bool:
    return isinstance(flow, list) and \
        all(map(lambda x: is_instruction(x), flow))


def is_list_of_flows(ll: list) -> bool:
    return all(map(lambda x: is_flow(x), ll))


### an instruction is a tuple (string, int)
def is_instruction(pp: tuple) -> bool:
    return len(pp) == 2 and \
        isinstance(pp[0], str) and \
        isinstance(pp[1], int)


def is_same_instruction(i1, i2):
    if args.ignore_lines:
        return i1[0] == i2[0]
    else:
        return i1 == i2


def is_same_flow(flow1, flow2):
    if flow1 == [] and flow2 == []:
        return True
    elif flow1 == [] and flow2 != []:
        return False
    elif flow1 != [] and flow2 == []:
        return False
    else:
        for i, f2 in enumerate(flow2):
            if is_same_instruction(f2, flow1[0]):
                return is_same_flow(flow1[1:], flow2[:i] + flow2[i+1:])    
        return False


def is_same_list_of_flows(l1, l2):
    if args.ignore_sanitizers:
        return True
    
    if l1 == [] and l2 == []:
        return True
    elif l1 == [] and l2 != []:
        return False
    elif l1 != [] and l2 == []:
        return False
    else:
        f1 = l1[0]
        for i, f2 in enumerate(l2):
            if is_same_flow(f1, f2):
                return is_same_list_of_flows(l1[1:], l2[:i] + l2[i+1:])
        return False


### Check if json object is a valid pattern
def is_pattern(json_obj) -> bool:
    assert match_keys(['vulnerability', 'sources', 'sanitizers', 'sinks', 'implicit'], json_obj), set(json_obj.keys())
        
    assert isinstance(json_obj['vulnerability'], str), f"vulnerability attribute is of wrong type: {json_obj['vulnerability']}"
        
    assert isinstance(json_obj['sources'], list), f"sources attribute is of wrong type: {json_obj['sources']}"
    assert is_list_of_strings(json_obj['sources']), f"sources attribute is of wrong type: {json_obj['sources']}"

    assert isinstance(json_obj['sanitizers'], list), f"sanitizers attribute is of wrong type: {json_obj['sanitizers']}"
    assert is_list_of_strings(json_obj['sanitizers']), f"sanitizers attribute is of wrong type: {json_obj['sanitizers']}"

    assert isinstance(json_obj['sinks'], list), f"sinks attribute is of wrong type: {json_obj['sinks']}"
    assert is_list_of_strings(json_obj['sinks']), f"sinks attribute is of wrong type: {json_obj['sinks']}"

    assert isinstance(json_obj['implicit'], str), f"implicit attribute is of wrong type: {json_obj['implicit']}"
    assert json_obj['implicit'] in ["yes", "no"], f"implicit attribute is of wrong type: {json_obj['implicit']}"

    return True


### Check if json object is a valid vulnerability output
def is_vulnerability(json_obj) -> bool:
    if args.ignore_implicit:
        assert match_keys(['vulnerability', 'source', 'sink', 'unsanitized_flows', 'sanitized_flows'], json_obj) or \
            match_keys(['vulnerability', 'source', 'sink', 'implicit', 'unsanitized_flows', 'sanitized_flows'], json_obj), set(json_obj.keys())
    else:
        assert match_keys(['vulnerability', 'source', 'sink', 'implicit', 'unsanitized_flows', 'sanitized_flows'], json_obj), set(json_obj.keys())
        
    assert isinstance(json_obj['vulnerability'], str), f"vulnerability attribute is of wrong type: {json_obj['vulnerability']}"
        
    assert is_instruction(json_obj['source']), f"source attribute is of wrong type: {json_obj['source']}"

    assert is_instruction(json_obj['sink']), f"sink attribute is of wrong type: {json_obj['sink']}"

    if not args.ignore_implicit:
        assert isinstance(json_obj['implicit'], str), f"implicit attribute is of wrong type: {json_obj['implicit']}"
        assert json_obj['implicit'] in ["yes", "no"], f"implicit attribute is of wrong type: {json_obj['implicit']}"

    assert isinstance(json_obj['unsanitized_flows'], str), f"unsanitized_flows attribute is of wrong type: {json_obj['unsanitized_flows']}"
    assert json_obj['unsanitized_flows'] in ["yes", "no"], f"unsanitized_flows attribute is of wrong type: {json_obj['unsanitized_flows']}"

    assert isinstance(json_obj['sanitized_flows'], list), f"sanitized_flows attribute is of wrong type: {json_obj['sanitized_flows']}"
    assert is_list_of_flows(json_obj['sanitized_flows']), f"sanitized_flows attribute is of wrong type: {json_obj['sanitized_flows']}"

    return True
    

### 2 vulnerabilities have the same name if they differ in their numbering
##  v == v_3
##  v_1 == v_2
##  v_1_1 == v_1_2
##  v_1_1 != v_1
##  v_1_1 != v_2_1
def is_same_vulnerability_name(name1, name2):
    pos1 = name1.rfind('_')
    pos2 = name2.rfind('_')
    rname1 = name1[:pos1] if pos1 != -1 else name1
    rname2 = name2[:pos2] if pos2 != -1 else name2
    return rname1 == rname2

# assert is_same_vulnerability_name('v', 'v_3') == True
# assert is_same_vulnerability_name('v_1', 'v_2') == True
# assert is_same_vulnerability_name('v_1_1', 'v_1_2') == True
# assert is_same_vulnerability_name('v_1_1', 'v_1') == False
# assert is_same_vulnerability_name('v_1_1', 'v_2_1') == False


### 2 vulnerabilities are the same if they match in everything, 
##  regardless of the order of the sanitized_flows
def is_same_vulnerability(v1, v2) -> bool:
    return is_same_vulnerability_name(v1['vulnerability'], v2['vulnerability']) and \
        is_same_instruction(v1['source'] ,v2['source']) and \
        is_same_instruction(v1['sink'] ,v2['sink']) and \
        (args.ignore_implicit or v1['implicit'] == v2['implicit']) and \
        v1['unsanitized_flows'] == v2['unsanitized_flows'] and \
        is_same_list_of_flows(v1['sanitized_flows'], v2['sanitized_flows'])


def is_vulnerability_in_target(vulnerability, target_list):
    for t in target_list:
        if is_same_vulnerability(vulnerability, t):
            target_list.remove(t)
            return True, target_list

    return False, target_list


### Check if all patterns in filename are valid patterns
def validate_patterns_file(filename: str) -> bool:
    with open(filename, 'r') as f:
        patterns_list = json.loads(f.read())
    assert isinstance(patterns_list, list)

    for json_obj in patterns_list:
        try:
            assert is_pattern(json_obj)
        except Exception as e:
            print(f"\n{bcolors.RED}[-] Incorrect Pattern in file {filename}:\n{e}\n{json_obj}{bcolors.ENDC}\n")
            exit(1)

    print(f"{bcolors.GREEN}[+] All patterns of file {filename} are well defined{bcolors.ENDC}")
   

### Check if all outputs in filename are valid vulnerability outputs
def validate_output_file(filename: str):
    with open(filename, 'r') as f:
        output_list = json.loads(f.read())
    assert isinstance(output_list, list)

    for json_obj in output_list:
        try:
            assert is_vulnerability(json_obj)
        except Exception as e:
            print(f"\n{bcolors.RED}[-] Incorrect Output in file {filename}:\n{e}\n{json_obj}{bcolors.ENDC}\n")
            exit(1)

    print(f"{bcolors.GREEN}[+] All outputs of file {filename} are well defined{bcolors.ENDC}")


### Check if output in output file is the same as in intended output (target)
def check_output(output, target):
    good = []
    extra = []

    with open(output, 'r') as f:
        output_list = json.loads(f.read())
    
    with open(target, 'r') as f:
        target_list = json.loads(f.read())

    for o in output_list:
        res, target_list = is_vulnerability_in_target(o, target_list)
        if res:
            good.append(o)
        else:
            extra.append(o)

    print(f"\nGOOD FLOWS\n{good}")
    if target_list != []:
        print(f"\n{bcolors.RED}\nMISSING FLOWS\n{target_list}{bcolors.ENDC}")
    if extra != []:
        print(f"\n{bcolors.YELLOW}\nWRONG FLOWS\n{extra}{bcolors.ENDC}")



parser = argparse.ArgumentParser()
parser.add_argument("--pattern", '-p', help="Validate <pattern> file", default = False)
### group's output
parser.add_argument("--output", '-o', help="Validate <output> file", default = False)
### intended output
parser.add_argument("--target", '-t', help="Check <output> vs <target_file>", default = False)

parser.add_argument("--ignore_lines", action="store_true", help="allows for mismatch in line numbers")
parser.add_argument("--ignore_implicit", action="store_true", help="allows for mismatch in the \"implicit\" tag")
parser.add_argument("--ignore_sanitizers", action="store_true", help="allows for mismatch in the \"sanitized_flows\" list")

args=parser.parse_args()

if args.ignore_lines:
    print(f"{bcolors.YELLOW}[-]WARNING: Not validating if line numbers are correct!{bcolors.ENDC}")
if args.ignore_implicit:
    print(f"{bcolors.YELLOW}[-]WARNING: Not validating if the implicit flag is present nor if the results are correct!{bcolors.ENDC}")
if args.ignore_sanitizers:
    print(f"{bcolors.YELLOW}[-]WARNING: Not validating if the list of sanitized flows is correct!{bcolors.ENDC}")


print("\n" + "*"*80)
if vars(args)['pattern']:
    validate_patterns_file(vars(args)['pattern'])
if vars(args)['output']:
    validate_output_file(vars(args)['output'])
if vars(args)['output'] and vars(args)['target']:
    validate_output_file(vars(args)['target'])
    check_output(vars(args)['output'], vars(args)['target'])
