#!/usr/bin/python3 

import kisslib as kiss
import subprocess
import time
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def main():
    target = "../hello_static"
    source_dir = "../static"
    output_file = "static_result"
    
    # db = kiss.DatabaseInstance(source_dir, output_file)
    # db.generate_database_to_file(patch=True)
    # db.construct_from_file()

    functions = {}
    counter = 0
    with open(target, 'rb') as f:
        elffile = ELFFile(f)


        text_offset = elffile.get_section_by_name('.text')['sh_addr']
        print("text offset is: " + hex(text_offset))
        section = elffile.get_section_by_name('.symtab')
        if section is None:
            section = elffile.get_section_by_name('.dynsym')
            if section is None:
                raise Exception('could not read .symtab and .dyntab of {}'.format(current_file))

        for symbol in section.iter_symbols():
            if (symbol.entry['st_info']['type'] == 'STT_FUNC' or symbol.entry['st_info']['type'] == 'STT_LOOS'):
                counter += 1
                functions[symbol.name] = symbol.entry['st_value'] - text_offset

    # for f, a in functions.items():
    #     print("{} @ {}".format(f, a))
    # print(len(functions))
    # print(counter)

    static_analyzer = kiss.StaticAnalizer(target, output_file + ".cdb", output_file + ".ofst")
    # results = static_analyzer.crawl_text_segment(32, 2)
    start_time = time.time()
    results = static_analyzer.crawl_text_segment(32, 2)
    runtime = (time.time() - start_time)

    print("Identified {} functions".format(len(results)))
    print(bcolors.OKBLUE + "Checking the results" + bcolors.ENDC)
    false_positives = 0
    for key, value in results.items():
        print("At address " + str(hex(key)))
        for p in value:
            print("\t{} from {}".format(p.function_name, p.library_name), end=' ')
            if p.function_name in functions:
                if(functions[p.function_name] == key):
                    print(bcolors.OKGREEN + "SUCCESS" + bcolors.ENDC)
                    continue
                print(bcolors.FAIL + "FAIL (offset){}".format(functions[p.function_name]) + bcolors.ENDC)
                false_positives += 1
                continue
            print(bcolors.FAIL + "FAIL (function name)" + bcolors.ENDC)
            false_positives += 1
                
    print("Summary:")
    print("\t\tthere were {} functions in the binary {}".format(len(functions), target))
    print("\t\tidentified {} of them correctly ({}%)".format(len(results) - false_positives, ((len(results) - false_positives)/len(functions)) * 100))
    print("\t\thad {} false positives ({}%)".format(false_positives, (false_positives/len(functions) * 100)))
    print("\t\tthe task was finished in {} seconds".format(runtime))

if __name__ == "__main__":
    main()
    # 12364
    # 76349 247
    # 54674 238
    # 63935
    # 64051 249
    # 9127 197
    # 9119 192
    # 9117
