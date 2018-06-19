#!/usr/bin/python3 

import kisslib as kiss
import glob
import os
import sys
import random
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import multiprocessing as mp
from itertools import islice
import time
import statistics
import csv

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
FUN_TRUNC_LEN = 25
NUM_PROCESSES = 64
SNIPPET_SIZE = 512

# helper
def chunks(data, size):
    it = iter(data)
    for i in range(0, len(data), size):
        yield {k:data[k] for k in islice(it, size)}

def main():
    source_dir = "/mnt/mnt/libcdb/libc"
    snippet_size = 32
    test_amount = 100
    random_seed = 'looks_like_someone_fucked_with_your_RNG'
    
    db = kiss.DatabaseInstance(source_dir, "result")
    db.generate_database_to_file()
    db.construct_from_file()
    # print("DONE constructing database")
    return

    random.seed(random_seed)

    start_time = time.time()
    search_engine = kiss.SearchEngine("result.cdb", "result.ofst")
    database_load_time = time.time() - start_time

    print("AAAAAAAA")
    # Go through files recursivly and pick a snippet in their .text segment at random
    file_list = []
    data_sizes = []
    for file_name in glob.glob(source_dir + '/**/*', recursive=True):
        if os.path.islink(file_name):
            continue
        try:
            with open(file_name, 'rb') as f:
                elffile = ELFFile(f)
                if(elffile.get_machine_arch() != 'x64'):
                    continue
                if(elffile.elfclass != 64):
                    continue

                data_size = len(elffile.get_section_by_name('.text').data())
                # print(file_name)
                # print("text_offset: " + hex(elffile.get_section_by_name('.text')['sh_offset']))
                # return
                file_list.append([file_name, data_size])
                data_sizes.append(data_size)
        except Exception:
            continue
    print("test base has {} files".format(len(file_list)))

    # Make random selections in the testbase
    test_locations = {}
    for _ in range(0, tests_amount):
        # Choose with relative weights
        chosen = random.choices(population=file_list, weights=data_sizes)[0]

        position = random.randint(0, chosen[1] - SNIPPET_SIZE)
        if(chosen[0] in test_locations):
            test_locations[chosen[0]].append(position)
        else:
            test_locations[chosen[0]] = [position]

    # Statistics
    mp.set_start_method('fork')
    manager = mp.Manager()
    stats = manager.dict()
    stats["unidentified"] = 0
    stats["no_fun_name"] = 0
    stats["wrong_fun_name"] = 0
    stats["time_sum"] = 0
    stats["wrong_hit_count"] = manager.dict()
    # stats["counter"] = 0

    # fork off tests
    processes_num = min(NUM_PROCESSES, len(test_locations))
    splitted_test_locations = chunks(test_locations, int(tests_amount / processes_num))

    jobs = []
    for l in splitted_test_locations:
        p = mp.Process(target=forked_test, args=(search_engine, l, stats))
        jobs.append(p)
        p.start()

    # wait for them all to finish
    for proc in jobs:
        proc.join()
        
    time_avg = stats["time_sum"] / tests_amount
    print("\n\nTested {} snippets of size {} and had".format(tests_amount, SNIPPET_SIZE))
    print("\t\t{} succesful identifications".format(tests_amount - stats["unidentified"]))
    # print("\t\t{} false positives".format(sum(stats["wrong_hit_count"])))
    # print("\t\t{} average amount of wrong hits per function".format(statistics.mean(stats["wrong_hit_count"])))
    # print("\t\t{} stdev of amount of wrong hits per function".format(statistics.stdev(stats["wrong_hit_count"])))
    print("\t\t{} wrong function names".format(stats["wrong_fun_name"]))
    print("\t\tthe average query time was {} seconds".format(time_avg))
    print("\t\tthe library was loaded in {}".format(database_load_time))

    # convert wrong_hit_count dict to list
    # wrong_hit_count_list = []

    # print(wrong_hit_count_list)
    with open('false_positives.csv', 'w') as f:  # Just use 'w' mode in 3.x
        writer = csv.writer(f, delimiter=',')
        writer.writerow(["false_positives", "amount"])
        for k, v in stats["wrong_hit_count"].items():
            # wrong_hit_count_list.append([k, v])
            writer.writerow([k, v])


def forked_test(search_engine, test_locations, stats):

    counter = 0
    for current_file, positions in test_locations.items():
        with open(current_file, 'rb') as file:
            elffile = ELFFile(file)
            # First get a list of all symbols
            offsets = []
            sizes = []
            names = []
            section = elffile.get_section_by_name('.symtab')
            if section is None:
                section = elffile.get_section_by_name('.dynsym')
                if section is None:
                    raise Exception('could not read .symtab and .dyntab of {}'.format(current_file))

            for symbol in section.iter_symbols():
                if (symbol.entry['st_info']['type']) == 'STT_FUNC':
                    offsets.append(symbol.entry['st_value'])
                    sizes.append(symbol.entry['st_size'])
                    names.append(symbol.name)
                

            # Extract text segment
            section = elffile.get_section_by_name('.text')
            text_offset = section['sh_offset']
            text = section.data()

            for pos in positions:
                print("test " + str(counter))
                counter += 1
                # Get random snippet of snippet_length
                snippet = text[pos: pos + SNIPPET_SIZE]

                # Identify if in function (which)
                fun_name = None
                for o in range(0, len(offsets)):
                    if(pos + text_offset >= offsets[o] and pos + text_offset < offsets[o] + sizes[o]):
                        fun_name = names[o]
                        break

                # Run kisslib / XXX
                start_time = time.time()
                # print('\nTesting {} with offset {} and length {} [{}]'.format(current_file, hex(pos), SNIPPET_SIZE, None if fun_name == None else fun_name[:FUN_TRUNC_LEN] + "..."))
                # print("It looks like this: " + str(snippet.hex()))
                hits = search_engine.search(bytes(snippet))
                stats["time_sum"] += (time.time() - start_time)
                if(hits == 0 or hits == None):
                    # print(bcolors.FAIL + "\t\t\t Not Found" + bcolors.ENDC)
                    stats["unidentified"] +=1
                    continue
                # print(bcolors.OKBLUE + "\t\t\t{} hits".format(hits) + bcolors.ENDC)
                start_time = time.time()
                results = search_engine.get_locations(hits)
                stats["time_sum"] += (time.time() - start_time)

                # several functions can be described overlapping so multiple hits can be a valid result
                correct = 0
                for r in results:
                    if(fun_name == None):
                        stats["no_fun_name"] += 1
                    # print("\t\t\t{}[{}] -> {}[{}] =>".format(r.library_name, hex(r.in_library_offset), None if r.function_name == None else r.function_name[:FUN_TRUNC_LEN] + "...", None if r.in_function_offset == None else hex(r.in_function_offset)), end=' ')
                    if(r.library_name != current_file):
                        # print(bcolors.FAIL + "FAIL (library)" + bcolors.ENDC)
                        continue
                    if(r.in_library_offset != pos):
                        # print(bcolors.FAIL + "FAIL (offset)" + bcolors.ENDC)
                        continue
                    if(r.function_name != fun_name):
                        # print(bcolors.WARNING + "WARN (function_name)" + bcolors.ENDC)
                        stats["wrong_fun_name"] += 1
                    # else:
                        # print(bcolors.OKGREEN + "SUCCESS" + bcolors.ENDC)
                    correct +=1
                wrong_hits = hits - correct

                if wrong_hits in stats["wrong_hit_count"]:
                    stats["wrong_hit_count"][wrong_hits] += 1
                else:
                    stats["wrong_hit_count"][wrong_hits] = 0

                if(correct == 0):
                    stats["unidentified"] += 1

if __name__ == "__main__":
    main()

