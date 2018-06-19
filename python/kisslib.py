"""This is the python interface for the Known Instruction Snippet Scanner(KISS) Library."""
from ctypes import *
from copy import deepcopy
from elftools.elf.elffile import ELFFile
from collections import Counter
import multiprocessing as mp
import binascii
import re
import sys
import os
 
class CSearchResult(Structure):
    _fields_ = [
        ("library_name", c_char_p),
        ("function_name", c_char_p),
        ("in_db_offset", c_size_t),
        ("in_library_offset", c_size_t),
        ("in_function_offset", c_size_t),
        ("function_size", c_size_t)]

kiss = cdll.LoadLibrary('../libkiss.so')
kiss.CreateCDatabase.restype = c_void_p
kiss.CreateCSearchEngine.restype = c_void_p
kiss.CSearchEngineGetResult.restype = POINTER(CSearchResult)
kiss.CSearchEngineExtract.restype = c_void_p

class DatabaseInstance:

    def __init__(self, source_directory, output_file_name):
        """Creates a new C++ Object initialized with source_path and output nomenclatur."""
        src_dir = create_string_buffer(bytes(source_directory, 'utf-8'))
        self.file_name = output_file_name
        output_name = create_string_buffer(bytes(output_file_name, 'utf-8'))
        self.kiss_db = kiss.CreateCDatabase(c_char_p(src_dir.raw), c_uint(sizeof(src_dir) - 1), c_char_p(output_name.raw), c_uint(sizeof(output_name) - 1))
        if(self.kiss_db == 0x0):
            raise RuntimeError("failed to create database instance")


    def __del__(self):
        """Deconstruct the db object and free all of its memory."""
        kiss.DeleteCDatabase(c_void_p(self.kiss_db))

    def construct_from_file(self):
        """Traverses the directory recursively and builds a huge database file out of collected text segments and creates offset table file matching it."""
        if(kiss.CDatabaseConstructFromFile(c_void_p(self.kiss_db)) == -1):
            raise RuntimeError("construct_from_file() failed")

    def generate_database_to_file(self, patch = False):
        """Uses huge db file to generate indexed and compressed search file."""
        if(kiss.CDatabaseGenerateDatabaseToFile(c_void_p(self.kiss_db)) == -1):
            raise RuntimeError("generate_database_to_file() failed")

        if(patch):
            db_debug = open(self.file_name + ".db", 'rb')
            text = db_debug.read()
            db_debug.close()
            os.remove(self.file_name + ".db")
            text = re.sub(b'\xff\x15....', b'\xff\x15\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8b\x05....', b'\x8b\x05\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8d\x3d....', b'\x8d\x3d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8d\x35....', b'\x8d\x35\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8d\x05....', b'\x8d\x05\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8d\x0d....', b'\x8d\x0d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8d\x05....', b'\x8d\x05\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8b\x15....', b'\x8b\x15\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x89\x05....', b'\x89\x05\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8d\x15....', b'\x8d\x15\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8b\x0d....', b'\x8b\x0d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8d\x1d....', b'\x8d\x1d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8b\x3d....', b'\x8b\x3d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8b\x35....', b'\x8b\x35\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8b\x1d....', b'\x8b\x1d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8b\x2d....', b'\x8b\x2d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\xff\x25....', b'\xff\x25\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8d\x2d....', b'\x8d\x2d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x89\x15....', b'\x89\x15\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x89\x1d....', b'\x89\x1d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8b\x25....', b'\x8b\x25\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x8d\x25....', b'\x8d\x25\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\xdb\x2d....', b'\xdb\x2d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x89\x35....', b'\x89\x35\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x89\x0d....', b'\x89\x0d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x89\x3d....', b'\x89\x3d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x89\x2d....', b'\x89\x2d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x3b\x15....', b'\x3b\x15\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x3b\x05....', b'\x3b\x05\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\xf6\x05....', b'\xf6\x05\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\xf6\x05....', b'\xf6\x05\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x89\x25....', b'\x89\x25\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x88\x0d....', b'\x88\x0d\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x39\x05....', b'\x39\x05\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\xd9\x05....', b'\xd9\x05\xa1\xa1\xa1\xa1', text, re.DOTALL)
            text = re.sub(b'\x39\x15....', b'\x39\x15\xa1\xa1\xa1\xa1', text, re.DOTALL)
            db_debug = open(self.file_name + ".db", 'bw+')
            db_debug.write(text)

class SearchEngine:

    class SearchResult:
        def __init__(self, _library_name, _function_name, _in_db_offset, _in_library_offset, _in_function_offset, _function_size):
            self.library_name = _library_name
            self.function_name = _function_name
            self.in_db_offset = _in_db_offset
            self.in_library_offset = _in_library_offset
            self.in_function_offset = _in_function_offset
            self.function_size = _function_size

        def __str__(self):
            return ("{}[{}] -> {}[{} of {}]".format(self.library_name, hex(self.in_library_offset), self.function_name, self.in_function_offset, self.function_size))

    def __init__(self, database_file_path, offset_file_path):
        """Creates a new C++ SearchEngine object initialized with the to be searched db file and its matching offset file."""
        db_path = create_string_buffer(bytes(database_file_path, 'utf-8'))
        ofst_path = create_string_buffer(bytes(offset_file_path, 'utf-8'))
        self.kiss_db = kiss.CreateCSearchEngine(c_char_p(db_path.raw), c_uint(sizeof(db_path) - 1), c_char_p(ofst_path.raw), c_uint(sizeof(ofst_path) - 1))
        if(self.kiss_db == 0x0):
            raise RuntimeError("failed to create database instance")

    def __del__(self):
        """Deconstruct the db object and free all of its memory."""
        kiss.DeleteCSearchEngine(c_void_p(self.kiss_db))

    def search(self, new_search_query):
        """Update engine with new search_query[bytes] (can contain null bytes) of search_query length and returns the amount of matching locations in the database.
        You might want to decide at this point if you either run a library/function lookup or concretise your search
        """ 
        query = create_string_buffer(new_search_query)
        ret = kiss.CSearchEngineSearch(c_void_p(self.kiss_db), c_char_p(query.raw), c_uint(sizeof(query) - 1))
        
        if(ret == -1):
            raise RuntimeError("search engine failed on database given")
        return ret
            
    def get_locations(self, amount):
        """Runs a lookup of up to amount locations found in the db via the previously given .ofst file and returns a tuple list of the results"""
        results = []
        num = kiss.CSearchEngineGetLocations(c_void_p(self.kiss_db), c_uint(amount))
        if(num == -1):
            sys.exit(0)
            raise RuntimeError("lookup failed on database and offsets given")

        for i in range(0, num):
            p = kiss.CSearchEngineGetResult(c_void_p(self.kiss_db), c_uint(i))
            if(p == 0x0):
                raise RuntimeError("lookup faicurrent_sub_entryled when transfering results to python")
            if(p.contents.function_name == None):
                results.append(self.SearchResult(c_char_p(p.contents.library_name).value.decode('utf-8'), None, p.contents.in_db_offset, p.contents.in_library_offset, None, None))
            else:
                results.append(self.SearchResult(c_char_p(p.contents.library_name).value.decode('utf-8'), c_char_p(p.contents.function_name).value.decode('utf-8'), p.contents.in_db_offset, p.contents.in_library_offset, p.contents.in_function_offset, p.contents.function_size))
        return results

    def extract_from_db(self, start, size):
        """Extracts the given section from the underlying database with start and end both inclusive.
            runtime estimation: length(db_file * len(query) + len(SA))
            http://www.cs.cmu.edu/~dga/csa.pdf
        """
        p = kiss.CSearchEngineExtract(c_void_p(self.kiss_db), c_uint(start), c_uint(size))
        if(p == 0x0):
            raise RuntimeError("extraction failed")
        # result = deepcopy(c_char_p(p).value)
        # TODO: deepcopy required ?
        result = deepcopy(c_char_p(p).value)
        # Free the memory of the result in c++
        if(kiss.CSearchEngineFree(c_void_p(p)) == -1):
            raise RuntimeError("freeing memory (produced by extract operation) failed")
        return result;


class StaticAnalizer:
    def __init__(self, target_file, database_file, offset_file):
        """Initializes an analyzer instance on the target static linked file with the .a based db and offset file."""
        self.elf = ELFFile(open(target_file, 'rb'))
        self.search_engine = SearchEngine(database_file, offset_file)

    def crawl_partial(self, search_block_size, search_step, start, end, text, result_set):
        """Helper function for crawl_text_segment to allow parrallel process forking."""
        for i in range(start, end, search_step):
            if(i % 1000 == 0):
                print(i)
            snippet = text[i:i + search_block_size]
            hit_count = self.search_engine.search(snippet)
            if(hit_count == 0):
                continue
            if(hit_count > 100):
                print("hit_count: " + str(hit_count))
            # print(hit_count)
            # print("pos: " + str(hex(i)))
            result = self.search_engine.get_locations(hit_count)
            for r in result:
                # if not recognized as function we will not use it for now
                if(r.function_name == None):
                    continue
                if(i - r.in_function_offset < 0):
                    continue

                key = (r.library_name, r.function_name, i - r.in_function_offset);
                if(key in result_set):
                    result_set[key][0] += 1
                else:
                    result_set[key] = [1, r];

    def lookup_partial(self, weighted_results, text, final_results):
        """Helper function for crawl_text_segment to allow parrallel process forking."""
        last_library = None
        last_in_library = None
        last_function_size = None
        last_extract = None
        last_fun_name = None

        for r in weighted_results:
            suspect = r[1][1]
            at = r[0][2]
            # print("Suspecting {} from {} @ {}\n... checking...".format(suspect.function_name, suspect.library_name, hex(at)))
            # print("located in the db @ " + str(hex(suspect.in_db_offset - suspect.in_function_offset)) + " with size " + str(hex(suspect.function_size)))
            if(last_library != suspect.library_name or last_in_library != suspect.in_library_offset or last_function_size != suspect.function_size):
                original = self.search_engine.extract_from_db(suspect.in_db_offset - suspect.in_function_offset, suspect.function_size)
                last_extract = original
                last_library = suspect.library_name
                last_in_library = suspect.in_library_offset
                last_function_size = suspect.function_size
                last_fun_name = suspect.function_name
            else:
                if(last_fun_name == suspect.function_size):
                    continue
                original = last_extract

            sample = text[at:at + suspect.function_size]

            match = True
            for i in range(0, len(original) - 1):
                if(original[i] == 0xa1):
                    continue
                if(original[i] != sample[i]):
                    match = False
                    # print("Failed at {} of {}".format(i, len(sample)))
                    break
            if(match):
                # print("matched: {} in {} @ {}".format(r[0][1], r[0][0], r[0][2]))
                key = at# + elf_text['sh_offset']
                if( key in final_results):
                    final_results[key].append(suspect)
                else:
                    final_results[key] = [suspect]

    def crawl_text_segment(self, search_block_size, search_step, min_hits = -1, num_threads = 64):
        """Crawl the text segment of the loaded ELF file and try to identify static linked functions using the search step and search_size params Only processing results with at least min_hits (-1 means all results)."""
        result_set = dict()
        elf_text = self.elf.get_section_by_name('.text')
        text = elf_text.data()
        # TODO: progressbar

        text = re.sub(b'\xff\x15....', b'\xff\x15\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8b\x05....', b'\x8b\x05\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8d\x3d....', b'\x8d\x3d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8d\x35....', b'\x8d\x35\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8d\x05....', b'\x8d\x05\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8d\x0d....', b'\x8d\x0d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8d\x05....', b'\x8d\x05\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8b\x15....', b'\x8b\x15\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x89\x05....', b'\x89\x05\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8d\x15....', b'\x8d\x15\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8b\x0d....', b'\x8b\x0d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8d\x1d....', b'\x8d\x1d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8b\x3d....', b'\x8b\x3d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8b\x35....', b'\x8b\x35\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8b\x1d....', b'\x8b\x1d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8b\x2d....', b'\x8b\x2d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\xff\x25....', b'\xff\x25\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8d\x2d....', b'\x8d\x2d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x89\x15....', b'\x89\x15\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x89\x1d....', b'\x89\x1d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8b\x25....', b'\x8b\x25\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x8d\x25....', b'\x8d\x25\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\xdb\x2d....', b'\xdb\x2d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x89\x35....', b'\x89\x35\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x89\x0d....', b'\x89\x0d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x89\x3d....', b'\x89\x3d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x89\x2d....', b'\x89\x2d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x3b\x15....', b'\x3b\x15\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x3b\x05....', b'\x3b\x05\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\xf6\x05....', b'\xf6\x05\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\xf6\x05....', b'\xf6\x05\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x89\x25....', b'\x89\x25\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x88\x0d....', b'\x88\x0d\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x39\x05....', b'\x39\x05\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\xd9\x05....', b'\xd9\x05\x00\x00\x00\x00', text, re.DOTALL)
        text = re.sub(b'\x39\x15....', b'\x39\x15\x00\x00\x00\x00', text, re.DOTALL)

        # print(binascii.hexlify(text[0:20]))
        # return None
        # for i in range(0, len(text) - 6):
        #     if(text[i:i+2] == b'\xff\x15'):
        #         print("patch")
        #         for j in range(0, 4):
        #             text[i + 2 + j] = 0x00

        # for i in range(0, len(text) - 6):
        #     if(text[i:i+2] == b'\xff\x15'):
        #         print("fail")
        #         for j in range(0, 4):
        #             text[i + 2 + j] = 0x00

        mp.set_start_method('fork')
        manager = mp.Manager()
        return_dict = manager.dict()
        jobs = []
        fragment_size = int((len(text) - search_block_size) / num_threads) + search_block_size
        for i in range(0, num_threads):
            p = mp.Process(target = self.crawl_partial, args = (search_block_size, search_step, fragment_size * i, min(fragment_size * (i + 1), (len(text) - search_block_size)), text, return_dict))
            # p = mp.Process(target = self.crawl_partial, args = (search_block_size, search_step, fragment_size * i, min(fragment_size * (i + 1), (50000 - search_block_size)), text, return_dict))
            jobs.append(p)
            p.start()

        for proc in jobs:
            proc.join()

        result_set = return_dict.copy()

        if(min_hits == -1):
            print("found {} suspects and checking all".format(str(len(result_set))))
        else:
            print("found {} suspects and checking hits > {}".format(str(len(result_set)), str(min_hits)))

        grouped_results = sorted(result_set.items(), key=lambda e: e[0][0] + e[0][1], reverse = True) # order by library name, in_library_offset, function_size

        filtered_results = []
        if(min_hits != -1):
            for i in range(0, len(grouped_results)):
                if(grouped_results[i][1][0] < min_hits):
                    print("skipping result (< min_hits)")
                    continue
                filtered_results[i] = grouped_results[i]
        else:
             filtered_results = grouped_results

        # Build chunks of same lib and func to reduce needed extract_from_db() operations 
        fragment_size = int(len(filtered_results) / min(len(filtered_results), num_threads))
        assert fragment_size > 0
        e = 0
        chunks = []
        for i in range(0, num_threads):
            chunks.append([])
            while True:
                if(e >= len(filtered_results)):
                    break
                if(len(chunks[i]) > fragment_size):
                    if(chunks[i][-1][0] != filtered_results[e][0] or chunks[i][-1][1] != filtered_results[e][1]): # If last element was of same type take it also into this chunk
                        break
                chunks[i].append(filtered_results[e])
                e += 1

        # Put the remaining in the last one
        for i in range(fragment_size * num_threads, len(filtered_results)):
            chunks[num_threads - 1].append(filtered_results[i])

        for c in chunks:
            print("#########")
            for e in c:
                print(e)
            print("#########")
        print(len(chunks))

       #  else:
       #      weighted_results = sorted(result_set.items(), key=lambda e: e[1][0], reverse = True)[0:max_lookups]

        print("looking up " + str(len(grouped_results)))

        jobs.clear()
        final_results = manager.dict() 
        for c in chunks:
            # TODO: passing whole text is inefficient in many cases 
            if(len(c) == 0):
                continue
            p = mp.Process(target = self.lookup_partial, args = (c, text, final_results))
            jobs.append(p)
            p.start()

        for proc in jobs:
            proc.join()

        print("found {} function headers".format(str(len(final_results))))

        return final_results.copy()

        # This is static linked binary so we should have all function sizes and offsets of its libary.a
    

# TODO: create PIP package
# Test for compress
# def main():
#     db = DatabaseInstance("/usr/lib64/python2.7", "result")
#     db.generate_database_to_file()
#     db.construct_from_file()
# 

# def main():
#     # db = DatabaseInstance("../static", "result")
#     # db.generate_database_to_file()
#     # db.construct_from_file()
#     # engine = SearchEngine("result.cdb", "result.ofst")
# 
#     # query = b"\x41\x56\x41\x55\x49\x89\xd6\x41\x54\x55\x49\x89\xf4\x53\x48\x89"
#     # print("search resulted in {} matches".format(engine.search(bytes(query))))
#     # result = engine.get_locations(10)
#     # # for r in result:
#     # #     print(r)
# 
#     # print(result[0])
#     # print(engine.extract_from_db(result[0].in_db_offset - result[0].in_function_offset, result[0].function_size))
# 
#     static_analyzer = StaticAnalizer("../hello_static", "result.cdb", "result.ofst")
#     results = static_analyzer.crawl_text_segment(32, 2)
# 
#     count_funs = 0
#     sum_size = 0
#     for key, value in results.items():
#         print("At address " + str(hex(key)))
#         current_largest = 0;
#         for p in value:
#             print("\t" + format(p))
#             count_funs += 1
#             current_largest = max(current_largest, p.function_size)
#         sum_size += current_largest
# 
# 
#     print("Found {} function accounting for a maximum size of {}".format(count_funs, sum_size))
# 
# if __name__ == "__main__":
#     main()

