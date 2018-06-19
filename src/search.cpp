#include "search.h"

using namespace sdsl;
using namespace std;

CSearchEngine::CSearchEngine(char *_database_file_path, size_t length_db_path, char* _offset_file_path, size_t length_offset_path) : CSearchEngine(string(_database_file_path, length_db_path), string(_offset_file_path, length_offset_path)) {};


CSearchEngine::CSearchEngine(string database_file_path, string offset_file_path)
{
	ifstream offset_data;
	string segment;
	size_t temp_lib_offset;
	size_t temp_fun_offset;
	size_t temp_fun_size;
	size_t delimiter_pos;
	size_t second_delimiter_pos;

	/* Init */
	amount_hits = 0;
	for(int i = 0; i < LIB_OFFSET_CACHE_SIZE; i++)
	{
		lib_offset_cache[i].offset = std::numeric_limits<size_t>::max();
		lib_offset_cache[i].entry = 0;
	}

	/* Load the offset file into memory */
	offset_data.open(offset_file_path);

	if(!offset_data)
	{
		dprintf("[ERROR] Could not open offset file\n");
		exit(0);
	}

	for(string line; getline(offset_data, line);)
	{
		delimiter_pos = line.find(' ');
		if(offset_lookup_table.size() != 0 && line[0] == '\t')
		{
			temp_fun_offset = stoi(line.substr(0, delimiter_pos), 0, 16);
			second_delimiter_pos = line.find(' ', delimiter_pos + 1);
			temp_fun_size = stoi(line.substr(delimiter_pos, second_delimiter_pos), 0, 16);
			offset_lookup_table.back().sub_entries.emplace_back(line.substr(second_delimiter_pos + 1), temp_fun_offset, temp_fun_size);
			// printf("\t%s with local_offset 0x%x and size 0x%x\n", line.substr(second_delimiter_pos + 1).c_str(), temp_fun_offset, temp_fun_size);
		}
		else
		{
			temp_lib_offset = stoi(line.substr(0, delimiter_pos), 0, 16);
			if(offset_lookup_table.size() != 0)
				temp_lib_offset += offset_lookup_table.back().offset;
			offset_lookup_table.emplace_back(line.substr(delimiter_pos + 1), temp_lib_offset);
			// printf("%s with offset 0x%x\n", line.substr(delimiter_pos).c_str(), temp_lib_offset);
		}
	}
	printf("Loaded %d libcs\n", offset_lookup_table.size());


// [WARNING] Could not identify function name
// libc_name:  ../static/loadmsgcat.o and offset 0xf17b3 and local_lib_offset: 0xbdc
// offset_table said were in lib offset 0xf21c8

	/* Load actual database into memory */
	if(!load_from_file(database, database_file_path))
	{
		dprintf("[ERROR] Loading the database file failed\n");
		exit(0);
	}

	dprintf("[SUCCESS] KISS initialized succesfully\n");
}


int CSearchEngine::Search(char *new_search_query, size_t length_search_query)
{
	current_search_query.clear();

	// current_search_query = malloc(length_search_query);
	for(int i = 0; i < length_search_query; i++)
	{
		if(new_search_query[i] == 0)
			current_search_query += REPLACED_CHAR;
		else
			current_search_query += new_search_query[i];
	}

	amount_hits = sdsl::count(database, current_search_query.begin(), current_search_query.end());
	return amount_hits;
}


int CSearchEngine::Search(string new_search_query)
{
	current_search_query.clear();

	// current_search_query = malloc(length_search_query);
	for(int i = 0; i < new_search_query.length(); i++)
	{
		if(new_search_query[i] == 0)
			current_search_query += REPLACED_CHAR;
		else
			current_search_query += new_search_query[i];
	}

	amount_hits = sdsl::count(database, current_search_query.begin(), current_search_query.end());
	return amount_hits;
}


int CSearchEngine::GetLocations(size_t amount_requested)
{
	size_t current_entry;
	size_t current_sub_entry;
	ssize_t local_offset;
	ssize_t in_function_offset;
	bool name_not_found;
	clock_t start;
	double duration;

	search_results.clear();

	if(offset_lookup_table.size() == 0)
		return -1;

	// start = clock();
	auto locations = locate(database, current_search_query.begin(), current_search_query.end());
	// duration = (clock() - start) / (double) CLOCKS_PER_SEC;
	// printf("A: %f\n", duration);
	/* TODO only sort requested number ? */

	// start = clock();
	sort(locations.begin(), locations.end());
	// duration = (clock() - start) / (double) CLOCKS_PER_SEC;
	// printf("B: %f\n", duration);


	current_entry = 0;

	// start = clock();

	for(int i = 0; i < min(amount_hits, amount_requested); i++)
	{
		// printf("location: 0x%llx\n", locations[i]);
		while(locations[i] >= offset_lookup_table[current_entry].offset)
		{
			// dprintf("current_entry: %d with offset 0x%x\n", current_entry, offset_lookup_table[current_entry].offset);
			current_entry++;
			if(current_entry >= offset_lookup_table.size() && locations[i] > offset_lookup_table[current_entry].offset)
			{
				dprintf("[ERROR] At least one result is out of index files scope\n");
				return -1;
			}
		}

		/* Try to find the functions name */
		local_offset = locations[i] - (current_entry == 0 ? 0 : offset_lookup_table[current_entry - 1].offset);
		// printf("local_offset: 0x%llx\n", local_offset);
		current_sub_entry = 0;
		// while(local_offset >= offset_lookup_table[current_entry].sub_entries[current_sub_entry].offset)
		// {
		// 	current_sub_entry++;

		// 	if(current_sub_entry >= offset_lookup_table[current_entry].sub_entries.size())
		// 	{
		// 		if(local_offset <= offset_lookup_table[current_entry].sub_entries[current_sub_entry - 1].offset + offset_lookup_table[current_entry].sub_entries[current_sub_entry - 1].size)
		// 		{
		// 			// printf("reached in %s\n", offset_lookup_table[current_entry].name);
		// 			// printf("local_offset: 0x%llx with current_sub_entry %d of %d\n", local_offset, current_sub_entry, offset_lookup_table[current_entry].sub_entries.size());
		// 			// printf("and last function ends at 0x%llx\n", offset_lookup_table[current_entry].sub_entries[current_sub_entry - 1].offset + offset_lookup_table[current_entry].sub_entries[current_sub_entry - 1].size);
		// 			break;
		// 		}
		// 		dprintf("[WARNING] Could not identify function name\n");
		// 		printf("libc_name: %s and offset 0x%x and local_lib_offset: 0x%x\n", offset_lookup_table[current_entry].name, locations[i], local_offset);
		// 		printf("offset_table said were in lib offset 0x%x\n", offset_lookup_table[current_entry].offset);
		// 		printf("current_sub_entry is at %d with offset_value 0x%x\n", current_sub_entry, offset_lookup_table[current_entry].sub_entries[current_sub_entry].offset);
		// 		return -1;
		// 		name_not_found = true;
		// 		break;
		// 	}
		// }
		name_not_found = true;
		for(int j = 0; j < offset_lookup_table[current_entry].sub_entries.size(); j++)
		{
			if(local_offset >= offset_lookup_table[current_entry].sub_entries[j].offset)
			{
				if(local_offset < offset_lookup_table[current_entry].sub_entries[j].offset + offset_lookup_table[current_entry].sub_entries[j].size)
				{
					// printf("0x%x[offset] 0x%x[local]%s @ 0x%x\n", locations[i], local_offset, offset_lookup_table[current_entry].sub_entries[j].name, offset_lookup_table[current_entry].sub_entries[j].offset);
					// printf("search_string: %s\n", current_search_query.c_str());
					current_sub_entry = j;
					name_not_found = false;
					break;

				}
			}
		}
		// if(name_not_found)
		// {
		// 	dprintf("[WARNING] Could not identify function name\n");
		// 	printf("libc_name: %s and offset 0x%x and local_lib_offset: 0x%x\n", offset_lookup_table[current_entry].name, locations[i], local_offset);
		// 	printf("offset_table said were in lib offset 0x%x\n", offset_lookup_table[current_entry].offset);
		// 	printf("current_sub_entry is at %d with offset_value 0x%x\n", current_sub_entry, offset_lookup_table[current_entry].sub_entries[current_sub_entry].offset);
		// }
// [WARNING] Could not identify function name
// libc_name:  ../static/loadmsgcat.o and offset 0xf17b3 and local_lib_offset: 0xbdc
// offset_table said were in lib offset 0xf21c8
// current_sub_entry is at 2 with offset_value 0x21

		// current_sub_entry--;

		in_function_offset = local_offset - (current_sub_entry == 0 ? 0 : offset_lookup_table[current_entry].sub_entries[current_sub_entry].offset);
		if(in_function_offset > offset_lookup_table[current_entry].sub_entries[current_sub_entry].size)
			name_not_found = true;

		if(name_not_found)
			search_results.emplace_back(offset_lookup_table[current_entry].name, locations[i], local_offset);
		else
			search_results.emplace_back(offset_lookup_table[current_entry].name, locations[i], local_offset, offset_lookup_table[current_entry].sub_entries[current_sub_entry].name, in_function_offset, offset_lookup_table[current_entry].sub_entries[current_sub_entry].size);
	}

	// duration = (clock() - start) / (double) CLOCKS_PER_SEC;
	// printf("C: %f\n", duration);

	return search_results.size();
}

SSearchResult *CSearchEngine::GetResult(size_t index)
{
	if(index < 0 || index >= search_results.size())
	{
		dprintf("[WARNING] Invalid result access\n");
		return 0;
	}

	return &(search_results[index]);
}


string CSearchEngine::Extract(size_t start, size_t size)
{
	if(start < 0)// || size + start > size_in_bytes(database))
	{
		dprintf("[ERROR] Extract was not within valid boundaries\n");
		return 0;
	}


	return extract(database, start, start + size);
}


/* C exposure for python interfacing */
extern "C"
{
	void *CreateCSearchEngine(char *database_file_path, size_t length_db_path, char *offset_file_path, size_t length_offset_path)
	{
		/* Note: Inside the function body, I can use C++. */
		return new(std::nothrow) CSearchEngine(database_file_path, length_db_path, offset_file_path, length_offset_path);
	}

	void DeleteCSearchEngine(void *ptr)
	{
		delete (CSearchEngine *)ptr;
	}

	/* Note: A downside here is the lack of type safety. 
		You could always internally(in the C++ library) save a reference to all 
		pointers created of type MyClass and verify it is an element in that
		structure. */

	/* Avoid throwing exceptions */
	int CSearchEngineSearch(void *ptr, char *new_search_query, size_t length_search_query)
	{
		try
		{
			return reinterpret_cast<CSearchEngine *>(ptr)->Search(new_search_query, length_search_query);
		}
		catch(...)
		{
			return -1; /* Error case */
		}
	}

	int CSearchEngineGetLocations(void *ptr, size_t amount)
	{
		try
		{
			return reinterpret_cast<CSearchEngine *>(ptr)->GetLocations(amount);
		}
		catch(...)
		{
			return -1; /* Error case */
		}
	}

	SSearchResult *CSearchEngineGetResult(void *ptr, size_t index)
	{
		try
		{
			return (reinterpret_cast<CSearchEngine *>(ptr)->GetResult(index));
		}
		catch(...)
		{
			return 0; /* Error case */
		}
	}

	/* Allocates memory and fills it with the extracted value from the db ! you are RESPONSIBLE for DEALLOCATIOn ! returns 0 if failed */
	char *CSearchEngineExtract(void *ptr, size_t start, size_t size)
	{
		char * return_value;
		try
		{
			std::string result(reinterpret_cast<CSearchEngine *>(ptr)->Extract(start, size));
			return_value = (char *)malloc(result.size() + 1);
			memcpy(return_value, result.c_str(), result.size() + 1);
			return return_value;
		}
		catch(...)
		{
			return 0; /* Error case */
		}
	}

	int CSearchEngineFree(void *p)
	{
		try
		{
			free(p);
			p = 0;
			return 1;
		}
		catch(...)
		{
			return -1; /* Error case */
		}
	}
}


