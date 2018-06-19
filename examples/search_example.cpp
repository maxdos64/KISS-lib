#include "search.h"
#include <iostream>
#include <string>
#include <algorithm>

int main()
{
	int number_results;
	SSearchResult *result;
	CSearchEngine search_instance(std::string("python/result.cdb"), std::string("python/result.ofst"));

	// uint8_t query[] = {0x41, 0x5F, 0xC3, 0x48, 0x29, 0xD0, 0x48, 0x83, 0xF8, 0xFF, 0x48, 0x8D, 0x70, 0x03, 0x48, 0x0F};
	// uint8_t query[] = {0x00, 0x49, 0x39, 0xC5, 0x0F, 0x87, 0x11, 0x01, 0x00, 0x00, 0x4D, 0x85, 0xED, 0x0F};
	/* getline */
	// uint8_t query[] = {0x48, 0x89, 0xd1, 0xba, 0x0a, 0x00, 0x00, 0x00, 0xe9, 0x73, 0x39, 0x00, 0x00, 0x90, 0x66, 0x90};
	/*  boost::c_regex_traits<char>::transform_primary @ libboost_regex.so*/
	uint8_t query[] = {0x41, 0x56, 0x41, 0x55, 0x49, 0x89, 0xd6, 0x41, 0x54, 0x55, 0x49, 0x89, 0xf4, 0x53, 0x48, 0x89};
	// uint8_t query[] = {0x55, 0x53, 0x48, 0x8D, 0x3D, 0x6D, 0x9E, 0x15, 0x00, 0xBE, 0x01, 0x00};
	// number_results = search_instance.Search((char *)query, 14);
	/* _ZTVN5boost6system12system_errorE @ libboost_type_erasure.so */
	// char s[] = "APATAVAUAQAQAQAQ";
	number_results = search_instance.Search((char *)query, 16);
	dprintf("Number of results %u\n", number_results);
	number_results = search_instance.GetLocations(100);

	if(number_results == -1)
	{
		dprintf("ERROR");
		exit(0);
	}


	for(int i = 0; i < number_results; i++)
	{
		result = search_instance.GetResult(i);
		if(result->function_name)
		{
			dprintf("%s with local offset 0x%x [[%s]](pos: 0x%x size: 0x%x)\n", result->library_name, result->in_library_offset, result->function_name, result->in_function_offset, result->function_size);
		}
		else
		{
			dprintf("%s with local offset 0x%x [[UNKNOWN]]\n", result->library_name, result->in_library_offset);
		}

		if(i == 0)
		{
			printf("FUNCTION: %s\n", search_instance.Extract(result->in_db_offset - result->in_function_offset, result->function_size).c_str());
			exit(0);
		}
	}

}
