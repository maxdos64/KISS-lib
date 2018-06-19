
#include "../include/compress.h"

using namespace sdsl;
using namespace std;
using namespace ELFIO;

CDatabase::CDatabase(char *_source_directory_path, size_t path_length, char *_output_file_name, size_t output_name_length)
{
	source_directory_path = string(_source_directory_path, path_length);
	file_name = string(_output_file_name, output_name_length);
}


CDatabase::CDatabase(string _source_directory_path, string _output_file_name)
{
	source_directory_path = _source_directory_path;
	file_name = _output_file_name;
}


void CDatabase::ConstructFromFile()
{
	dprintf("[INFO] Constructing indexed-compressed file %s\n", (file_name + ".cdb").c_str());

	construct(database, file_name + ".db", 1);   /* generate index */
	store_to_file(database, file_name + ".cdb"); /* save it */
}


void CDatabase::GenerateDatabaseToFile()
{
	db_file.open(file_name + ".db");
	offset_file.open(file_name + ".ofst");

	dprintf("[INFO] Constructing database file %s\n", (file_name + ".db").c_str());
	dprintf("[INFO] Constructing offset file %s\n", (file_name + ".ofst").c_str());

	CrawlDirectories(source_directory_path.c_str());
	dprintf("[SUCCESS] Done constructing database\n");
}


void CDatabase::CrawlDirectories(const char *path_root)
{
	DIR *dir;
	struct dirent *entry;
	char path[1024];
	elfio elf_reader;
	Elf_Half number_sections;
	size_t text_section_offset;
	size_t text_section_size;
	char *extracted_text;
	char offset_number_string[256];
	string offset_entry;
	/* Symbol extraction stuff */
	std::string symbol_name;
	Elf64_Addr symbol_value;
	Elf_Xword symbol_size;
	unsigned char symbol_bind;
	unsigned char symbol_type;
	Elf_Half symbols_section_index;
	unsigned char symbol_other;
	vector<SSymbol> symbols_found;
	size_t symbol_text_offset;

	if (!(dir = opendir(path_root)))
	{
		dprintf("[ERROR] while crawling in directory %s\n", path_root);
		return;
	}

	while ((entry = readdir(dir)))
	{
		snprintf(path, sizeof(path), "%s/%s", path_root, entry->d_name);
		if (entry->d_type == DT_DIR)
		{
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;

			CrawlDirectories(path);
		}
		else if(entry->d_type == DT_REG)
		{
			/* Try to load ELF file header */
			if (!elf_reader.load(path))
			{
				// dprintf("[WARNING] Cannot process %s as ELF\n", entry->d_name);
				continue;
			}

			if(elf_reader.get_class() == ELFCLASS64 && elf_reader.get_machine() == EM_X86_64)
			{
				dprintf("[INFO] Analyzing ELF %s\n", path);

				number_sections = elf_reader.sections.size();
				for (int i = 0; i < number_sections; i++)
				{
					section* psec = elf_reader.sections[i];
					if(psec->get_name() == ".text")
					{
						text_section_offset = psec->get_address();
						text_section_size = psec->get_size();
						// dprintf("\ttext_section starts at 0x%x and has size 0x%x\n", text_section_offset, text_section_size);
						extracted_text = (char *)malloc(text_section_size);
						memcpy(extracted_text, elf_reader.sections[i]->get_data(), text_section_size);

						/* Patch out the zero bytes */
						for(size_t i = 0; i < text_section_size; i++)
							if(extracted_text[i] == 0x00)
								extracted_text[i] = REPLACED_CHAR;

						/* Append to db file */
						db_file.write(extracted_text, text_section_size);
						/* Append to ofst file */
						offset_file << std::hex << text_section_size << " " << path << "\n";
						offset_file.flush();
					}
					else if(psec->get_type() == SHT_SYMTAB || psec->get_type() == SHT_DYNSYM)
					{
						symbols_found.clear();
						const symbol_section_accessor symbols(elf_reader, psec);
						for(ssize_t j = 0; j < symbols.get_symbols_num(); j++)
						{
							symbols.get_symbol(j, symbol_name, symbol_value, symbol_size, symbol_bind, symbol_type, symbols_section_index, symbol_other);
							if(symbol_type == STT_FUNC || symbol_type == 10) // TODO GNU_IFUNC ?
							{
								// dprintf("function %s @ 0x%llx\n", symbol_name.c_str(), symbol_value);
								symbols_found.emplace_back(symbol_name, symbol_value, symbol_size);

// 0022 maxdos@ryan[pts/2]:~/projekte/TUM/Semester6/Reverse/re18s-team-demystified-blob/kiss-lib/python-> readelf -s --wide ../libc/libboost_program_options.so.1.66.0 | grep _ZN5boost15program_options6detail7cmdline3runEv
//    794: 000000000002eb80  4759 FUNC    GLOBAL DEFAULT    9 _ZN5boost15program_options6detail7cmdline3runEv
							}
						}
					}
				}

				sort(symbols_found.begin(), symbols_found.end());
				for(int i = 0; i < symbols_found.size(); i++)
				{
					if(symbols_found[i].offset >= text_section_offset)
					{
						symbol_text_offset = symbols_found[i].offset - text_section_offset;
						offset_file << "\t" << std::hex << symbol_text_offset << " " << std::hex << symbols_found[i].size << " " << symbols_found[i].name << "\n";
					}
				}

				/* Get known function offset */
			}
			else
			{
				// dprintf("[INFO] Filtering out %s\n", entry->d_name);
			}
		}
	}
	offset_file.flush();
	closedir(dir);
}

/* C exposure for python interfacing */
extern "C"
{
	void *CreateCDatabase(char *source_directory_path, size_t path_length, char *output_file_name, size_t output_name_length)
	{
		/* Note: Inside the function body, I can use C++. */
		return new(std::nothrow) CDatabase(source_directory_path, path_length, output_file_name, output_name_length);
	}

	void DeleteCDatabase(void *ptr)
	{
		delete (CDatabase *)ptr;
	}

	/* Note: A downside here is the lack of type safety. 
		You could always internally(in the C++ library) save a reference to all 
		pointers created of type MyClass and verify it is an element in that
		structure. */

	/* Avoid throwing exceptions */
	int CDatabaseConstructFromFile(void *ptr)
	{
		try
		{
			reinterpret_cast<CDatabase *>(ptr)->ConstructFromFile();
		}
		catch(...)
		{
			return -1; /* Error case */
		}
		return 1;
	}

	int CDatabaseGenerateDatabaseToFile(void *ptr)
	{
		try
		{
			reinterpret_cast<CDatabase *>(ptr)->GenerateDatabaseToFile();
		}
		catch(...)
		{
			return -1; /* Error case */
		}
		return 1;
	}
}
