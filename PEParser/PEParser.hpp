#pragma once
#include <string>
#include <Windows.h>
#include <vector>
#include <type_traits>
#include <memory>

struct export_obj
{
	unsigned int ordinal;
	std::string name;
	std::uintptr_t address;
	std::uintptr_t external_address;
	byte architecture;
	//TODO: IMPLEMENT BASE
	//std::uintptr_t internal_address;
	export_obj(const std::string& name, std::uintptr_t address, std::uintptr_t external_address, byte architecture, unsigned int ordinal /*std::uintptr_t internal_address*/) :
		name(name),
		address(address),
		external_address(external_address),
		architecture(architecture),
		ordinal(ordinal) {};
	/*internal_address(internal_address)*/
};


class pe_parser
{
	// other vars
	BYTE* base = nullptr;
	// headers
	IMAGE_DOS_HEADER* dos_header = nullptr;
	IMAGE_OPTIONAL_HEADER64* optional_header64 = nullptr;
	_IMAGE_OPTIONAL_HEADER* optional_header32 = nullptr;
	IMAGE_IMPORT_DESCRIPTOR* import_table = nullptr;
	_IMAGE_EXPORT_DIRECTORY* export_table = nullptr;
	// List of exported functions
	std::vector<export_obj> exported_funcs;

public:
	HMODULE module_of_proc;
	pe_parser(const char* dll_name)
	{
		// Check if the module is loaded, if not try to load it...
		if (GetModuleHandleA(dll_name) == NULL)
			if (LoadLibraryA(dll_name) == NULL)
				throw std::exception("Module not found");

		module_of_proc = GetModuleHandleA(dll_name);

		if (reinterpret_cast<IMAGE_DOS_HEADER*>(module_of_proc) == 0)
			throw std::exception("Could not get dos header");

		// base address of the module
		base = reinterpret_cast<BYTE*>(module_of_proc);
		// PE Headers
		dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_of_proc);

		// If the image is 64 bit
		if (dos_header->e_magic == 0x20)
		{
			optional_header64 = reinterpret_cast<_IMAGE_OPTIONAL_HEADER64*>(base + dos_header->e_lfanew + 24);
			import_table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + optional_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

			// PE Tables
			export_table = reinterpret_cast<_IMAGE_EXPORT_DIRECTORY*>(base + optional_header64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			// address of exported data
			auto exported_names_address = reinterpret_cast<DWORD*>(base + export_table->AddressOfNames);
			auto exported_func_address = reinterpret_cast<DWORD*>(base + export_table->AddressOfFunctions);
			// add the exported functions and names to the list
			for (auto i = 0; i < export_table->NumberOfFunctions; i++)
			{
				// name of function
				auto func_name = reinterpret_cast<char*>(base + exported_names_address[i]);
				// relative address of function from base
				auto func_addy = static_cast<std::uintptr_t>(exported_func_address[i]);
				//external address of the function ex: 0x0007FFE5D953943
				auto func_ex_addy = reinterpret_cast<std::uintptr_t>(base + func_addy);
				exported_funcs.emplace_back(export_obj(std::string(func_name), func_addy, func_ex_addy, 64, i + 1));
			}
		}
		else
		{
			optional_header32 = reinterpret_cast<_IMAGE_OPTIONAL_HEADER*>(base + dos_header->e_lfanew + 24);
			import_table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + optional_header32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

			// PE Tables
			export_table = reinterpret_cast<_IMAGE_EXPORT_DIRECTORY*>(base + optional_header32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			// address of exported data
			auto exported_names_address = reinterpret_cast<DWORD*>(base + export_table->AddressOfNames);
			auto exported_func_address = reinterpret_cast<DWORD*>(base + export_table->AddressOfFunctions);
			// add the exported functions and names to the list
			for (auto i = 0; i < export_table->NumberOfFunctions; i++)
			{
				// name of function
				auto func_name = reinterpret_cast<char*>(base + exported_names_address[i]);
				// relative address of function from base
				auto func_addy = static_cast<std::uintptr_t>(exported_func_address[i]);
				//external address of the function ex: 0x0007FFE5D953943
				auto func_ex_addy = reinterpret_cast<std::uintptr_t>(base + func_addy);

				exported_funcs.emplace_back(export_obj(std::string(func_name), func_addy, func_ex_addy, 32, i + 1));
			}
		}
	};

	std::vector<export_obj> get_func_list()
	{
		return exported_funcs;
	}

	export_obj find_by_name(const std::string& func_name)
	{
		for (auto i = 0; i < exported_funcs.size(); i++)
		{
			if (exported_funcs.at(i).name.find(func_name) != std::string::npos)
				return exported_funcs.at(i);
		}
	}
	export_obj get_by_index(unsigned int idx)
	{
		return get_func_list().at(idx);
	}
};