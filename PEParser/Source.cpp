#include "PEParser.hpp"

#include <Windows.h>
#include <iostream>

int main()
{
	auto parsed_dll = pe_parser("win32u.dll");
	// iterate through every exported function from kernel32.dll
	for (auto& func : parsed_dll.get_func_list())
	{
		printf("Name: %s - Address: %d - External Address: %p\n", func.name.c_str(), func.address, func.external_address);
	}
}