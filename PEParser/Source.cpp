#include <Windows.h>
#include <iostream>
int main()
{
	//Import and export addresses(Starting address)
	//IMAGE_OPTIONAL_HEADER
	// Dos Header(Starting address for anything)
	//IMAGE_DOS_HEADER
	//Export Address
	//_IMAGE_EXPORT_DIRECTORY
	//IMPORT ADDRESS
	//IMAGE_IMPORT_DESCRIPTOR
	//auto current_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	auto current_proc = GetModuleHandleA("kernel32.dll");
	//auto res = DuplicateHandle(GetCurrentProcess(), &current_proc, GetCurrentProcess(), &current_proc, PROCESS_DUP_HANDLE, false, PROCESS_ALL_ACCESS | DUPLICATE_SAME_ACCESS);

	// base address for all PE data
	auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(current_proc);
	// base address for import and export addresses
	auto optional_header = reinterpret_cast<IMAGE_OPTIONAL_HEADER*>(reinterpret_cast<BYTE*>(current_proc) + dos_header->e_lfanew + 24);

	auto import_table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<BYTE*>(current_proc) + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	auto export_table = reinterpret_cast<_IMAGE_EXPORT_DIRECTORY*>(reinterpret_cast<BYTE*>(current_proc) + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	auto test = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(current_proc) + export_table->AddressOfNames + 4);
	auto test2 = export_table->AddressOfNames;
	for (auto i = 0; i < 10; i++)
	{
		std::cout << "Name: " << std::hex << reinterpret_cast<const char*>(&export_table->AddressOfNames + (i * 4)) << std::endl;
	}

}