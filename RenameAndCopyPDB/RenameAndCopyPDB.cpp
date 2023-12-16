#include <windows.h>
#include <string>
#include <iostream>
#include <locale>
#include <filesystem>
#include <memory>
#include <fstream>

// https://programmerall.com/article/19922097655/

enum Error {
	OK = 0,
	FAIL = 1,
	NO_PDB_DATA = 2,
	DLL_LOCKED = 3,
	DLL_TOO_BIG_ADDRESS = 4,
};

struct PdbName {
	size_t address;
	std::string name;
};

Error get_pdb_info(std::string dll_name, PdbName& pdb_info) {
	HMODULE module = LoadLibraryA(dll_name.c_str());

	if (module == 0)
	{
		std::cout << "Failed load:" << dll_name << std::endl;
		return FAIL;
	}

	// Figure out where the executable is mapped in memory.
	uintptr_t base_pointer = (uintptr_t)module;

	// This is where the MZ...blah header lives (the DOS header)
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)base_pointer;

	// We want the PE header.
	IMAGE_FILE_HEADER* file_header = (IMAGE_FILE_HEADER*)(base_pointer + dos_header->e_lfanew + 4);

	// Straight after that is the optional header (which technically is optional, but in practice always there.)
	IMAGE_OPTIONAL_HEADER* opt_header = (IMAGE_OPTIONAL_HEADER*)(((char*)file_header) + sizeof(IMAGE_FILE_HEADER));

	// Grab the debug data directory which has an indirection to its data
	IMAGE_DATA_DIRECTORY* dir = &opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

	// Convert that data to the right type.
	IMAGE_DEBUG_DIRECTORY* dbg_dir = (IMAGE_DEBUG_DIRECTORY*)(base_pointer + dir->VirtualAddress);

	// Check to see that the data has the right type
	if (IMAGE_DEBUG_TYPE_CODEVIEW == dbg_dir->Type)
	{
		struct PdbRSDS
		{
			DWORD     Signature;
			BYTE      Guid[16];
			DWORD     Age;
			char      PdbFileName[1];
		};

		PdbRSDS* pdb_rsds = (PdbRSDS*)(base_pointer + dbg_dir->AddressOfRawData);
		if (0 == memcmp(&pdb_rsds->Signature, "RSDS", 4))
		{
			// WiNdOwS widechar to char...
			int bufferSize = MultiByteToWideChar(CP_UTF8, 0, pdb_rsds->PdbFileName, -1, nullptr, 0);
			std::wstring wideFilePath(bufferSize, 0);
			MultiByteToWideChar(CP_UTF8, 0, pdb_rsds->PdbFileName, -1, &wideFilePath[0], bufferSize);

			bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideFilePath.c_str(), -1, nullptr, 0, nullptr, nullptr);
			std::string utf8String(bufferSize, 0);
			WideCharToMultiByte(CP_ACP, 0, wideFilePath.c_str(), -1, &utf8String[0], bufferSize, nullptr, nullptr);

			pdb_info.name = utf8String;

			int name_offset = (int)(reinterpret_cast<char*>(pdb_rsds->PdbFileName) - reinterpret_cast<char*>(pdb_rsds));
			pdb_info.address = dbg_dir->PointerToRawData + name_offset;
		}
	}

	FreeLibrary(module);
	return OK;
}

Error patch_pdb_name(std::string dll, std::string pdb, size_t address, size_t original_size) {
	std::fstream file(dll, std::ios::in | std::ios::out | std::ios::binary);

	if (!file.is_open()) {
		return DLL_LOCKED;
	}

	file.seekp(address, std::ios::beg);
	if (file.fail()) {
		return DLL_TOO_BIG_ADDRESS;
	}

	file.write(pdb.c_str(), pdb.size());
	if (file.fail()) {
		return DLL_LOCKED;
	}

	// Terminate string and fill original string with '\0'
	// can be replaced by file.write("\0", 1);
	int pad_size = (int)(original_size - pdb.length());
	auto padding = std::unique_ptr<char>(new char[pad_size]);
	memset(padding.get(), 0, pad_size);
	file.write(padding.get(), pad_size);

	file.close();
	return OK;
}

int main(int argc, char** argv) {
	std::setlocale(LC_ALL, "");

	if (argc < 2) {
		std::cout << "Please specify DLL file!" << std::endl;
		return -1;
	}

	if (!std::filesystem::exists(argv[1])) {
		std::cout << "DLL file does not exists!" << std::endl;
		return -1;
	}

	std::string dll_name = argv[1];
	// Rename to "[full/path/]~[dll_name]"
	std::string new_dll_name = std::filesystem::path(dll_name).parent_path().append("~" + std::filesystem::path(dll_name).filename().string()).string();

	std::error_code err;
	// Copy DLL like in Godot
	std::filesystem::copy_file(argv[1], new_dll_name, std::filesystem::copy_options::overwrite_existing, err);

	if (err) {
		std::cout << err.message() << std::endl;
		return -1;
	}

	// Get PDB name and address inside DLL file
	PdbName pdb_name;
	Error err_code = get_pdb_info(new_dll_name, pdb_name);

	if (err_code == OK) {
		std::cout << "Original PDB name: " << pdb_name.name << std::endl;
	}
	else if (err_code == NO_PDB_DATA) {
		std::cout << "No PDB info found inside: " << new_dll_name << std::endl;
		return -1;
	}
	else {
		std::cout << "Failed to rename PDB inside: " << dll_name << std::endl;
		std::filesystem::remove(new_dll_name, err);
		return -1;
	}

	// Save the new base name for the PDB. It will be relative, not absolute, as in Visual Studio by default.
	// This is necessary so as not to change the size of the field with the PDB name, but simply replace it with a new name.
	// TODO add logic to support short relative names
	std::string new_pdb_base_name = std::filesystem::path(new_dll_name).filename().replace_extension("").string() + "_";

	for (int i = 0; i < 1000; i++) {
		// Generate new name for PDB
		std::string new_pdb_name = new_pdb_base_name + std::to_string(i) + ".pdb";
		// Try to copy PDB
		std::filesystem::copy_file(
			pdb_name.name,
			std::filesystem::path(dll_name).parent_path().append(new_pdb_name).string(),
			std::filesystem::copy_options::overwrite_existing, err);

		if (err) {
			std::cout << err.message() << std::endl;
			continue;
		}

		err_code = patch_pdb_name(new_dll_name, new_pdb_name, pdb_name.address, pdb_name.name.length());
		if (err_code == OK) {
			std::cout << "DLL patched. New PDB name: " << new_pdb_name << std::endl;
			break;
		}
		else if (err_code == DLL_LOCKED) {
			std::cout << "DLL locked. Failed to patch DLL: " << new_dll_name << std::endl;
			break;
		}
		else if (err_code == DLL_TOO_BIG_ADDRESS) {
			std::cout << "PDB address was too big. Failed to patch DLL: " << new_dll_name << std::endl;
			break;
		}
	}

	return 0;
}
