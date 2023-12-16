#include <windows.h>
#include <string>
#include <iostream>
#include <locale>
#include <filesystem>
#include <memory>
#include <fstream>
#include <vector>
#include <algorithm>
#include <system_error>

// https://programmerall.com/article/19922097655/

enum Error {
	OK = 0,
	FAIL = 1,
	NO_PDB_DATA = 2,
	DLL_LOCKED = 3,
	DLL_WRITE_FAIL = 4,
	DLL_TOO_BIG_ADDRESS = 5,
};

struct PdbName {
	size_t address;
	std::string original_path;
	std::wstring utf_name;
};

char* wc_to_utf8(const wchar_t* wc) {
	int ulen = WideCharToMultiByte(CP_UTF8, 0, wc, -1, nullptr, 0, nullptr, nullptr);
	char* ubuf = new char[ulen + 1];
	WideCharToMultiByte(CP_UTF8, 0, wc, -1, ubuf, ulen, nullptr, nullptr);
	ubuf[ulen] = 0;
	return ubuf;
}

wchar_t* utf8_to_wc(const char* utf8) {
	int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
	wchar_t* wbuf = new wchar_t[wlen + 1];
	MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wbuf, wlen);
	wbuf[wlen] = 0;
	return wbuf;
}

Error get_pdb_info(std::wstring dll_name, PdbName& pdb_info) {
	HMODULE module = LoadLibraryW(dll_name.c_str());

	if (module == 0)
	{
		std::wcout << "Failed loading PE: " << dll_name << std::endl;
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
			pdb_info.original_path = pdb_rsds->PdbFileName;
			pdb_info.utf_name = utf8_to_wc(pdb_rsds->PdbFileName);

			int name_offset = (int)(reinterpret_cast<char*>(pdb_rsds->PdbFileName) - reinterpret_cast<char*>(pdb_rsds));
			pdb_info.address = dbg_dir->PointerToRawData + name_offset;

			FreeLibrary(module);
			return OK;
		}
	}

	FreeLibrary(module);
	return NO_PDB_DATA;
}

Error patch_pdb_name(std::wstring dll, std::wstring pdb, size_t address, size_t original_size) {
	std::fstream file(dll, std::ios::in | std::ios::out | std::ios::binary);

	if (!file.is_open()) {
		return DLL_LOCKED;
	}

	file.seekp(address, std::ios::beg);
	if (file.fail()) {
		return DLL_TOO_BIG_ADDRESS;
	}

	std::string updb = wc_to_utf8(pdb.c_str());
	file.write(updb.c_str(), updb.size());
	if (file.fail()) {
		return DLL_WRITE_FAIL;
	}

	// Terminate string and fill original string with '\0'
	// can be replaced by file.write("\0", 1);
	int pad_size = (int)(original_size - updb.length());
	auto padding = std::unique_ptr<char>(new char[pad_size]);
	memset(padding.get(), 0, pad_size);
	file.write(padding.get(), pad_size);

	file.close();
	return OK;
}

int wmain(int argc, wchar_t** argv) {
	std::setlocale(LC_ALL, "");

	if (argc < 2) {
		std::wcout << "Please specify PE file!" << std::endl;
		return -1;
	}

	std::wstring dll_name = argv[1];
	if (!std::filesystem::exists(dll_name)) {
		std::wcout << "File does not exists! " << dll_name << std::endl;
		return -1;
	}

	// Rename to "[full/path/]~[dll_name]"
	std::wstring new_dll_name = std::filesystem::path(dll_name).parent_path().append(L"~" + std::filesystem::path(dll_name).filename().wstring()).wstring();

	std::error_code err;
	// Copy DLL like in Godot
	std::filesystem::copy_file(dll_name, new_dll_name, std::filesystem::copy_options::overwrite_existing, err);

	if (err) {
		std::cout << err.message() << std::endl;
		return -1;
	}

	// Get PDB name and address inside DLL file
	PdbName pdb_name;
	Error err_code = get_pdb_info(new_dll_name, pdb_name);

	if (err_code == OK) {
		std::wcout << "Original PDB name: " << pdb_name.utf_name << std::endl;
	}
	else if (err_code == NO_PDB_DATA) {
		std::wcout << "No PDB info found inside: " << new_dll_name << std::endl;
		std::filesystem::remove(new_dll_name, err);
		return -1;
	}
	else {
		std::wcout << "Failed to rename PDB inside: " << dll_name << std::endl;
		std::filesystem::remove(new_dll_name, err);
		return -1;
	}

	// Save the new base name for the PDB. It will be relative, not absolute, as in Visual Studio by default.
	// This is necessary so as not to change the size of the field with the PDB name, but simply replace it with a new name.
	// TODO add logic to support short relative names
	std::wstring new_pdb_base_name = L"~" + std::filesystem::path(pdb_name.utf_name).filename().replace_extension("").wstring() + L"_";

	const size_t suffix_size = 3 /* 999 */ + 4 /* .pdb */;
	size_t numbered_pdb_size = std::string(wc_to_utf8(new_pdb_base_name.c_str())).length() + suffix_size;
	if (numbered_pdb_size > pdb_name.original_path.length()) {
		if (pdb_name.original_path.length() < suffix_size + 1) {
			std::cout << "The original PDB path length is too small: " << pdb_name.original_path << std::endl;
			std::filesystem::remove(new_dll_name, err);
			return -1;
		}

		new_pdb_base_name = std::wstring(utf8_to_wc(std::string(wc_to_utf8(new_pdb_base_name.c_str())).substr(0, pdb_name.original_path.length() - suffix_size).c_str()));
	}

	{
		struct FilesDataWithTime {
			std::filesystem::path path;
			std::filesystem::file_time_type time;
		};

		// Clear old PDB files
		std::vector<FilesDataWithTime> old_pdb_files;
		for (int i = 0; i < 1000; i++) {
			std::filesystem::path new_pdb_name = std::filesystem::path(dll_name).parent_path().append(new_pdb_base_name + std::to_wstring(i) + L".pdb");
			if (std::filesystem::exists(new_pdb_name)) {
				old_pdb_files.push_back({
						new_pdb_name,
						std::filesystem::last_write_time(new_pdb_name)
					});
			}
		}

		std::sort(old_pdb_files.begin(), old_pdb_files.end(), [](FilesDataWithTime first, FilesDataWithTime second) { return first.time < second.time; });
		// Don't touch the newest one
		if (old_pdb_files.size()) {
			old_pdb_files.pop_back();
		}

		for (const auto& file : old_pdb_files) {
			std::filesystem::remove(file.path, err);
		}
	}

	for (int i = 0; i < 1000; i++) {
		// Generate new name for PDB
		std::wstring new_pdb_name = new_pdb_base_name + std::to_wstring(i) + L".pdb";

		std::wstring copy_path = pdb_name.utf_name;
		if (std::filesystem::path(pdb_name.utf_name).is_relative()) {
			copy_path = std::filesystem::path(dll_name).parent_path().append(pdb_name.utf_name).wstring();
		}
		else {
			if (!std::filesystem::exists(pdb_name.utf_name)) {
				copy_path = std::filesystem::path(dll_name).parent_path().append(std::filesystem::path(pdb_name.utf_name).filename().wstring()).wstring();
			}
		}

		// Try to copy PDB
		std::filesystem::copy_file(
			copy_path,
			std::filesystem::path(dll_name).parent_path().append(new_pdb_name).wstring(),
			std::filesystem::copy_options::overwrite_existing, err);

		if (err == std::errc::no_such_file_or_directory) {
			std::cout << err.message() << std::endl;
			std::wcout << "PDB file not found: " << pdb_name.utf_name << std::endl;
			std::filesystem::remove(new_dll_name, err);
			return -1;
		}
		else if (err) {
			std::cout << err.message() << std::endl;
			continue;
		}

		err_code = patch_pdb_name(new_dll_name, new_pdb_name, pdb_name.address, pdb_name.original_path.length());
		if (err_code == OK) {
			std::wcout << "File patched. New PDB name: " << new_pdb_name << std::endl;
			break;
		}
		else if (err_code == DLL_LOCKED) {
			std::wcout << "File locked. Failed to patch DLL: " << new_dll_name << std::endl;
			break;
		}
		else if (err_code == DLL_TOO_BIG_ADDRESS) {
			std::wcout << "PDB address was too big. Failed to patch DLL: " << new_dll_name << std::endl;
			break;
		}
	}

	return 0;
}