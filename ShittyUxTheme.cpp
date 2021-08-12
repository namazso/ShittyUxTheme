#define _NO_CVCONST_H
#include <Windows.h>
#include <DbgHelp.h>

#include <cstdio>
#include <unordered_set>
#include <xutility>
#include <vector>
#include <string>
#include <fstream>
#include <cstdint>

BOOL TakeOwnership(LPTSTR lpszOwnFile);

std::vector<uint8_t> read_all(const wchar_t* path)
{
  std::ifstream is(path, std::ios::binary);
  if (!is.good() || !is.is_open())
    return {};
  is.seekg(0, std::ifstream::end);
  std::vector<uint8_t> data;
  data.resize((size_t)is.tellg());
  is.seekg(0, std::ifstream::beg);
  is.read(reinterpret_cast<char*>(data.data()), (std::streamsize)data.size());
  return data;
}

bool write_all(const wchar_t* path, const void* data, size_t size)
{
  std::ofstream os(path, std::ios::binary);
  if (!os.is_open() || !os.good())
    return false;
  os.write((const char*)data, size);
  return os.good();
}

uint32_t rva2fo(const uint8_t* image, uint32_t rva)
{
  const auto idh = (PIMAGE_DOS_HEADER)image;
  if (idh->e_magic != IMAGE_DOS_SIGNATURE)
    return 0;
  const auto inh = (PIMAGE_NT_HEADERS)(image + idh->e_lfanew);
  if (inh->Signature != IMAGE_NT_SIGNATURE)
    return 0;
  const auto sections = IMAGE_FIRST_SECTION(inh);
  const auto sections_count = inh->FileHeader.NumberOfSections;
  for (size_t i = 0; i < sections_count; ++i)
  {
    const auto& sec = sections[i];
    if (sec.PointerToRawData && sec.VirtualAddress <= rva && sec.VirtualAddress + sec.SizeOfRawData > rva)
      return rva - sec.VirtualAddress + sec.PointerToRawData;
  }
  return 0;
}

static int do_the_patch(const wchar_t* image)
{
  wprintf(L"Trying image %s\n", image);

  const auto lib = LoadLibraryExW(image, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);

  if (!lib)
  {
    wprintf(L"LoadLibraryExW failed: %lu\n", GetLastError());
    return 0; // whatever
  }

  wchar_t path[MAX_PATH + 1];
  if (!GetModuleFileNameW(lib, path, (DWORD)std::size(path)))
  {
    wprintf(L"GetModuleFileNameW failed: %lu\n", GetLastError());
    return 0;
  }

  const auto load_base = SymLoadModuleExW(
    GetCurrentProcess(),
    nullptr,
    path,
    nullptr,
    (DWORD64)lib,
    0,
    nullptr,
    0
  );
  
  if (load_base == 0)
  {
    wprintf(L"SymLoadModuleExW failed: %lu\n", GetLastError());
    return 0;
  }

  std::unordered_set<uint32_t> patch_rvas;
  auto success = SymEnumSymbolsExW(
    GetCurrentProcess(),
    (DWORD64)lib,
    nullptr,
    [](
      _In_ PSYMBOL_INFOW sym_info,
      _In_ ULONG /*SymbolSize*/,
      _In_opt_ PVOID ctx
      )->BOOL
    {
      if (0 == wcscmp(sym_info->Name, L"CThemeSignature::Verify"))
      {
        const auto rva = (uint32_t)(sym_info->Address - sym_info->ModBase);
        ((std::unordered_set<uint32_t>*)ctx)->insert(rva);
      }
      return TRUE;
    },
    &patch_rvas,
    SYMENUM_OPTIONS_DEFAULT
  );

  if (patch_rvas.empty())
    return 0;

  auto file = read_all(path);

  if(file.empty())
  {
    wprintf(L"can't read file\n");
    return 0;
  }

  constexpr static uint8_t patch[] =
#if defined(_M_IX86)
  {
    0x31, 0xC0,             // xor eax, eax
    0xC2, 0x08, 0x00        // ret 8
  }
#elif defined(_M_AMD64)
  {
    0x31, 0xC0,             // xor eax, eax
    0xC3                    // ret
  }
#elif defined(_M_ARM64)
  {
    0x00, 0x00, 0x80, 0x52, // mov w0, #0
    0xC0, 0x03, 0x5F, 0xD6, // ret
  }
#endif
    ;

  for (auto rva : patch_rvas)
  {
    const auto fo = rva2fo(file.data(), rva);
    wprintf(L"found at rva %08X file offset %08X\n", rva, fo);
    if (fo == 0)
      continue;
    memcpy(file.data() + fo, patch, sizeof patch);
  }

  const auto patched_path = std::wstring(path) + L".patched";
  const auto backup_path = std::wstring(path) + L".bak";

  if(!write_all(patched_path.c_str(), file.data(), file.size()))
  {
    fwprintf(stderr, L"write_all failed\n");
    return 0;
  }

  if(!TakeOwnership(path))
  {
    fwprintf(stderr, L"TakeOwnership failed: %lu\n", GetLastError());
    return 0;
  }

  if(!MoveFileW(path, backup_path.c_str()))
  {
    fwprintf(stderr, L"MoveFileW %s -> %s failed: %lu\n", path, backup_path.c_str(), GetLastError());
    return 0;
  }

  if (!MoveFileW(patched_path.c_str(), path))
  {
    fwprintf(stderr, L"MoveFileW %s -> %s failed: %lu\n", patched_path.c_str(), path, GetLastError());
    if (!MoveFileW(backup_path.c_str(), path))
      fwprintf(stderr, L"MoveFileW %s -> %s failed: %lu. This is pretty bad!\n", backup_path.c_str(), path, GetLastError());
    return 0;
  }

  return (int)patch_rvas.size();
}

constexpr static const wchar_t* s_images[] = {
  L"themeui",
  L"themeservice",
  L"uxinit",
  L"uxtheme",
};

enum return_code
{
  error_success,
  error_no_symsrv,
  error_sym_set_options,
  error_get_temp_path,
  error_sym_initialize,
  error_none_patched
};

int main()
{
  if(nullptr == LoadLibraryW(L"symsrv.dll"))
  {
    fwprintf(stderr, L"Can't load symsrv: %lu\n", GetLastError());
    return error_no_symsrv;
  }

  if (!SymSetOptions(SYMOPT_UNDNAME | SYMOPT_EXACT_SYMBOLS | SYMOPT_FAIL_CRITICAL_ERRORS))
  {
    fwprintf(stderr, L"SymSetOptions failed: %lu\n", GetLastError());
    return error_sym_set_options;
  }

  wchar_t temp_path[MAX_PATH + 1];
  if(0 == GetTempPathW((DWORD)std::size(temp_path), temp_path))
  {
    fwprintf(stderr, L"GetTempPathW failed: %lu\n", GetLastError());
    return error_get_temp_path;
  }

  wchar_t search_path[MAX_PATH + 100];
  swprintf_s(search_path, L"srv*%sSymbols*https://msdl.microsoft.com/download/symbols", temp_path);

  if (!SymInitializeW(GetCurrentProcess(), search_path, false))
  {
    fwprintf(stderr, L"SymInitializeW failed: %lu\n", GetLastError());
    return error_sym_initialize;
  }
  
  auto patched = 0;

  for (auto image : s_images)
  {
    const auto result = do_the_patch(image);

    patched += result;
  }

  if (patched == 0)
  {
    fwprintf(stderr, L"patching failed: none patched\n");
    return error_none_patched;
  }

  wprintf(L"patched %d\n", patched);

  return 0;
}
