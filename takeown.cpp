#include <Windows.h>
#include <accctrl.h>
#include <aclapi.h>
#include <cstdio>


BOOL SetPrivilege(
  HANDLE hToken,          // access token handle
  LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
  BOOL bEnablePrivilege   // to enable or disable privilege
)
{
  TOKEN_PRIVILEGES tp;
  LUID luid;

  if (!LookupPrivilegeValue(
    nullptr,            // lookup privilege on local system
    lpszPrivilege,   // privilege to lookup 
    &luid
  ))        // receives LUID of privilege
  {
    wprintf(L"LookupPrivilegeValue error: %lu\n", GetLastError());
    return FALSE;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  if (bEnablePrivilege)
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  else
    tp.Privileges[0].Attributes = 0;

  // Enable the privilege or disable all privileges.

  if (!AdjustTokenPrivileges(
    hToken,
    FALSE,
    &tp,
    sizeof(TOKEN_PRIVILEGES),
    nullptr,
    nullptr
  ))
  {
    wprintf(L"AdjustTokenPrivileges error: %lu\n", GetLastError());
    return FALSE;
  }

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

  {
    wprintf(L"The token does not have the specified privilege. \n");
    return FALSE;
  }

  return TRUE;
}

BOOL TakeOwnership(LPTSTR lpszOwnFile)
{
  BOOL bRetval = FALSE;

  HANDLE hToken = nullptr;
  PSID pSIDAdmin = nullptr;
  PSID pSIDEveryone = nullptr;
  PACL pACL = nullptr;
  SID_IDENTIFIER_AUTHORITY SIDAuthWorld =
    SECURITY_WORLD_SID_AUTHORITY;
  SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
  const int NUM_ACES = 2;
  EXPLICIT_ACCESS ea[NUM_ACES];
  DWORD dwRes = 0;

  // Specify the DACL to use.
  // Create a SID for the Everyone group.
  if (!AllocateAndInitializeSid(
    &SIDAuthWorld,
    1,
    SECURITY_WORLD_RID,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    &pSIDEveryone
  ))
  {
    wprintf(
      L"AllocateAndInitializeSid (Everyone) error %lu\n",
      GetLastError()
    );
    goto Cleanup;
  }

  // Create a SID for the BUILTIN\Administrators group.
  if (!AllocateAndInitializeSid(
    &SIDAuthNT,
    2,
    SECURITY_BUILTIN_DOMAIN_RID,
    DOMAIN_ALIAS_RID_ADMINS,
    0,
    0,
    0,
    0,
    0,
    0,
    &pSIDAdmin
  ))
  {
    wprintf(L"AllocateAndInitializeSid (Admin) error %lu\n", GetLastError());
    goto Cleanup;
  }

  ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

  // Set read access for Everyone.
  ea[0].grfAccessPermissions = GENERIC_READ;
  ea[0].grfAccessMode = SET_ACCESS;
  ea[0].grfInheritance = NO_INHERITANCE;
  ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  ea[0].Trustee.ptstrName = (LPTSTR)pSIDEveryone;

  // Set full control for Administrators.
  ea[1].grfAccessPermissions = GENERIC_ALL;
  ea[1].grfAccessMode = SET_ACCESS;
  ea[1].grfInheritance = NO_INHERITANCE;
  ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
  ea[1].Trustee.ptstrName = (LPTSTR)pSIDAdmin;

  if (ERROR_SUCCESS != SetEntriesInAcl(
    NUM_ACES,
    ea,
    nullptr,
    &pACL
  ))
  {
    wprintf(L"Failed SetEntriesInAcl\n");
    goto Cleanup;
  }

  // Try to modify the object's DACL.
  dwRes = SetNamedSecurityInfo(
    lpszOwnFile,                 // name of the object
    SE_FILE_OBJECT,              // type of object
    DACL_SECURITY_INFORMATION,   // change only the object's DACL
    nullptr,
    nullptr,                  // do not change owner or group
    pACL,                        // DACL specified
    nullptr
  );                       // do not change SACL

  if (ERROR_SUCCESS == dwRes)
  {
    wprintf(L"Successfully changed DACL\n");
    bRetval = TRUE;
    // No more processing needed.
    goto Cleanup;
  }
  if (dwRes != ERROR_ACCESS_DENIED)
  {
    wprintf(
      L"First SetNamedSecurityInfo call failed: %lu\n",
      dwRes
    );
    goto Cleanup;
  }

  // If the preceding call failed because access was denied, 
  // enable the SE_TAKE_OWNERSHIP_NAME privilege, create a SID for 
  // the Administrators group, take ownership of the object, and 
  // disable the privilege. Then try again to set the object's DACL.

  // Open a handle to the access token for the calling process.
  if (!OpenProcessToken(
    GetCurrentProcess(),
    TOKEN_ADJUST_PRIVILEGES,
    &hToken
  ))
  {
    wprintf(L"OpenProcessToken failed: %lu\n", GetLastError());
    goto Cleanup;
  }

  // Enable the SE_TAKE_OWNERSHIP_NAME privilege.
  if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE))
  {
    wprintf(L"You must be logged on as Administrator.\n");
    goto Cleanup;
  }

  // Set the owner in the object's security descriptor.
  dwRes = SetNamedSecurityInfo(
    lpszOwnFile,                 // name of the object
    SE_FILE_OBJECT,              // type of object
    OWNER_SECURITY_INFORMATION,  // change only the object's owner
    pSIDAdmin,                   // SID of Administrator group
    nullptr,
    nullptr,
    nullptr
  );

  if (dwRes != ERROR_SUCCESS)
  {
    wprintf(L"Could not set owner. Error: %lu\n", dwRes);
    goto Cleanup;
  }

  // Disable the SE_TAKE_OWNERSHIP_NAME privilege.
  if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE))
  {
    wprintf(L"Failed SetPrivilege call unexpectedly.\n");
    goto Cleanup;
  }

  // Try again to modify the object's DACL,
  // now that we are the owner.
  dwRes = SetNamedSecurityInfo(
    lpszOwnFile,                 // name of the object
    SE_FILE_OBJECT,              // type of object
    DACL_SECURITY_INFORMATION,   // change only the object's DACL
    nullptr,
    nullptr,                  // do not change owner or group
    pACL,                        // DACL specified
    nullptr
  );                       // do not change SACL

  if (dwRes == ERROR_SUCCESS)
  {
    wprintf(L"Successfully changed DACL\n");
    bRetval = TRUE;
  }
  else
  {
    wprintf(L"Second SetNamedSecurityInfo call failed: %lu\n", dwRes);
  }

Cleanup:

  if (pSIDAdmin)
    FreeSid(pSIDAdmin);

  if (pSIDEveryone)
    FreeSid(pSIDEveryone);

  if (pACL)
    LocalFree(pACL);

  if (hToken)
    CloseHandle(hToken);

  return bRetval;
}
