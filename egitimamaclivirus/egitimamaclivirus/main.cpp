#include <windows.h>
#include <aclapi.h>
#include <iostream>

void lockRegistryKey(const std::wstring& keyPath) {
    // SetNamedSecurityInfoW için "MACHINE\" prefix'i gerekli
    std::wstring fullPath = L"MACHINE\\" + keyPath;

    PSID pEveryoneSID = nullptr;
    PACL pNewAcl = nullptr;

    // Everyone SID oluştur
    SID_IDENTIFIER_AUTHORITY sidAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &sidAuthWorld, 1,
        SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0,
        &pEveryoneSID)) {
        std::wcerr << L"SID oluşturulamadı: " << GetLastError() << std::endl;
        return;
    }

    // Erişim kuralını tanımla (sadece okuma)
    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = KEY_READ;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pEveryoneSID);

    // Yeni ACL oluştur
    DWORD result = SetEntriesInAclW(1, &ea, nullptr, &pNewAcl);
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"ACL oluşturulamadı: " << result << std::endl;
        FreeSid(pEveryoneSID);
        return;
    }

    result = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(fullPath.c_str()),
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr,
        pNewAcl,
        nullptr
    );

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"ACL uygulanamadı: " << result << std::endl;
    }
    else {
        std::wcout << L"Başarıyla kilitlendi." << std::endl;
    }

    LocalFree(pNewAcl);
    FreeSid(pEveryoneSID);
}

int main() {
    const std::wstring keyPath =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

    lockRegistryKey(keyPath);
    return 0;
}
