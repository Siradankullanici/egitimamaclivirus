#include <windows.h>
#include <aclapi.h>
#include <iostream>

#pragma comment(lib, "advapi32.lib")

// ─────────────────────────────────────────────
// Privilege aktif et
// ─────────────────────────────────────────────
bool enablePrivilege(LPCWSTR privName) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::wcerr << L"OpenProcessToken başarısız: " << GetLastError() << std::endl;
        return false;
    }

    LUID luid = {};
    if (!LookupPrivilegeValueW(nullptr, privName, &luid)) {
        std::wcerr << L"LookupPrivilegeValue başarısız: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    if (!ok || err != ERROR_SUCCESS) {
        std::wcerr << L"AdjustTokenPrivileges başarısız: " << err << std::endl;
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────
// Sahipliği Administrators grubuna al
// ─────────────────────────────────────────────
bool takeOwnership(const std::wstring& fullPath) {
    PSID pAdminSID = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(
        &ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdminSID)) {
        std::wcerr << L"Admin SID oluşturulamadı: " << GetLastError() << std::endl;
        return false;
    }

    DWORD result = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(fullPath.c_str()),
        SE_REGISTRY_KEY,
        OWNER_SECURITY_INFORMATION,
        pAdminSID,
        nullptr, nullptr, nullptr
    );

    FreeSid(pAdminSID);

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"SetNamedSecurityInfo (owner) başarısız: " << result << std::endl;
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────
// Administrators grubuna tam kontrol ver
// (kilitlemeden önce erişimi garanti altına al)
// ─────────────────────────────────────────────
bool grantAdminFullControl(const std::wstring& fullPath) {
    PSID pAdminSID = nullptr;
    PACL pNewAcl = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(
        &ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdminSID)) {
        std::wcerr << L"Admin SID oluşturulamadı: " << GetLastError() << std::endl;
        return false;
    }

    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = KEY_ALL_ACCESS;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pAdminSID);

    DWORD result = SetEntriesInAclW(1, &ea, nullptr, &pNewAcl);
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"SetEntriesInAcl başarısız: " << result << std::endl;
        FreeSid(pAdminSID);
        return false;
    }

    result = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(fullPath.c_str()),
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, pNewAcl, nullptr
    );

    LocalFree(pNewAcl);
    FreeSid(pAdminSID);

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"Admin ACL uygulanamadı: " << result << std::endl;
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────
// Everyone için Deny ACL uygula (kilitle)
// ─────────────────────────────────────────────
bool applyDenyACL(const std::wstring& fullPath) {
    PSID pEveryoneSID = nullptr;
    PSID pSystemSID = nullptr;
    PSID pAdminSID = nullptr;
    PACL pNewAcl = nullptr;

    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    // Everyone SID
    if (!AllocateAndInitializeSid(
        &worldAuth, 1,
        SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0,
        &pEveryoneSID)) {
        std::wcerr << L"Everyone SID oluşturulamadı: " << GetLastError() << std::endl;
        return false;
    }

    // SYSTEM SID
    if (!AllocateAndInitializeSid(
        &ntAuth, 1,
        SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0,
        &pSystemSID)) {
        std::wcerr << L"System SID oluşturulamadı: " << GetLastError() << std::endl;
        FreeSid(pEveryoneSID);
        return false;
    }

    // Administrators SID
    if (!AllocateAndInitializeSid(
        &ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdminSID)) {
        std::wcerr << L"Admin SID oluşturulamadı: " << GetLastError() << std::endl;
        FreeSid(pEveryoneSID);
        FreeSid(pSystemSID);
        return false;
    }

    // 3 adet Deny kuralı
    EXPLICIT_ACCESSW ea[3] = {};

    // Everyone — Deny
    ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
    ea[0].grfAccessMode = DENY_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(pEveryoneSID);

    // SYSTEM — Deny
    ea[1].grfAccessPermissions = KEY_ALL_ACCESS;
    ea[1].grfAccessMode = DENY_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSystemSID);

    // Administrators — Deny
    ea[2].grfAccessPermissions = KEY_ALL_ACCESS;
    ea[2].grfAccessMode = DENY_ACCESS;
    ea[2].grfInheritance = NO_INHERITANCE;
    ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[2].Trustee.ptstrName = reinterpret_cast<LPWSTR>(pAdminSID);

    DWORD result = SetEntriesInAclW(3, ea, nullptr, &pNewAcl);
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"SetEntriesInAcl başarısız: " << result << std::endl;
        FreeSid(pEveryoneSID);
        FreeSid(pSystemSID);
        FreeSid(pAdminSID);
        return false;
    }

    result = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(fullPath.c_str()),
        SE_REGISTRY_KEY,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, pNewAcl, nullptr
    );

    LocalFree(pNewAcl);
    FreeSid(pEveryoneSID);
    FreeSid(pSystemSID);
    FreeSid(pAdminSID);

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"Deny ACL uygulanamadı: " << result << std::endl;
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────
// Ana kilitleme fonksiyonu
// ─────────────────────────────────────────────
void lockRegistryKey(const std::wstring& keyPath) {
    std::wstring fullPath = L"MACHINE\\" + keyPath;

    std::wcout << L"[*] Hedef: " << fullPath << std::endl;

    // 1. Gerekli yetkileri aç
    std::wcout << L"[*] Yetkiler alınıyor..." << std::endl;
    if (!enablePrivilege(SE_TAKE_OWNERSHIP_NAME)) {
        std::wcerr << L"[-] SeTakeOwnership yetkisi alınamadı." << std::endl;
        return;
    }
    if (!enablePrivilege(SE_RESTORE_NAME)) {
        std::wcerr << L"[-] SeRestore yetkisi alınamadı." << std::endl;
        return;
    }
    if (!enablePrivilege(SE_SECURITY_NAME)) {
        std::wcerr << L"[-] SeSecurity yetkisi alınamadı." << std::endl;
        return;
    }
    std::wcout << L"[+] Yetkiler alındı." << std::endl;

    // 2. Sahipliği Administrators'a al
    std::wcout << L"[*] Sahiplik alınıyor..." << std::endl;
    if (!takeOwnership(fullPath)) {
        std::wcerr << L"[-] Sahiplik alınamadı." << std::endl;
        return;
    }
    std::wcout << L"[+] Sahiplik alındı." << std::endl;

    // 3. Önce Admin'e tam kontrol ver (sonraki adım için gerekli)
    std::wcout << L"[*] Admin erişimi açılıyor..." << std::endl;
    if (!grantAdminFullControl(fullPath)) {
        std::wcerr << L"[-] Admin erişimi açılamadı." << std::endl;
        return;
    }
    std::wcout << L"[+] Admin erişimi açıldı." << std::endl;

    // 4. Deny ACL uygula
    std::wcout << L"[*] Kilit uygulanıyor..." << std::endl;
    if (!applyDenyACL(fullPath)) {
        std::wcerr << L"[-] Kilit uygulanamadı." << std::endl;
        return;
    }
    std::wcout << L"[+] Anahtar başarıyla kilitlendi!" << std::endl;
}

// ─────────────────────────────────────────────
// Giriş noktası
// ─────────────────────────────────────────────
int main() {
    // !! Yönetici (Administrator) olarak çalıştır !!
    const std::wstring keyPath =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

    lockRegistryKey(keyPath);

    std::wcout << L"\nDevam etmek için Enter'a bas..." << std::endl;
    std::wcin.get();
    return 0;
}
