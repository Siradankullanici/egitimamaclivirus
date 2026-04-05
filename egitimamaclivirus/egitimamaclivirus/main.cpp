#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <iostream>

void lockRegistryKey(const std::wstring& keyPath) {
	HKEY hKey;
	LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_ALL_ACCESS, &hKey);
	if (result != ERROR_SUCCESS) {
		std::wcerr << L"Failed to open registry key: " << result << std::endl;
		return;
	}
	// Yeni bir ACL oluþtur
	PACL pNewAcl = nullptr;
	EXPLICIT_ACCESSW ea;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	PSID pEveryoneSID = nullptr;
	// Everyone SID'sini oluþtur
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
		std::wcerr << L"Failed to create SID: " << GetLastError() << std::endl;
		RegCloseKey(hKey);
		return;
	}
	// Eriþim haklarýný ayarla
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESSW));
	ea.grfAccessPermissions = KEY_READ; // Sadece okuma izni ver
	ea.grfAccessMode = SET_ACCESS; // Mevcut izinleri deðiþtir
	ea.grfInheritance = NO_INHERITANCE; // Alt anahtarlara izin verme
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = (LPWSTR)pEveryoneSID;
	// Yeni ACL'yi oluþtur
	result = SetEntriesInAclW(1, &ea, nullptr, &pNewAcl);
	if (result != ERROR_SUCCESS) {
		std::wcerr << L"Failed to set ACL: " << result << std::endl;
		FreeSid(pEveryoneSID);
		RegCloseKey(hKey);
		return;
	}
	// Yeni ACL'yi anahtara uygula
	result = SetNamedSecurityInfoW((LPWSTR)keyPath.c_str(), SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewAcl, nullptr);
	if (result != ERROR_SUCCESS) {
		std::wcerr
			<< L"Failed to apply ACL: " << result << std::endl;
	}
}

int main() {
	const std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
	// Registry anahtarýný kitle
	lockRegistryKey(keyPath);
	return 0;
}