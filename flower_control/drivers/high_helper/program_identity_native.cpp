// Offline file identity and publisher verification for retained Flower features.
// Exposes only the three compatibility exports used by administrator program
// inspection and ordinary security-prompt provenance; no UAC desktop, input,
// SYSTEM worker, telemetry, update or network behavior is introduced here.
// Signature chain and catalog checks retain the original cache-only policy.
// The exported inspection always uses a null Stop handle. Non-null Stop is
// rejected because this standalone component has no secure-desktop monitor.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <sddl.h>
#include <aclapi.h>
#include <winver.h>
#pragma comment(lib, "version.lib")
#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
namespace flower_uac {
struct Boundary : std::runtime_error { using std::runtime_error::runtime_error; };
void require(bool ok, const char* code) { if (!ok) throw Boundary(code); }
struct Handle {
    HANDLE value = nullptr;
    explicit Handle(HANDLE v = nullptr) : value(v) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
bool same(const std::wstring& a, const std::wstring& b) {
    return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(),
        static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}
std::wstring wide(const char* value) {
    std::wstring result; while (*value) result.push_back(static_cast<unsigned char>(*value++));
    return result;
}
std::wstring quote(const std::wstring& value) {
    std::wstring result = L"\"";
    for (wchar_t c : value) {
        if (c == L'"' || c == L'\\') { result += L'\\'; result += c; }
        else if (c < 32) {
            wchar_t escaped[7]{}; swprintf_s(escaped, L"\\u%04x", static_cast<unsigned>(c)); result += escaped;
        } else result += c;
    }
    return result + L"\"";
}
std::wstring hex(const BYTE* bytes, size_t length, bool upper = false) {
    const wchar_t* digits = upper ? L"0123456789ABCDEF" : L"0123456789abcdef";
    std::wstring result; result.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) { result += digits[bytes[i] >> 4]; result += digits[bytes[i] & 15]; }
    return result;
}
int writeResult(const std::wstring& json, wchar_t* out, unsigned cap, int code) {
    if (!out || cap == 0) return 3;
    out[0] = 0;
    if (json.size() >= cap) return 3;
    std::copy(json.begin(), json.end(), out); out[json.size()] = 0; return code;
}
std::wstring failure(const char* reason) {
    return L"{\"schema\":1,\"state\":\"rejected\",\"reason\":" + quote(wide(reason))
        + L",\"input_dispatched\":false,\"input_route_verified\":false,\"production_ready\":false,"
          L"\"cancel_available\":false,\"accept_available\":false,\"program_binding_verified\":false} ";
}

bool nonceValid(const std::wstring& value) { return value.size() == 64 && value.find_first_not_of(L"0123456789abcdef") == std::wstring::npos; }
void requireLocalPath(const std::wstring& path) {
    require(path.size() >= 3 && path.size() < 32760 && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))
        && path[1] == L':' && path[2] == L'\\' && path.find(L':', 2) == std::wstring::npos
        && path.find_first_of(L"\r\n\"<>|?*") == std::wstring::npos, "publisher_path_rejected");
    const auto root = path.substr(0, 3); require(GetDriveTypeW(root.c_str()) == DRIVE_FIXED, "publisher_path_not_local_fixed");
}
std::wstring finalPath(HANDLE file) {
    std::wstring path(32768, 0); auto count = GetFinalPathNameByHandleW(file, path.data(), static_cast<DWORD>(path.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    require(count > 0 && count < path.size(), "publisher_path_unavailable"); path.resize(count);
    require(path.rfind(L"\\\\?\\", 0) == 0 && path.rfind(L"\\\\?\\UNC\\", 0) != 0, "publisher_path_not_local_fixed");
    path.erase(0, 4); requireLocalPath(path); return path;
}
void readAt(HANDLE file, ULONGLONG offset, void* result, DWORD count) {
    LARGE_INTEGER position{}; position.QuadPart = static_cast<LONGLONG>(offset); DWORD read = 0;
    require(SetFilePointerEx(file, position, nullptr, FILE_BEGIN) && ReadFile(file, result, count, &read, nullptr) && read == count, "publisher_pe_unavailable");
}
bool embeddedSignatureAbsent(HANDLE file, bool* managedPayload = nullptr) {
    IMAGE_DOS_HEADER dos{}; readAt(file, 0, &dos, sizeof(dos));
    require(dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew >= static_cast<LONG>(sizeof(dos)) && dos.e_lfanew <= 1048576, "publisher_pe_unavailable");
    DWORD signature = 0; readAt(file, static_cast<ULONGLONG>(dos.e_lfanew), &signature, sizeof(signature));
    require(signature == IMAGE_NT_SIGNATURE, "publisher_pe_unavailable"); IMAGE_FILE_HEADER header{};
    const auto optionalOffset = static_cast<ULONGLONG>(dos.e_lfanew) + sizeof(DWORD) + sizeof(header);
    readAt(file, static_cast<ULONGLONG>(dos.e_lfanew) + sizeof(DWORD), &header, sizeof(header)); WORD magic = 0;
    readAt(file, optionalOffset, &magic, sizeof(magic)); IMAGE_DATA_DIRECTORY security{};
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 optional{}; require(header.SizeOfOptionalHeader >= sizeof(optional), "publisher_pe_unavailable");
        readAt(file, optionalOffset, &optional, sizeof(optional)); require(optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY, "publisher_pe_unavailable");
        security = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        if (managedPayload) *managedPayload = optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
            && (optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0 || optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0);
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 optional{}; require(header.SizeOfOptionalHeader >= sizeof(optional), "publisher_pe_unavailable");
        readAt(file, optionalOffset, &optional, sizeof(optional)); require(optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY, "publisher_pe_unavailable");
        security = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        if (managedPayload) *managedPayload = optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
            && (optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0 || optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0);
    } else throw Boundary("publisher_pe_unavailable");
    return security.Size == 0 && security.VirtualAddress == 0;
}
struct Trust {
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    Trust() {
        data.cbStruct = sizeof(data); data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4;
    }
    ~Trust() { data.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data); }
    LONG verify() { return WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data); }
    std::wstring signer(bool microsoftRequired, std::wstring* subject = nullptr) {
        auto provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        require(provider != nullptr, "publisher_signer_unavailable");
        auto signer = WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
        require(signer && signer->dwError == 0 && signer->csCertChain > 0 && signer->pasCertChain && signer->pasCertChain[0].pCert
            && signer->pChainContext, "publisher_signer_unavailable");
        auto certificate = signer->pasCertChain[0].pCert;
        const auto chain = signer->pChainContext;
        require(chain->cChain > 0 && chain->rgpChain && chain->rgpChain[0] && chain->rgpChain[0]->cElement > 0
            && chain->rgpChain[0]->rgpElement && chain->rgpChain[0]->rgpElement[0] && chain->rgpChain[0]->rgpElement[0]->pCertContext
            && CertCompareCertificate(X509_ASN_ENCODING, certificate->pCertInfo, chain->rgpChain[0]->rgpElement[0]->pCertContext->pCertInfo),
            "publisher_signer_chain_mismatch");
        if (microsoftRequired) {
            CERT_CHAIN_POLICY_PARA parameters{}; parameters.cbSize = sizeof(parameters);
            parameters.dwFlags = MICROSOFT_ROOT_CERT_CHAIN_POLICY_DISABLE_FLIGHT_ROOT_FLAG;
            CERT_CHAIN_POLICY_STATUS status{}; status.cbSize = sizeof(status);
            require(CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, signer->pChainContext, &parameters, &status)
                && status.dwError == 0, "consent_not_microsoft_signed");
        }
        if (subject) {
            // Read the CN from the leaf actually accepted by WinTrust, never
            // a PE resource, unverified certificate or display-name fallback.
            const auto count = CertGetNameStringW(certificate, CERT_NAME_ATTR_TYPE, 0,
                const_cast<char*>(szOID_COMMON_NAME), nullptr, 0);
            require(count > 1 && count <= 512, "publisher_subject_unavailable");
            std::vector<wchar_t> name(count);
            require(CertGetNameStringW(certificate, CERT_NAME_ATTR_TYPE, 0,
                const_cast<char*>(szOID_COMMON_NAME), name.data(), count) == count,
                "publisher_subject_unavailable");
            subject->assign(name.data(), count - 1);
        }
        BYTE* encoded = nullptr; DWORD count = 0;
        require(CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &certificate->pCertInfo->SubjectPublicKeyInfo,
            CRYPT_ENCODE_ALLOC_FLAG, nullptr, &encoded, &count) != FALSE, "publisher_key_unavailable");
        struct Local { BYTE* value; ~Local() { LocalFree(value); } } memory{encoded};
        BYTE hash[32]{}; DWORD hashCount = sizeof(hash);
        require(CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr, encoded, count, hash, &hashCount) && hashCount == 32, "publisher_key_unavailable");
        return hex(hash, sizeof(hash));
    }
};
struct Publisher { int code = 2; std::wstring key, path, subject; };
Publisher publisherFromHandle(HANDLE file, const std::wstring& path, bool microsoftRequired = false, bool needSubject = false) {
    WINTRUST_FILE_INFO fileInfo{}; fileInfo.cbStruct = sizeof(fileInfo); fileInfo.pcwszFilePath = path.c_str(); fileInfo.hFile = file;
    {
        Trust trust; trust.data.dwUnionChoice = WTD_CHOICE_FILE; trust.data.pFile = &fileInfo;
        const auto status = trust.verify();
        if (status == ERROR_SUCCESS) {
            std::wstring subject; auto key = trust.signer(microsoftRequired, needSubject ? &subject : nullptr);
            return {0, std::move(key), path, std::move(subject)};
        }
        if (status != TRUST_E_NOSIGNATURE) return {2, L"", path};
    }
    // Windows binaries can be catalog signed. Query only locally installed
    // catalogs before treating a valid PE with no certificate table as unsigned.
    require(embeddedSignatureAbsent(file), "publisher_invalid_embedded_signature");
    HCATADMIN admin = nullptr;
    require(CryptCATAdminAcquireContext2(&admin, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != FALSE, "publisher_catalog_unavailable");
    struct CatalogAdmin { HCATADMIN value; ~CatalogAdmin() { CryptCATAdminReleaseContext(value, 0); } } releaseAdmin{admin};
    DWORD hashSize = 0;
    require(CryptCATAdminCalcHashFromFileHandle2(admin, file, &hashSize, nullptr, 0) && hashSize > 0 && hashSize <= 128, "publisher_catalog_unavailable");
    std::vector<BYTE> hash(hashSize);
    require(CryptCATAdminCalcHashFromFileHandle2(admin, file, &hashSize, hash.data(), 0) != FALSE, "publisher_catalog_unavailable");
    const auto tag = hex(hash.data(), hashSize, true);
    SetLastError(ERROR_SUCCESS); auto catalog = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), hashSize, 0, nullptr);
    const auto error = GetLastError();
    if (!catalog) {
        require(error == ERROR_SUCCESS || error == ERROR_NOT_FOUND, "publisher_catalog_unavailable"); return {1, L"", path};
    }
    struct Catalog { HCATADMIN admin; HCATINFO value; ~Catalog() { CryptCATAdminReleaseCatalogContext(admin, value, 0); } } releaseCatalog{admin, catalog};
    CATALOG_INFO infoCatalog{}; infoCatalog.cbStruct = sizeof(infoCatalog);
    require(CryptCATCatalogInfoFromContext(catalog, &infoCatalog, 0) != FALSE, "publisher_catalog_unavailable");
    WINTRUST_CATALOG_INFO catalogInfo{}; catalogInfo.cbStruct = sizeof(catalogInfo);
    catalogInfo.pcwszCatalogFilePath = infoCatalog.wszCatalogFile; catalogInfo.pcwszMemberTag = tag.c_str();
    catalogInfo.pcwszMemberFilePath = path.c_str(); catalogInfo.hMemberFile = file;
    catalogInfo.pbCalculatedFileHash = hash.data(); catalogInfo.cbCalculatedFileHash = hashSize; catalogInfo.hCatAdmin = admin;
    Trust trust; trust.data.dwUnionChoice = WTD_CHOICE_CATALOG; trust.data.pCatalog = &catalogInfo;
    if (trust.verify() == ERROR_SUCCESS) {
        std::wstring subject; auto key = trust.signer(microsoftRequired, needSubject ? &subject : nullptr);
        return {0, std::move(key), path, std::move(subject)};
    }
    // A failed/unknown local catalog is never downgraded to unsigned. Other
    // catalog candidates may exist; this conservative narrow route stays unknown.
    return {2, L"", path};
}
Publisher publisher(const wchar_t* raw, bool microsoftRequired = false, bool needSubject = false) {
    require(raw && wcsnlen_s(raw, 32768) < 32768, "publisher_path_rejected"); std::wstring path(raw); requireLocalPath(path);
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    require(file.value != INVALID_HANDLE_VALUE, "publisher_file_unavailable"); BY_HANDLE_FILE_INFORMATION info{};
    require(GetFileInformationByHandle(file.value, &info) && (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0,
        "publisher_file_rejected"); return publisherFromHandle(file.value, finalPath(file.value), microsoftRequired, needSubject);
}

void stopCheck(HANDLE stop, ULONGLONG deadline) { (void)stop; (void)deadline; throw Boundary("identity_experiment_stop_argument_rejected"); }
void programPathSyntax(const std::wstring& path) {
    requireLocalPath(path);
    require(path.size() <= 2048 && path.find(L'/') == std::wstring::npos
        && path.find_first_of(L"\t\b\f") == std::wstring::npos
        && std::none_of(path.begin(), path.end(), [](wchar_t c) { return c < 32; }), "uac_program_path_rejected");
    for (size_t at = 3; at < path.size();) {
        const auto next = path.find(L'\\', at); const auto end = next == std::wstring::npos ? path.size() : next;
        const auto segment = path.substr(at, end - at);
        require(!segment.empty() && segment != L"." && segment != L".." && segment.back() != L'.' && segment.back() != L' ', "uac_program_path_rejected");
        if (next == std::wstring::npos) break; at = next + 1;
    }
    require(path.size() > 4 && same(path.substr(path.size() - 4), L".exe"), "uac_program_pe_required");
}
void caseInsensitiveDirectory(HANDLE directory) {
    struct CaseInfo { ULONG flags; } info{};
    require(GetFileInformationByHandleEx(directory, FileCaseSensitiveInfo, &info, sizeof(info)) && info.flags == 0,
        "uac_program_case_sensitive_or_unknown");
}
struct ManagedPayloadMarker {
    // SDK apphosts carry a custom OriginalFilename but resolve these hostfxr
    // entry points to execute their separate managed payload. Keep this a
    // finite known-host veto, not a claim to recognize arbitrary loaders.
    static constexpr char marker[] = "hostfxr_main";
    size_t matched = 0; bool found = false;
    void consume(const BYTE* bytes, size_t count) {
        for (size_t index = 0; index < count && !found; ++index) {
            const auto value = bytes[index]; matched = value == marker[matched] ? matched + 1 : value == marker[0] ? 1 : 0;
            found = matched == sizeof(marker) - 1;
        }
    }
};
std::wstring programDigest(HANDLE file, HANDLE stop = nullptr, ULONGLONG deadline = 0, bool* managedPayload = nullptr) {
    LARGE_INTEGER size{}, zero{};
    require(GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= 2147483648LL && SetFilePointerEx(file, zero, nullptr, FILE_BEGIN), "uac_program_size_rejected");
    BCRYPT_ALG_HANDLE algorithm = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
    require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "uac_program_hash_unavailable");
    struct HashRelease { BCRYPT_ALG_HANDLE algorithm; BCRYPT_HASH_HANDLE& hash; ~HashRelease() { if (hash) BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0); } } release{algorithm, hash};
    require(BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) == 0, "uac_program_hash_unavailable");
    std::vector<BYTE> chunk(1024 * 1024); ULONGLONG consumed = 0; ManagedPayloadMarker marker;
    while (consumed < static_cast<ULONGLONG>(size.QuadPart)) {
        if (stop) stopCheck(stop, deadline); DWORD count = 0;
        require(ReadFile(file, chunk.data(), static_cast<DWORD>(std::min<ULONGLONG>(chunk.size(), size.QuadPart - consumed)), &count, nullptr)
            && count > 0 && BCryptHashData(hash, chunk.data(), count, 0) == 0, "uac_program_hash_unavailable"); consumed += count;
        if (managedPayload) marker.consume(chunk.data(), count);
    }
    if (managedPayload && marker.found) *managedPayload = true;
    BYTE bytes[32]{}; require(BCryptFinishHash(hash, bytes, sizeof(bytes), 0) == 0, "uac_program_hash_unavailable"); return hex(bytes, sizeof(bytes));
}
struct ProgramAncestor {
    Handle handle; std::wstring path;
    explicit ProgramAncestor(const std::wstring& raw) : handle(CreateFileW((L"\\\\?\\" + raw).c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr)) {
        require(handle.value != INVALID_HANDLE_VALUE, "uac_program_ancestor_unavailable"); BY_HANDLE_FILE_INFORMATION info{};
        require(GetFileInformationByHandle(handle.value, &info) && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            && !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "uac_program_ancestor_reparse");
        caseInsensitiveDirectory(handle.value); path = finalPath(handle.value);
    }
    void recheck() const { caseInsensitiveDirectory(handle.value); BY_HANDLE_FILE_INFORMATION info{};
        require(GetFileInformationByHandle(handle.value, &info) && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            && !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && finalPath(handle.value) == path, "uac_program_ancestor_changed"); }
};
struct ProgramFile {
    std::vector<std::unique_ptr<ProgramAncestor>> ancestors; Handle file;
    std::wstring path, digest, kind, identity, volume, fileId; bool managedPayload = false;
    bool allowlistProtected() const;
    explicit ProgramFile(const std::wstring& raw, HANDLE stop = nullptr, ULONGLONG deadline = 0) {
        programPathSyntax(raw); const auto separator = raw.find_last_of(L'\\');
        ancestors.push_back(std::make_unique<ProgramAncestor>(raw.substr(0, 3)));
        for (size_t at = 3; at < separator;) {
            if (stop) stopCheck(stop, deadline); const auto next = raw.find(L'\\', at);
            const auto end = std::min(separator, next); ancestors.push_back(std::make_unique<ProgramAncestor>(raw.substr(0, end)));
            if (end == separator) break; at = end + 1;
        }
        file.value = CreateFileW((L"\\\\?\\" + raw).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        require(file.value != INVALID_HANDLE_VALUE, "uac_program_file_unavailable"); BY_HANDLE_FILE_INFORMATION info{};
        require(GetFileInformationByHandle(file.value, &info) && !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)), "uac_program_file_reparse");
        path = finalPath(file.value); programPathSyntax(path);
        // Re-check the physical parent chain too. Aliases do not authorize a
        // second path, and ordinary programs do not require helper ACLs/labels.
        const auto parentAt = path.find_last_of(L'\\'); require(same(path.substr(0, parentAt == 2 ? 3 : parentAt), ancestors.back()->path), "uac_program_parent_changed");
        FILE_ID_INFO id{}; require(GetFileInformationByHandleEx(file.value, FileIdInfo, &id, sizeof(id)), "uac_program_file_id_unavailable");
        volume = hex(reinterpret_cast<const BYTE*>(&id.VolumeSerialNumber), sizeof(id.VolumeSerialNumber)); fileId = hex(id.FileId.Identifier, sizeof(id.FileId.Identifier));
        (void)embeddedSignatureAbsent(file.value, &managedPayload); digest = programDigest(file.value, stop, deadline, &managedPayload);
        const auto signer = publisherFromHandle(file.value, path);
        if (signer.code == 0 && nonceValid(signer.key)) { kind = L"signed"; identity = signer.key; }
        else if (signer.code == 1) { kind = L"sha256"; identity = digest; }
        else throw Boundary("uac_program_signature_unknown");
        recheck(stop, deadline);
    }
    void recheck(HANDLE stop = nullptr, ULONGLONG deadline = 0) const {
        for (const auto& parent : ancestors) { if (stop) stopCheck(stop, deadline); parent->recheck(); }
        FILE_ID_INFO id{}; require(GetFileInformationByHandleEx(file.value, FileIdInfo, &id, sizeof(id))
            && volume == hex(reinterpret_cast<const BYTE*>(&id.VolumeSerialNumber), sizeof(id.VolumeSerialNumber))
            && fileId == hex(id.FileId.Identifier, sizeof(id.FileId.Identifier)) && path == finalPath(file.value)
            && digest == programDigest(file.value, stop, deadline), "uac_program_changed");
        const auto fresh = publisherFromHandle(file.value, path);
        require(kind == L"signed" ? fresh.code == 0 && fresh.key == identity : fresh.code == 1, "uac_program_signature_unknown");
    }
    std::wstring json() const {
        return L"{\"path\":" + quote(path) + L",\"sha256\":" + quote(digest) + L",\"identity_kind\":" + quote(kind)
            + L",\"identity\":" + quote(identity) + L",\"volume\":" + quote(volume) + L",\"file_id\":" + quote(fileId)
            + L",\"allowlist_protected\":" + (allowlistProtected() ? L"true}" : L"false}");
    }
};

constexpr DWORD ProofMutationRights = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
bool privilegedSid(PSID value, bool allowInstaller = false) {
    if (!value || !IsValidSid(value)) return false;
    if (IsWellKnownSid(value, WinLocalSystemSid) || IsWellKnownSid(value, WinBuiltinAdministratorsSid)) return true;
    if (!allowInstaller) return false;
    PSID installer = nullptr;
    require(ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &installer), "proof_security_unavailable");
    const bool result = EqualSid(value, installer) != FALSE; LocalFree(installer); return result;
}
void protectedDescriptor(PSECURITY_DESCRIPTOR descriptor, bool requireHigh, bool allowInstaller, bool systemExecutable = false, DWORD mutationRights = ProofMutationRights) {
    require(descriptor && IsValidSecurityDescriptor(descriptor), "proof_security_unavailable");
    PSID owner = nullptr; BOOL defaulted = FALSE;
    require(GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) && privilegedSid(owner, allowInstaller), "proof_owner_unprotected");
    PACL dacl = nullptr; BOOL present = FALSE;
    require(GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) && present && dacl && IsValidAcl(dacl), "proof_dacl_unprotected");
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw = nullptr; require(GetAce(dacl, i, &raw), "proof_acl_unavailable"); const auto header = static_cast<ACE_HEADER*>(raw);
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        require(header->AceType == ACCESS_ALLOWED_ACE_TYPE && header->AceSize >= sizeof(ACCESS_ALLOWED_ACE), "proof_acl_type_unsupported");
        const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        if (ace->Mask & mutationRights) require(privilegedSid(&ace->SidStart, allowInstaller), "proof_write_acl_unprotected");
    }
    if (systemExecutable) {
        // A High image label demotes a SYSTEM child via NEW_PROCESS_MIN.
        // Only the exact helper executable uses this contract; ACLs above and
        // the High version directory remain mandatory.
        PACL labels = nullptr;
        require(GetSecurityDescriptorSacl(descriptor, &present, &labels, &defaulted), "proof_label_unavailable");
        if (present && labels) {
            require(IsValidAcl(labels), "proof_label_unavailable");
            for (DWORD i = 0; i < labels->AceCount; ++i) {
                void* raw = nullptr; require(GetAce(labels, i, &raw), "proof_label_unavailable");
                require(static_cast<ACE_HEADER*>(raw)->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE, "uac_image_label_would_demote_system");
            }
        }
        return;
    }
    if (!requireHigh) return;
    PACL sacl = nullptr; require(GetSecurityDescriptorSacl(descriptor, &present, &sacl, &defaulted) && present && sacl && IsValidAcl(sacl), "proof_high_label_missing");
    unsigned labels = 0;
    for (DWORD i = 0; i < sacl->AceCount; ++i) {
        void* raw = nullptr; require(GetAce(sacl, i, &raw), "proof_label_unavailable"); const auto header = static_cast<ACE_HEADER*>(raw);
        if (header->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE || (header->AceFlags & INHERIT_ONLY_ACE)) continue;
        const auto label = static_cast<SYSTEM_MANDATORY_LABEL_ACE*>(raw); auto labelSid = static_cast<PSID>(&label->SidStart);
        require(header->AceSize >= sizeof(SYSTEM_MANDATORY_LABEL_ACE) && IsValidSid(labelSid)
            && (label->Mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) && GetSidSubAuthorityCount(labelSid) && *GetSidSubAuthorityCount(labelSid) == 1,
            "proof_high_label_unprotected");
        const auto level = *GetSidSubAuthority(labelSid, 0);
        require(IsWellKnownSid(labelSid, WinHighLabelSid) || (level == SECURITY_MANDATORY_SYSTEM_RID && IsWellKnownSid(labelSid, WinSystemLabelSid)), "proof_high_label_unprotected");
        ++labels;
    }
    require(labels == 1, "proof_high_label_unprotected");
}
void protectedHandle(HANDLE file, bool high, bool installer, bool systemExecutable = false, DWORD mutationRights = ProofMutationRights) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto flags = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | ((high || systemExecutable) ? LABEL_SECURITY_INFORMATION : 0);
    require(GetSecurityInfo(file, SE_FILE_OBJECT, flags, nullptr, nullptr, nullptr, nullptr, &descriptor) == ERROR_SUCCESS, "proof_security_unavailable");
    struct Release { PSECURITY_DESCRIPTOR p; ~Release() { LocalFree(p); } } release{descriptor}; protectedDescriptor(descriptor, high, installer, systemExecutable, mutationRights);
}
bool ProgramFile::allowlistProtected() const {
    if (managedPayload) return false;
    try {
        // Security descriptors are read from the same pinned objects used for
        // identity/hash inspection, not from a second path lookup. No High
        // mandatory label is imposed on ordinary installed applications.
        protectedHandle(file.value, false, true);
        for (size_t index = 0; index < ancestors.size(); ++index) {
            // A volume root may let users create unrelated directories. They
            // must still be unable to delete/replace our protected descendant.
            const DWORD mask = index == 0 ? DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL : ProofMutationRights;
            protectedHandle(ancestors[index]->handle.value, false, true, false, mask);
        }
        return true;
    } catch (const Boundary&) { return false; }
}
}
extern "C" __declspec(dllexport) int __cdecl FlowerUacPublisher(const wchar_t* file, wchar_t* out, unsigned cap) {
    using namespace flower_uac;
    if (!out || cap == 0) return 3; out[0] = 0;
    try { const auto result = publisher(file); return result.code == 0 ? writeResult(result.key, out, cap, 0) : result.code; }
    catch (...) { return 2; }
}
extern "C" __declspec(dllexport) int __cdecl FlowerUacPublisherDetails(const wchar_t* file, wchar_t* out, unsigned cap) {
    using namespace flower_uac;
    if (!out || cap < 1024) { if (out && cap) out[0] = 0; return 3; }
    try {
        const auto result = publisher(file, false, true);
        if (result.code != 0) return result.code;
        return writeResult(L"{\"schema\":1,\"publisher_key_sha256\":" + quote(result.key)
            + L",\"signer_common_name\":" + quote(result.subject) + L",\"signature\":\"trusted_offline\"}", out, cap, 0);
    } catch (...) { out[0] = 0; return 2; }
}
extern "C" __declspec(dllexport) int __cdecl FlowerUacInspectProgram(const wchar_t* path, wchar_t* out, unsigned cap) {
    using namespace flower_uac; if (!out || cap < 1024) { if (out && cap) out[0] = 0; return 3; }
    try { require(path && wcsnlen_s(path, 2049) <= 2048, "uac_program_path_rejected"); ProgramFile file(path);
        return writeResult(file.json(), out, cap, 0); } catch (const std::exception& error) { return writeResult(failure(error.what()), out, cap, 2); }
}