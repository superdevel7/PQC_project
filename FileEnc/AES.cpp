#include "util.h"
#include "AES.h"

#pragma comment(lib, "bcrypt")

static NTSTATUS gen_random(BYTE* buf, ULONG buf_len)
{
	BCRYPT_ALG_HANDLE hAlg = nullptr;
	NTSTATUS status = NTE_FAIL;
	do {
		status = BCryptOpenAlgorithmProvider(&hAlg, L"RNG", nullptr, 0);
		if (status != ERROR_SUCCESS) {
			return status;
		}
		status = BCryptGenRandom(hAlg, buf, buf_len, 0);
	} while (0);
	if (hAlg) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}
	return status;
}

//static NTSTATUS derive_key(BYTE* pass, ULONG pass_len, BYTE* salt,
//	ULONG salt_len, const ULONG iteration, BYTE* derived_key, ULONG derived_key_len)
//{
//	BCRYPT_ALG_HANDLE hPrf = nullptr;
//	NTSTATUS status = ERROR_SUCCESS;
//	do {
//		status = BCryptOpenAlgorithmProvider(&hPrf, L"SHA256", nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//		status = BCryptDeriveKeyPBKDF2(hPrf, pass, pass_len, salt, salt_len, iteration, derived_key, derived_key_len, 0);
//	} while (0);
//	if (hPrf) {
//		BCryptCloseAlgorithmProvider(hPrf, 0);
//	}
//	return status;
//}
//
//static NTSTATUS do_encrypt(BYTE* key, ULONG key_len, BYTE* plain_text, ULONG plain_text_len,
//	std::vector<BYTE>& iv, std::vector<BYTE>& cipher_text)
//{
//	NTSTATUS status = NTE_FAIL;
//	BCRYPT_ALG_HANDLE hAlg = nullptr;
//	BCRYPT_KEY_HANDLE hKey = nullptr;
//	do {
//		status = BCryptOpenAlgorithmProvider(&hAlg, L"AES", nullptr, 0);
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//
//		/* create key object */
//		status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, key, key_len, 0);
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//
//		/* set chaining mode */
//		std::wstring mode = BCRYPT_CHAIN_MODE_CBC;
//		BYTE* ptr = reinterpret_cast<BYTE*>(const_cast<wchar_t*>(mode.data()));
//		ULONG size = static_cast<ULONG>(sizeof(wchar_t) * (mode.size() + 1));
//		status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, ptr, size, 0);
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//
//		/* generate iv */
//		ULONG block_len = 0;
//		ULONG res = 0;
//		status = BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, reinterpret_cast<BYTE*>(&block_len), sizeof(block_len), &res, 0);
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//		iv.resize(block_len);
//		status = gen_random(iv.data(), static_cast<ULONG>(iv.size()));
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//
//		/* BCryptEncrypt modify iv parameter, so we need to make copy */
//		std::vector<BYTE> iv_copy = iv;
//
//		/* get cipher text length */
//		ULONG cipher_text_len = 0;
//		status = BCryptEncrypt(hKey, plain_text, plain_text_len, nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
//			nullptr, cipher_text_len, &cipher_text_len, BCRYPT_BLOCK_PADDING);
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//		cipher_text.resize(static_cast<size_t>(cipher_text_len));
//
//		/* now encrypt */
//		status = BCryptEncrypt(hKey, plain_text, plain_text_len, nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
//			cipher_text.data(), cipher_text_len, &cipher_text_len, BCRYPT_BLOCK_PADDING);
//	} while (0);
//	/* cleanup */
//	if (hKey) {
//		BCryptDestroyKey(hKey);
//	}
//	if (hAlg) {
//		BCryptCloseAlgorithmProvider(hAlg, 0);
//	}
//	return status;
//}
//
//static NTSTATUS do_decrypt(BYTE* key, ULONG key_len, BYTE* cipher_text, ULONG cipher_text_len,
//	const std::vector<BYTE>& iv, std::vector<BYTE>& plain_text)
//{
//	NTSTATUS status = NTE_FAIL;
//	BCRYPT_ALG_HANDLE hAlg = nullptr;
//	BCRYPT_KEY_HANDLE hKey = nullptr;
//	do {
//		status = BCryptOpenAlgorithmProvider(&hAlg, L"AES", nullptr, 0);
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//
//		/* create key object */
//		status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, key, key_len, 0);
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//
//		/* set chaining mode */
//		std::wstring mode = BCRYPT_CHAIN_MODE_CBC;
//		BYTE* ptr = reinterpret_cast<BYTE*>(const_cast<wchar_t*>(mode.data()));
//		ULONG size = static_cast<ULONG>(sizeof(wchar_t) * (mode.size() + 1));
//		status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, ptr, size, 0);
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//
//		/* BCryptEncrypt modify iv parameter, so we need to make copy */
//		std::vector<BYTE> iv_copy = iv;
//
//		/* get expected plain text length */
//		ULONG plain_text_len = 0;
//		status = BCryptDecrypt(hKey, cipher_text, cipher_text_len, nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
//			nullptr, plain_text_len, &plain_text_len, BCRYPT_BLOCK_PADDING);
//		plain_text.resize(static_cast<size_t>(plain_text_len));
//
//		/* decrypt */
//		status = BCryptDecrypt(hKey, cipher_text, cipher_text_len, nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
//			plain_text.data(), plain_text_len, &plain_text_len, BCRYPT_BLOCK_PADDING);
//		/* actualize size */
//		plain_text.resize(static_cast<size_t>(plain_text_len));
//	} while (0);
//	/* cleanup */
//	if (hKey) {
//		BCryptDestroyKey(hKey);
//	}
//	if (hAlg) {
//		BCryptCloseAlgorithmProvider(hAlg, 0);
//	}
//	return status;
//}
//
//
//NTSTATUS encrypt(BYTE* pass, ULONG pass_len, const std::vector<BYTE>& plain_text,
//	std::vector<BYTE>& salt, std::vector<BYTE>& iv, std::vector<BYTE>& cipher_text)
//{
//	NTSTATUS status = NTE_FAIL;
//	salt.resize(8);
//	std::array<BYTE, 32> key{ 0x00 };
//	do {
//		/* generate salt */
//		status = gen_random(salt.data(), static_cast<ULONG>(salt.size()));
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//		/* derive key from password using SHA256 algorithm and 20000 iteration */
//		status = derive_key(pass, pass_len, salt.data(), static_cast<ULONG>(salt.size()), 20000, key.data(), key.size());
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//		/* encrypt */
//		status = do_encrypt(key.data(), static_cast<ULONG>(key.size()), const_cast<BYTE*>(plain_text.data()),
//			static_cast<ULONG>(plain_text.size()), iv, cipher_text);
//	} while (0);
//	SecureZeroMemory(key.data(), key.size());
//	return status;
//}
//
//
//NTSTATUS decrypt(BYTE* pass, ULONG pass_len, const std::vector<BYTE>& salt, const std::vector<BYTE>& iv,
//	const std::vector<BYTE>& cipher_text, std::vector<BYTE>& plain_text)
//{
//	NTSTATUS status = NTE_FAIL;
//	std::array<BYTE, 32> key{ 0x00 };
//	do {
//		/* derive key from password using same algorithm, salt and iteraion count */
//		status = derive_key(pass, pass_len, const_cast<BYTE*>(salt.data()), static_cast<ULONG>(salt.size()),
//			20000, key.data(), key.size());
//		if (status != ERROR_SUCCESS) {
//			break;
//		}
//		/* decrypt */
//		status = do_decrypt(key.data(), static_cast<ULONG>(key.size()), const_cast<BYTE*>(cipher_text.data()),
//			static_cast<ULONG>(cipher_text.size()), const_cast<BYTE*>(iv.data()),
//			static_cast<ULONG>(iv.size()), plain_text);
//	} while (0);
//	SecureZeroMemory(key.data(), key.size());
//	return status;
//}

BYTE AES_KEY[32];
const ULONG AES_KEY_LEN = 32;
std::vector<BYTE> iv_copy;
BCRYPT_ALG_HANDLE hAlg = nullptr;
BCRYPT_KEY_HANDLE hKey = nullptr;

NTSTATUS InitializeBCrypt(HANDLE hFile, LONGLONG &llFileSize, BYTE * pass, ULONG pass_len, BOOL bFileCryptFlag)
{
	BCRYPT_ALG_HANDLE hPrf = nullptr;
	NTSTATUS status = ERROR_SUCCESS;
	do {
		/* derive key from password using SHA256 algorithm and 20000 iteration */
		status = BCryptOpenAlgorithmProvider(&hPrf, L"SHA256", nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
		if (status != ERROR_SUCCESS) {
			break;
		}

		status = BCryptDeriveKeyPBKDF2(hPrf, (PUCHAR)pass, pass_len, (PUCHAR)AES_SALT, SALT_LENGTH, 20000, AES_KEY, AES_KEY_LEN, 0);
	} while (0);
	if (hPrf) {
		BCryptCloseAlgorithmProvider(hPrf, 0);
	}

	if (status != ERROR_SUCCESS)
		return status;

	do {
		status = BCryptOpenAlgorithmProvider(&hAlg, L"AES", nullptr, 0);
		if (status != ERROR_SUCCESS) {
			break;
		}

		/* create key object */
		status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, AES_KEY, AES_KEY_LEN, 0);
		if (status != ERROR_SUCCESS) {
			break;
		}

		/* set chaining mode */
		std::wstring mode = BCRYPT_CHAIN_MODE_CBC;
		BYTE* ptr = reinterpret_cast<BYTE*>(const_cast<wchar_t*>(mode.data()));
		ULONG size = static_cast<ULONG>(sizeof(wchar_t) * (mode.size() + 1));
		status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, ptr, size, 0);
		if (status != ERROR_SUCCESS) {
			break;
		}

		/* generate/get iv */
		std::vector<BYTE> iv;
		
		ULONG block_len = 0;
		ULONG res = 0;
		DWORD dwBytesRead;
		status = BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, reinterpret_cast<BYTE*>(&block_len), sizeof(block_len), &res, 0);
		if (status != ERROR_SUCCESS) {
			break;
		}
		iv.resize(block_len);
		if (bFileCryptFlag) {
			status = gen_random(iv.data(), static_cast<ULONG>(iv.size()));
			if (status != ERROR_SUCCESS) {
				break;
			}
		}
		else {
			if (!ReadFile(hFile, iv.data(), block_len, &dwBytesRead, NULL) ||
				dwBytesRead != block_len
				)
			{
				wprintf(L"IV read error\n");
				break;
			}
			llFileSize -= dwBytesRead;
		}

		/* BCryptEncrypt modify iv parameter, so we need to make copy */
		iv_copy = iv;
	} while (0);
	return status;
}

NTSTATUS crypt_iv_write(HANDLE hFile)
{
	NTSTATUS status = ERROR_WRITE_FAULT;
	DWORD dwWriteBytes;
	if (WriteFile(hFile, iv_copy.data(), static_cast<ULONG>(iv_copy.size()), &dwWriteBytes, NULL)) {
		status = ERROR_SUCCESS;
	}
	return status;
}

NTSTATUS buffer_crypt(BOOL isEnc, BYTE* buffer, ULONG buffer_length, BYTE* enc_buffer, ULONG &enc_length, ULONG ulCryptFlag)
{
	NTSTATUS status;
	if (isEnc)
		status = BCryptEncrypt(hKey, buffer, buffer_length, nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
			nullptr, enc_length, &enc_length, ulCryptFlag);
	else
		status = BCryptDecrypt(hKey, buffer, buffer_length, nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
			nullptr, enc_length, &enc_length, ulCryptFlag);
	if (status != ERROR_SUCCESS) {
		return status;
	}
	if (isEnc)
		status = BCryptEncrypt(hKey, buffer, buffer_length, nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
			enc_buffer, enc_length, &enc_length, ulCryptFlag);
	else
		status = BCryptDecrypt(hKey, buffer, buffer_length, nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
			enc_buffer, enc_length, &enc_length, ulCryptFlag);
	return status;
}

void CloseEncryption()
{
	if (hKey) {
		BCryptDestroyKey(hKey);
	}
	if (hAlg) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}
}
//
//NTSTATUS file_enrypt(WCHAR* filePath) {
//	NTSTATUS status = NTE_FAIL;
//	BYTE  ReadBuffer[CHUNK_SIZE + 1];
//	DWORD dwBytesRead;
//	HANDLE hReadFile = CreateFile(filePath,                // file to read
//		GENERIC_READ,			// open for reading
//		FILE_SHARE_READ,		// share for reading
//		NULL,					// default security
//		OPEN_EXISTING,			// existing file only
//		FILE_ATTRIBUTE_NORMAL,	// normal file
//		NULL);
//	if (hReadFile == INVALID_HANDLE_VALUE)
//	{
//		wprintf(L"File open failed\n");
//		return status;
//	}
//
//	WCHAR filePathToWrite[MAX_FILE_PATH_LENGTH] = {};
//	swprintf_s(filePathToWrite, L"%s.enc", filePath);
//
//	HANDLE hWriteFile = CreateFile(filePathToWrite,                // file to write
//		GENERIC_WRITE,			// open for writing
//		FILE_SHARE_WRITE,		// share for writing
//		NULL,					// default security
//		CREATE_ALWAYS,			// create always
//		FILE_ATTRIBUTE_NORMAL,	// normal file
//		NULL);
//
//	if (hWriteFile== INVALID_HANDLE_VALUE)
//	{
//		wprintf(L"Enc file open failed\n");
//		CloseHandle(hReadFile);
//		return status;
//	}
//
//	status = InitializeBCrypt();
//	if (status != ERROR_SUCCESS) {
//		wprintf(L"Initialize crypt failed\n");
//		CloseHandle(hReadFile);
//		CloseHandle(hWriteFile);
//		return status;
//	}
//
//	iv_copy.clear();
//	for (int i = 0; i < 16; i++) iv_copy.push_back(tmp[i]);
//	iv_backup = iv_copy;
//
//	BYTE EncBuffer[CHUNK_SIZE << 1] = {};
//	ULONG EncBufferLen = 0;
//	ULONG WritedBufferLen = 0;
//	
//	// Get file size
//	// Use Large Integer because the file size is up to 10G
//	LARGE_INTEGER lFileSize;
//	GetFileSizeEx(hReadFile, &lFileSize);
//	LONGLONG llFileSize, llCurrentFileSize = 0;
//	memcpy_s(&llFileSize, sizeof(LONGLONG), &lFileSize, sizeof(LARGE_INTEGER));
//
//	while (ReadFile(hReadFile, ReadBuffer, CHUNK_SIZE, &dwBytesRead, NULL) == TRUE) {
//		if (dwBytesRead <= 0) {
//			break;
//		}
//		if (!(llCurrentFileSize & 0xFFFFF)) {
//			print_progress_bar(1. * llCurrentFileSize / llFileSize);
//		}
//		llCurrentFileSize += dwBytesRead;
//
//		// setting crypt flag
//		ULONG ulCryptFlag = 0;
//		if (llCurrentFileSize >= llFileSize)
//			ulCryptFlag = BCRYPT_BLOCK_PADDING;
//
//		status = buffer_crypt(FALSE, ReadBuffer, dwBytesRead, EncBuffer, EncBufferLen, ulCryptFlag);
//		if (status != ERROR_SUCCESS) {
//			wprintf(L"buffer encrypt failed ERROR CODE: %08x\n", status);
//			break;
//		}
//
//		if (!WriteFile(hWriteFile, EncBuffer, EncBufferLen, &WritedBufferLen, NULL)) {
//			status = ERROR_WRITE_FAULT;
//			break;
//		}
//	}
//	if (status == ERROR_SUCCESS) {
//		print_progress_bar(100.);
//	}
//
//	wprintf(L"\n");
//
//	CloseEncryption();
//	CloseHandle(hReadFile);
//	CloseHandle(hWriteFile);
//	return status;
//}