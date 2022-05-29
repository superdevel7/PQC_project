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
