#include <windows.h>
#include "util.h"
#include "PostQuantum.h"


#ifdef OQS_ENABLE_KEM_frodokem_640_aes

BYTE shared_secret_e[OQS_KEM_frodokem_640_aes_length_shared_secret];
BYTE shared_secret_d[OQS_KEM_frodokem_640_aes_length_shared_secret];
extern BYTE public_key[OQS_KEM_frodokem_640_aes_length_public_key];
extern BYTE secret_key[OQS_KEM_frodokem_640_aes_length_secret_key];
extern BYTE ciphertext[OQS_KEM_frodokem_640_aes_length_ciphertext];
extern BYTE aes_password[OQS_KEM_frodokem_640_aes_length_shared_secret];
extern BOOL bFileCryptFlag;
extern BYTE TmpReadBuffer[65536];

OQS_STATUS get_aes_password()
{
	OQS_STATUS rc;
	if (bFileCryptFlag) {
		rc = OQS_KEM_frodokem_640_aes_encaps(ciphertext, shared_secret_e, public_key);
		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_KEM_frodokem_640_aes_encaps failed!\n");
			cleanup_stack(secret_key, OQS_KEM_frodokem_640_aes_length_secret_key,
				shared_secret_e, shared_secret_d,
				OQS_KEM_frodokem_640_aes_length_shared_secret);

			return OQS_ERROR;
		}
		memcpy_s(aes_password, OQS_KEM_frodokem_640_aes_length_shared_secret, shared_secret_e, OQS_KEM_frodokem_640_aes_length_shared_secret);
	}
	else {
		rc = OQS_KEM_frodokem_640_aes_decaps(shared_secret_d, ciphertext, secret_key);
		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_KEM_frodokem_640_aes_decaps failed!\n");
			cleanup_stack(secret_key, OQS_KEM_frodokem_640_aes_length_secret_key,
				shared_secret_e, shared_secret_d,
				OQS_KEM_frodokem_640_aes_length_shared_secret);

			return OQS_ERROR;
		}
		memcpy_s(aes_password, OQS_KEM_frodokem_640_aes_length_shared_secret, shared_secret_d, OQS_KEM_frodokem_640_aes_length_shared_secret);
	}

	return OQS_SUCCESS; // success!

}
#endif
void cleanup_stack(BYTE* secret_key, size_t secret_key_len,
	BYTE* shared_secret_e, BYTE* shared_secret_d,
	size_t shared_secret_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
	OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}

BOOL oqs_initialize(int argc, WCHAR** argv)
{
#ifndef OQS_ENABLE_KEM_frodokem_640_aes // if FrodoKEM-640-AES was not enabled at compile-time
	printf("[example_stack] OQS_KEM_frodokem_640_aes was not enabled at "
		"compile-time.\n");
	return FALSE;
#else

	// setting crypt flag
	if (!wcscmp(argv[1], L"-E")) bFileCryptFlag = TRUE;
	else if (!wcscmp(argv[1], L"-D")) bFileCryptFlag = FALSE;
	else
	{
		print_usage(argv[0]);
		return FALSE;
	}

	// setting key
	if (argc == 5)
	{
		if (wcscmp(argv[2], L"-K"))
		{
			print_usage(argv[0]);
			return FALSE;
		}

		HANDLE hReadFile = CreateFile(argv[3],                // file to read
			GENERIC_READ,			// open for reading
			FILE_SHARE_READ,		// share for reading
			NULL,					// default security
			OPEN_EXISTING,			// existing file only
			FILE_ATTRIBUTE_NORMAL,	// normal file
			NULL);

		if (hReadFile == INVALID_HANDLE_VALUE)
		{
			wprintf(L"Key file open failed\n");
			return FALSE;
		}


		DWORD dwBytesRead;
		DWORD keySize = OQS_KEM_frodokem_640_aes_length_public_key;
		if (!bFileCryptFlag)
			keySize = OQS_KEM_frodokem_640_aes_length_secret_key;
		if (!ReadFile(hReadFile, TmpReadBuffer, keySize + 1, &dwBytesRead, NULL)) {
			wprintf(L"Key file read failed\n");
			CloseHandle(hReadFile);
			return FALSE;
		}
		if (dwBytesRead != keySize)
		{
			wprintf(L"Invalid key file\n");
			CloseHandle(hReadFile);
			return FALSE;
		}
		if (bFileCryptFlag) {
			memcpy_s(public_key, OQS_KEM_frodokem_640_aes_length_public_key, TmpReadBuffer, keySize);
		}
		else {
			memcpy_s(secret_key, OQS_KEM_frodokem_640_aes_length_secret_key, TmpReadBuffer, keySize);
		}
	}
	else if (argc == 3)
	{
		if (!bFileCryptFlag)
		{
			wprintf(L"Please select private key file\n");
			return FALSE;
		}
		OQS_STATUS rc = OQS_KEM_frodokem_640_aes_keypair(public_key, secret_key);
		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_KEM_frodokem_640_aes_keypair failed!\n");
			cleanup_stack(secret_key, OQS_KEM_frodokem_640_aes_length_secret_key,
				shared_secret_e, shared_secret_d,
				OQS_KEM_frodokem_640_aes_length_shared_secret);

			return FALSE;
		}
	}

	return TRUE;
#endif
}