// FileEnc.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <iostream>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <oqs\oqs.h>

#include "util.h"
#include "AES.h"

/* Cleaning up memory etc */
void cleanup_stack(BYTE* secret_key, size_t secret_key_len,
	BYTE* shared_secret_e, BYTE* shared_secret_d,
	size_t shared_secret_len);
#ifdef OQS_ENABLE_KEM_frodokem_640_aes
BYTE public_key[OQS_KEM_frodokem_640_aes_length_public_key];
BYTE secret_key[OQS_KEM_frodokem_640_aes_length_secret_key];
BYTE ciphertext[OQS_KEM_frodokem_640_aes_length_ciphertext];
BYTE shared_secret_e[OQS_KEM_frodokem_640_aes_length_shared_secret];
BYTE shared_secret_d[OQS_KEM_frodokem_640_aes_length_shared_secret];
BYTE aes_password[OQS_KEM_frodokem_640_aes_length_shared_secret];
BOOL bFileCryptFlag;
WCHAR szFilePath[MAX_FILE_PATH_LENGTH];
//BYTE TmpReadBuffer[OQS_KEM_frodokem_640_aes_length_secret_key + 10];
BYTE TmpReadBuffer[65536];

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

	// setting file path
	wcscpy_s(szFilePath, argv[argc - 1]);
	return TRUE;
#endif
}

NTSTATUS crypt_file() {
	NTSTATUS status = NTE_FAIL;
	DWORD dwBytesRead;
	LARGE_INTEGER lFileSize;
	LONGLONG llFileSize, llCurrentFileSize = 0;
	HANDLE hReadFile = CreateFile(szFilePath,                // file to read
		GENERIC_READ,			// open for reading
		FILE_SHARE_READ,		// share for reading
		NULL,					// default security
		OPEN_EXISTING,			// existing file only
		FILE_ATTRIBUTE_NORMAL,	// normal file
		NULL);
	if (hReadFile == INVALID_HANDLE_VALUE)
	{
		wprintf(L"Crypt file open failed\n");
		return status;
	}

	// Get file size
	// Use Large Integer because the file size is up to 10G
	GetFileSizeEx(hReadFile, &lFileSize);
	memcpy_s(&llFileSize, sizeof(LONGLONG), &lFileSize, sizeof(LARGE_INTEGER));

	WCHAR filePathToWrite[MAX_FILE_PATH_LENGTH] = {};
	if (bFileCryptFlag) {
		swprintf_s(filePathToWrite, L"%s.enc", szFilePath);
	}
	else {
		swprintf_s(filePathToWrite, L"%s.dec", szFilePath);
	}

	HANDLE hWriteFile = CreateFile(filePathToWrite,                // file to write
		GENERIC_WRITE,			// open for writing
		FILE_SHARE_WRITE,		// share for writing
		NULL,					// default security
		CREATE_ALWAYS,			// create always
		FILE_ATTRIBUTE_NORMAL,	// normal file
		NULL);

	if (hWriteFile == INVALID_HANDLE_VALUE)
	{
		wprintf(L"Write file open failed\n");
		CloseHandle(hReadFile);
		return status;
	}

	if (!bFileCryptFlag) {
		TmpReadBuffer[MAGIC_LENGTH] = 0;
		if (!ReadFile(hReadFile, TmpReadBuffer, MAGIC_LENGTH, &dwBytesRead, NULL) ||
			dwBytesRead != MAGIC_LENGTH ||
			strcmp((char*)TmpReadBuffer, MAGIC_BYTES)
			)
		{
			wprintf(L"Magic word error\n");
			CloseHandle(hReadFile);
			return status;
		}
		llFileSize -= MAGIC_LENGTH;

		if (!ReadFile(hReadFile, ciphertext, OQS_KEM_frodokem_640_aes_length_ciphertext, &dwBytesRead, NULL) ||
			dwBytesRead != OQS_KEM_frodokem_640_aes_length_ciphertext
			)
		{
			wprintf(L"Cipher text read error\n");
			CloseHandle(hReadFile);
			return status;
		}
		llFileSize -= OQS_KEM_frodokem_640_aes_length_ciphertext;
	}

	// Get aes password using OQS encapsulation/decapsulation
	get_aes_password();

	status = InitializeBCrypt(hReadFile, llFileSize, aes_password, OQS_KEM_frodokem_640_aes_length_shared_secret, bFileCryptFlag);
	if (status != ERROR_SUCCESS) {
		wprintf(L"Initialize crypt failed\n");
		CloseHandle(hReadFile);
		CloseHandle(hWriteFile);
		return status;
	}

	if (llFileSize <= 0) {
		wprintf(L"File size error\n");
		status = ERROR_FILE_INVALID;
	}

	BYTE EncBuffer[CHUNK_SIZE << 1] = {};
	ULONG EncBufferLen = 0;
	ULONG WritedBufferLen = 0;
	
	if (bFileCryptFlag && status == ERROR_SUCCESS) {
		if (!WriteFile(hWriteFile, MAGIC_BYTES, MAGIC_LENGTH, &WritedBufferLen, NULL)) {
			status = ERROR_WRITE_FAULT;
		}

		if (!WriteFile(hWriteFile, ciphertext, OQS_KEM_frodokem_640_aes_length_ciphertext, &WritedBufferLen, NULL)) {
			status = ERROR_WRITE_FAULT;
		}

		status = crypt_iv_write(hWriteFile);
	}

	if (status == ERROR_SUCCESS)
	{
		if (bFileCryptFlag)
			wprintf(L"Encrypting %s...\n", szFilePath);
		else
			wprintf(L"Decrypting %s...\n", szFilePath);
		while (ReadFile(hReadFile, TmpReadBuffer, CHUNK_SIZE, &dwBytesRead, NULL) == TRUE) {
			if (dwBytesRead <= 0) {
				break;
			}
			if (!(llCurrentFileSize & 0xFFFFF)) {
				print_progress_bar(1. * llCurrentFileSize / llFileSize);
			}
			llCurrentFileSize += dwBytesRead;

			// setting crypt flag
			ULONG ulCryptFlag = 0;
			if (llCurrentFileSize >= llFileSize)
				ulCryptFlag = BCRYPT_BLOCK_PADDING;

			status = buffer_crypt(bFileCryptFlag, TmpReadBuffer, dwBytesRead, EncBuffer, EncBufferLen, ulCryptFlag);
			if (status != ERROR_SUCCESS) {
				wprintf(L"buffer encrypt failed ERROR CODE: %08x\n", status);
				break;
			}

			if (!WriteFile(hWriteFile, EncBuffer, EncBufferLen, &WritedBufferLen, NULL)) {
				status = ERROR_WRITE_FAULT;
				break;
			}
		}
	}
	if (status == ERROR_SUCCESS) {
		print_progress_bar(1.);
		wprintf(L"\nDone!");
	}
	else {
		wprintf(L"\nFailed!");
	}

	wprintf(L"\n");

	CloseEncryption();
	CloseHandle(hReadFile);
	CloseHandle(hWriteFile);
	return status;
}

void make_key_file(int argc)
{
	if (argc == 3)
	{
		DWORD dwBytesWrite;
		HANDLE hFile = CreateFile(L"secret.bin",                // file to write
			GENERIC_WRITE,			// open for writing
			FILE_SHARE_WRITE,		// share for writing
			NULL,					// default security
			CREATE_ALWAYS,			// create always
			FILE_ATTRIBUTE_NORMAL,	// normal file
			NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			wprintf(L"Secret key file write failed\n");
		}
		else {
			WriteFile(hFile, secret_key, OQS_KEM_frodokem_640_aes_length_secret_key, &dwBytesWrite, NULL);
			CloseHandle(hFile);
		}
		
		hFile = CreateFile(L"public.bin",                // file to write
			GENERIC_WRITE,			// open for writing
			FILE_SHARE_WRITE,		// share for writing
			NULL,					// default security
			CREATE_ALWAYS,			// create always
			FILE_ATTRIBUTE_NORMAL,	// normal file
			NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			wprintf(L"Public key file write failed\n");
		}
		else {
			WriteFile(hFile, public_key, OQS_KEM_frodokem_640_aes_length_public_key, &dwBytesWrite, NULL);
			CloseHandle(hFile);
		}
	}
}

int wmain(int argc, WCHAR *argv[])
{
	if (argc != 3 && argc != 5) {
		print_usage(argv[0]);
		return 0;
	}

	if (!oqs_initialize(argc, argv))
		return 0;

	if (crypt_file() == ERROR_SUCCESS) {
		make_key_file(argc);
	}

	return 0;
}