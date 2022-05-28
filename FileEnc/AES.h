#pragma once

#include <Windows.h>
#include <iostream>
#include <vector>
#include <array>

#define MAX_FILE_PATH_LENGTH	256
#define CHUNK_SIZE				65536

// salt set 8 length word
const BYTE AES_SALT[] = "SALTSALT";
#define SALT_LENGTH				8

NTSTATUS InitializeBCrypt(HANDLE hFile, LONGLONG& llFileSize, BYTE* pass, ULONG pass_len, BOOL bFileCryptFlag);
NTSTATUS crypt_iv_write(HANDLE hFile);
NTSTATUS buffer_crypt(BOOL isEnc, BYTE* buffer, ULONG buffer_length, BYTE* enc_buffer, ULONG& enc_length, ULONG ulCryptFlag);
void CloseEncryption();
NTSTATUS file_enrypt(WCHAR* filePath);
