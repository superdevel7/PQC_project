#pragma once
#include <oqs\oqs.h>
#include "AES.h"

#ifdef OQS_ENABLE_KEM_frodokem_640_aes

OQS_STATUS get_aes_password();

#endif

BOOL oqs_initialize(int argc, WCHAR** argv);

/* Cleaning up memory etc */
void cleanup_stack(BYTE* secret_key, size_t secret_key_len,
	BYTE* shared_secret_e, BYTE* shared_secret_d,
	size_t shared_secret_len);

