#pragma once

// For progress bar
#define PROGRESS_BAR_WIDTH		70
#define MAGIC_BYTES				"HYBRID ENC"
#define MAGIC_LENGTH			10

void print_progress_bar(double per);
void print_usage(wchar_t *argv0);