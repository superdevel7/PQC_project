#include <windows.h>
#include <stdio.h>
#include "util.h"

void print_progress_bar(double per) {
	int pos = PROGRESS_BAR_WIDTH * per;
	wprintf(L"[");
	for (int i = 0; i < PROGRESS_BAR_WIDTH; i++) {
		if (i < pos) wprintf(L"=");
		else if (i == pos) wprintf(L">");
		else wprintf(L" ");
	}
	wprintf(L"] %.2lf %%\r", 100 * per);
	fflush(stdout);
}

void print_usage(WCHAR* argv0) {
	wprintf(L"Usage: %s <-E|-D> [<-K> <keyfilename>] <crypt file path>\n", argv0);
}