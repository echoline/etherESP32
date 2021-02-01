#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"

char *log_etherESP32;

int
vprintf_etherESP32(const char * format, va_list arg){
	int l = strlen(log_etherESP32);
	log_etherESP32 = realloc(log_etherESP32, l + 0x400);
	return vsnprintf(&log_etherESP32[l], 0x3FF, format, arg);
	l = strlen(log_etherESP32)+1;
	if (l >= 0x400) {
		memmove(log_etherESP32, &log_etherESP32[l - 0x3FF], 0x400);
	}
}

