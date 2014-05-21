/*
 * common.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef __ANDROID__
#include <android/log.h>
#endif

#include "common.h"
#include <string.h>

//#define DB_LOG (D_PACKET | D_FUNC | D_CALLBACK |  D_ENC)
#define DB_LOG (D_CALLBACK |  D_ENC )

void dolog(int type, const char *format, ...)
{
	if (!type || (type && (type & DB_LOG))) {
		va_list ap;
		va_start(ap, format);

#ifdef __ANDROID__
		__android_log_vprint(ANDROID_LOG_WARN, "vcrypt_lib", format, ap);
#else
		vfprintf(stderr, format, ap);
		fflush(stderr);
#endif
		va_end(ap);
	}
}

uint64_t time_get_ms()
{
	struct timeval time;
	gettimeofday(&time, NULL );
	return time.tv_sec * 1E3 + time.tv_usec / 1E3;
}

uint64_t time_passed_ms(uint64_t previous)
{
	return time_get_ms() - previous;
}

void free_null(void **ptr)
{
	if (*ptr != NULL ) {
		free(*ptr);
		*ptr = NULL;
	}
}

int fletcher64_to_str(char checksum[FLETCHER_SIZE_STR], uint64_t *checksum_src)
{
	snprintf(checksum, FLETCHER_SIZE_STR,
			"%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
			*((uint8_t*) checksum_src + 0) & 0xFF, //
			*((uint8_t*) checksum_src + 1) & 0xFF, //
			*((uint8_t*) checksum_src + 2) & 0xFF, //
			*((uint8_t*) checksum_src + 3) & 0xFF, //
			*((uint8_t*) checksum_src + 4) & 0xFF, //
			*((uint8_t*) checksum_src + 5) & 0xFF, //
			*((uint8_t*) checksum_src + 6) & 0xFF, //
			*((uint8_t*) checksum_src + 7) & 0xFF);

	return 0;
}

uint64_t fletcher64(const void* data, int count)
{
	uint64_t sum1 = 0;
	uint64_t sum2 = 0;
	int i, j;

	uint32_t uint32_max = 0xFFFFFFFF;
	uint32_t tmp;

	for (i = 0; i < count;) {
		tmp = 0;
		for (j = 0; i < count && j < 4; i++, j++) {
			tmp |= ((uint8_t*) data)[i] << j * 8;
		}

		sum1 = (sum1 + tmp) % uint32_max;
		sum2 = (sum2 + sum1) % uint32_max;
	}

	return (sum2 << 32) | sum1;
}

int min_int(int a, int b)
{
	return a > b ? b : a;
}

/* this will null terminate the resulting string */
char* strncpy_ex(char *dst, const char *src, size_t n)
{
	char *ret = strncpy(dst, src, n);

	if (ret && n > 0) {
		dst[n - 1] = 0; // null terminate the resulting string
	}

	return ret;
}
