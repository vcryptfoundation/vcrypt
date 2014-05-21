/*
 * common.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef COMMON_H_
#define COMMON_H_

#define FLETCHER_SIZE_STR 24

#ifdef __cplusplus
extern "C" {
#endif

#define D_PACKET   0x80
#define D_FUNC     0x40
#define D_CALLBACK 0x20
#define D_ENC     0x10

#define MAX(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

void dolog(int type, const char *format, ...) __attribute__ ((format (printf, 2, 3)));
uint64_t time_get_ms();
uint64_t time_passed_ms(uint64_t previous);
void free_null(void **ptr);
uint64_t fletcher64(const void* data, int count);
int fletcher64_to_str(char checksum[FLETCHER_SIZE_STR], uint64_t *cs);
int min_int(int a, int b);
char* strncpy_ex(char *dst, const char *src, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H_ */
