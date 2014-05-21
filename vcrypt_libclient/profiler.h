/*
 * profiler.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef PROFILER_H_
#define PROFILER_H_

/*
#define PROFILER_START \
	static uint64_t last_dbg;\
	static uint64_t total_ms;\
	static uint32_t total_calls;\
	uint64_t start_ms = time_get_ms();

#define PROFILER_END(time)\
{\
	total_calls++;\
	total_ms += time_passed_ms(start_ms);\
	if (time_passed_ms(last_dbg) > time) {\
		fprintf(stderr, " -------- AVG call time for %s: %f\n", __func__,\
				(float) total_ms / (float) total_calls);\
		fflush(stderr);\
		last_dbg = time_get_ms();\
		total_ms = 0;\
		total_calls = 0;\
	}\
}
*/

#endif /* PROFILER_H_ */
