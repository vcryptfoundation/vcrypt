/*
 * setup.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#define PROFILING 0

/* this is for speex resampler */
#define OUTSIDE_SPEEX
#define FLOATING_POINT
#define SPX_RESAMPLE_EXPORT
#define RANDOM_PREFIX vcrypt

#if WIN32

#define HAVE_WINDOWS_H 1
#define USE_POLL 0
#else

// for now, we assume we're on linux
#define HAVE_NETINET_IN_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_NETDB_H 1
#define HAVE_ARPA_INET_H 1

#endif

#endif /* CONFIG_H_ */
