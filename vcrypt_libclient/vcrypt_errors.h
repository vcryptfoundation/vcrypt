/*
 * vcrypt_errors.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef VCRYPT_ERRORS_H_
#define VCRYPT_ERRORS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "error_enum.h"
const char *vcrypt_get_error(int error);

#define ERR_UNKNOWN(x) (x)

#ifdef __cplusplus
}
#endif

#endif /* VCRYPT_ERRORS_H_ */
