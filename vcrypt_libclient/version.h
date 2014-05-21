/*
 * version.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef VERSION_H_
#define VERSION_H_

/*
 * protocol version will be checked upon connect, if client has smaller version, the connection will not be allowed
 * this will be sent to server as uint32_t
 */
#define VCRYPT_PROTOCOL_VERSION 12

#endif /* VERSION_H_ */
