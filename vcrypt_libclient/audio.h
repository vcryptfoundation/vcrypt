/*
 * audio.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef AUDIO_H_
#define AUDIO_H_

#include "resampler/speex_resampler.h"
#include "packets.h"

#define VCRYPT_AUDIO_CHANNELS 1
#define VCRYPT_AUDIO_FRAME_US 60000 // must be multiple of 2.5ms=2500us. range 2500-60000
#define VCRYPT_AUDIO_OPUS_SAMPLERATE 16000
#define VCRYPT_OPUS_APPLICATION OPUS_APPLICATION_VOIP

#if VCRYPT_AUDIO_FRAME_US % 2500
#error Opus frame duration must be multiple of 2500us
#endif

typedef struct VAUDIO_CTX {
	OpusEncoder *encoder;
	OpusDecoder *decoder;
	SpeexResamplerState *resampler_enc;
	SpeexResamplerState *resampler_dec;
	int sample_rate_in;
	int sample_rate_out;
	/* the number of frames that opus codec will use */
	int packet_frames_opus;
	/* the client will have to send ONLY this number of frames */
	int packet_frames_rec;
	/* the client will have to allocate this number of frames for receiving audio */
	int packet_frames_play;
} VAUDIO_CTX;

void audio_ctx_zero(VAUDIO_CTX *actx);
void audio_ctx_close(VAUDIO_CTX *actx);
int audio_ctx_init(VAUDIO_CTX *actx, int sample_rate_rec, int sample_rate_play);
int audio_encode(VAUDIO_CTX *actx, const int16_t *in_buff, int in_frames,
		unsigned char *out_buff, int out_size);
int audio_decode(VAUDIO_CTX *actx, const unsigned char *encoded,
		int encoded_bytes, int16_t *out_buff, int out_frames, int decode_fec);

#endif /* AUDIO_H_ */
