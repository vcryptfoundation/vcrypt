/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include <stdlib.h>
#include <assert.h>
#include <opus/opus.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <opus/opus.h>

#include "audio.h"
#include "common.h"
#include "vcrypt_errors.h"

void audio_ctx_zero(VAUDIO_CTX *actx)
{
	memset(actx, 0, sizeof *actx);
}

void audio_ctx_close(VAUDIO_CTX *actx)
{
	if (actx->encoder)
		opus_encoder_destroy(actx->encoder);
	if (actx->decoder)
		opus_decoder_destroy(actx->decoder);

	if (actx->resampler_enc)
		vcrypt_resampler_destroy(actx->resampler_enc);
	if (actx->resampler_dec)
		vcrypt_resampler_destroy(actx->resampler_dec);
}

/* takes supported sample rates for rec and play
 * this will auto close audio context if there is error */
int audio_ctx_init(VAUDIO_CTX *actx, int sample_rate_rec, int sample_rate_play)
{
	int err = 0;

	// check recorder resampling consistency
	double opus_frames = VCRYPT_AUDIO_OPUS_SAMPLERATE
			* (double) VCRYPT_AUDIO_FRAME_US * 0.000001;
	assert(opus_frames == floor(opus_frames));
	actx->packet_frames_opus = (int) opus_frames;

	double non_resampled_frames = opus_frames
			* (double) sample_rate_rec/ VCRYPT_AUDIO_OPUS_SAMPLERATE;

	// check if the number of frames is integer
	if (non_resampled_frames != floor(non_resampled_frames)) {
		err = -ERR_UNSUPPORTED_REC_SAMPLERATE;
		goto toerr;
	}

	actx->packet_frames_rec = (int) non_resampled_frames;

	// check players resampling consistency
	non_resampled_frames = opus_frames
			* (double) sample_rate_play/ VCRYPT_AUDIO_OPUS_SAMPLERATE;

	// check if the number of frames is integer
	if (non_resampled_frames != floor(non_resampled_frames)) {
		err = -ERR_UNSUPPORTED_PLAY_SAMPLERATE;
		goto toerr;
	}

	actx->packet_frames_play = (int) non_resampled_frames;

	dolog(0, "packet durations, opus %d, rec: %d, play: %d\n",
			actx->packet_frames_opus, actx->packet_frames_rec,
			actx->packet_frames_play);

	actx->encoder = opus_encoder_create(VCRYPT_AUDIO_OPUS_SAMPLERATE,
			VCRYPT_AUDIO_CHANNELS, VCRYPT_OPUS_APPLICATION, &err);
	if (err != OPUS_OK) {
		actx->encoder = NULL;
		err = -ERR_CODEC_REC_SETUP;
		goto toerr;
	}

	opus_encoder_ctl(actx->encoder, OPUS_SET_DTX(1));
	opus_encoder_ctl(actx->encoder, OPUS_SET_PACKET_LOSS_PERC(5));

	err = 0;
	actx->decoder = opus_decoder_create(VCRYPT_AUDIO_OPUS_SAMPLERATE,
			VCRYPT_AUDIO_CHANNELS, &err);
	if (err != OPUS_OK) {
		actx->decoder = NULL;
		err = -ERR_CODEC_PLAY_SETUP;
		goto toerr;
	}

	// set resamplers
	int resampler_err = 0;

	if (sample_rate_rec != VCRYPT_AUDIO_OPUS_SAMPLERATE) {
		actx->resampler_enc = vcrypt_resampler_init(VCRYPT_AUDIO_CHANNELS,
				sample_rate_rec, VCRYPT_AUDIO_OPUS_SAMPLERATE, 1,
				&resampler_err);
		if (resampler_err) {
			dolog(0, "unable to open resampler in: %d %s\n", resampler_err,
					vcrypt_resampler_strerror(resampler_err));
			err = -ERR_RESAMPLER_REC_SETUP;
			goto toerr;
		}
	}

	if (sample_rate_play != VCRYPT_AUDIO_OPUS_SAMPLERATE) {
		actx->resampler_dec = vcrypt_resampler_init(VCRYPT_AUDIO_CHANNELS,
				VCRYPT_AUDIO_OPUS_SAMPLERATE, sample_rate_play, 1,
				&resampler_err);
		if (resampler_err) {
			dolog(0, "unable to open resampler out: %d %s\n", resampler_err,
					vcrypt_resampler_strerror(resampler_err));
			err = -ERR_RESAMPLER_PLAY_SETUP;
			goto toerr;
		}
	}

	actx->sample_rate_in = sample_rate_rec;
	actx->sample_rate_out = sample_rate_play;

	return 0;

	toerr: //
	audio_ctx_close(actx);

	return err;
}

/* user sould send ONLY actx->packet_frames_rec frames per channel interleaved
 * returns the encoded bytes count */
int audio_encode(VAUDIO_CTX *actx, const int16_t *in_buff, int in_frames,
		unsigned char *out_buff, int out_size)
{
	int16_t resampled[actx->packet_frames_opus * VCRYPT_AUDIO_CHANNELS];

	assert(in_frames == actx->packet_frames_rec);

	const int16_t *source_buff = in_buff;
	int source_frames = in_frames;

	if (actx->resampler_enc) {
		unsigned int x1 = in_frames, x2 = actx->packet_frames_opus;

		if (vcrypt_resampler_process_interleaved_int(actx->resampler_enc,
				in_buff, &x1, resampled, &x2) != RESAMPLER_ERR_SUCCESS) {
			dolog(0, "RESAMPLING error\n");
			return -2;
		}

		assert(x1 == in_frames && x2 == actx->packet_frames_opus);

		source_buff = resampled;
		source_frames = actx->packet_frames_opus;
	}

	/* in_size is number of samples per channel */
	int enc_size = opus_encode(actx->encoder, source_buff, source_frames,
			out_buff, out_size);
	if (enc_size <= 0) {
		dolog(0, "opus encoding error %d %s\n", enc_size,
				opus_strerror(enc_size));
		return -1;
	}

	return enc_size;
}

/* this will always return at least out_frames frames per channel interleaved
 * returns the number of frames */
int audio_decode(VAUDIO_CTX *actx, const unsigned char *encoded,
		int encoded_bytes, int16_t *out_buff, int out_frames, int decode_fec)
{
	int dec_size;
	unsigned int x1, x2;

	if (actx->resampler_dec) {
		int16_t not_resampled[actx->packet_frames_opus * VCRYPT_AUDIO_CHANNELS];

		dec_size = opus_decode(actx->decoder, encoded, encoded_bytes,
				not_resampled, actx->packet_frames_opus, 0);

		if (dec_size <= 0) {
			dolog(0, "opus decoding error1 %d %s\n", dec_size,
					opus_strerror(dec_size));
			return -1;
		}

		x1 = dec_size;
		x2 = out_frames;

		x1 = dec_size;
		if (vcrypt_resampler_process_interleaved_int(actx->resampler_dec,
				not_resampled, &x1, out_buff, &x2) != RESAMPLER_ERR_SUCCESS) {
			dolog(0, "RESAMPLING error\n");
			return -2;
		}

		if (x1 != dec_size || x2 != actx->packet_frames_play) {
			dolog(0, "RESAMPLING error, buffer to small\n");
			return -2;
		}

	} else {
		dec_size = opus_decode(actx->decoder, encoded, encoded_bytes, out_buff,
				out_frames, decode_fec);
	}

	if (dec_size != actx->packet_frames_opus) {
		dolog(0, "got only decoded frames: %d\n", dec_size);
	}

	if (dec_size <= 0) {
		dolog(0, "opus decoding error2 %d %s\n", dec_size,
				opus_strerror(dec_size));
		return -1;
	}

	return actx->resampler_dec ? x2 : dec_size;
}
