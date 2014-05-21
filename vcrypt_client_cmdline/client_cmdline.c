/*
 * test.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#include "client.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#define ALSA_PCM_NEW_HW_PARAMS_API
#include <alsa/asoundlib.h>
char *alsa_dev_rec = NULL;
char *alsa_dev_play = NULL;
const char *username = NULL;
int samplerate_rec = 0;
int samplerate_play = 0;

#include "dummycallbacks.h"

VCRYPT_CTX *v;
static volatile int signal_shutdown = 0;
volatile int sending_triggered = 0;
volatile int sending_err = 0;
volatile int connect_triggered = 0;
pthread_t audio_thread_handle;
snd_pcm_t *alsa_rec;
snd_pcm_t *alsa_play;
volatile int audio_sending = 0;

FILE *f_audiorec = NULL;

void signal_handler(int s)
{
	if (s != 2) {
		printf("got signal %d, dont know how to process it!\n", s);
		exit(2);
	}

	if (signal_shutdown == 0) {
		fprintf(stderr,
				"\nGot SIGINT, exiting cleanly (send SIGING one more time to force shutdown)\n");
		signal_shutdown = 1;
	} else {
		fprintf(stderr, "\nGot SIGINT twice, forcing shutdown)\n");
		exit(1);
	}
}

int install_signal_handlers()
{
	struct sigaction sig_int_handler;

	sig_int_handler.sa_handler = signal_handler;
	sigemptyset(&sig_int_handler.sa_mask);
	sig_int_handler.sa_flags = 0;

	sigaction(SIGINT, &sig_int_handler, NULL );

	return 0;
}

void alsa_close(snd_pcm_t* handle)
{
	if (handle == NULL )
		return;

	snd_pcm_drop(handle);
	snd_pcm_unlink(handle);
	snd_pcm_hw_free(handle);
	snd_pcm_close(handle);
	snd_config_update_free_global();
}

snd_pcm_t* alsa_setup_rec(const char *dev, snd_pcm_stream_t stream,
		const int rec_sample_rate, const int need_frames)
{
	int rc = 0;
	snd_pcm_hw_params_t *params;
	unsigned int val = 0;
	int dir = 0;
	snd_pcm_uframes_t frames = 0;
	snd_pcm_t *handle;

	/* Open PCM device for recording (capture). */
	rc = snd_pcm_open(&handle, dev, stream, 0);
	snd_config_update_free_global();
	if (rc < 0) {
		fprintf(stderr, "unable to open pcm device: %s\n", snd_strerror(rc));
		return NULL ;
	}

	/* Allocate a hardware parameters object. */
	snd_pcm_hw_params_alloca(&params);

	/* Fill it in with default values. */
	snd_pcm_hw_params_any(handle, params);

	/* Interleaved mode */
	snd_pcm_hw_params_set_access(handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);

	/* Signed 16-bit little-endian format */
	snd_pcm_hw_params_set_format(handle, params, SND_PCM_FORMAT_S16);

	if (snd_pcm_hw_params_set_channels(handle, params, VCRYPT_AUDIO_CHANNELS)) {
		fprintf(stderr, "unable to set channels\n");
		goto fex;
	}

	val = rec_sample_rate;
	snd_pcm_hw_params_set_rate_near(handle, params, &val, &dir);
	if (val != rec_sample_rate) {
		fprintf(stderr, "unable to set sample rate, got: %d\n", val);
		goto fex;
	}

	frames = need_frames;
	snd_pcm_hw_params_set_period_size_near(handle, params, &frames, &dir);

	if (frames != need_frames) {
		fprintf(stderr, "unable to satisfy wanted frames, wanted %d got %ld\n",
				need_frames, frames);
		goto fex;
	}

	if (frames != need_frames) {
		fprintf(stderr, "cant satisfy frames, need %d got %d\n", need_frames,
				(int) frames);
		goto fex;
	}

	fprintf(stderr, "will use %d frames per packet\n", need_frames);

	/* Write the parameters to the driver */
	rc = snd_pcm_hw_params(handle, params);
	if (rc < 0) {
		fprintf(stderr, "unable to set hw parameters: %s\n", snd_strerror(rc));
		goto fex;
	}

	return handle;

	fex: //
	alsa_close(handle);
	return NULL ;
}

int alsa_setup_play_buff(snd_pcm_t* alsa_play, int buff_frames)
{
	snd_pcm_sw_params_t* sw_params;
	snd_pcm_sw_params_alloca(&sw_params);
	snd_pcm_sw_params_current(alsa_play, sw_params);
	int parmres = snd_pcm_sw_params_set_start_threshold(alsa_play, sw_params,
			buff_frames);
	if (parmres) {
		fprintf(stderr, "alsa sw params setting error: %s\n",
				snd_strerror(parmres));
		return -1;
	}

	parmres = snd_pcm_sw_params(alsa_play, sw_params);
	if (parmres) {
		fprintf(stderr, "alsa sw params setting error2: %s\n",
				snd_strerror(parmres));
		return -1;
	}

	return 0;
}

void callback_server_disconnect(int error_id)
{
	connect_triggered = 0;
	unset_callback_debug(__func__);
	dolog(D_CALLBACK, "|--- Server connected/disconnected: (%d) %s\n", error_id,
			vcrypt_get_error(error_id));
}

void *audio_sending_thread(void *param)
{
	VCRYPT_CTX *ctx = param;
	int frames_to_read = ctx->call_ctx.audio_ctx.packet_frames_rec;
	int16_t buff_in[frames_to_read];
	memset(buff_in, 0, sizeof buff_in);

	while (audio_sending == 1 && signal_shutdown == 0) {
		int rc = snd_pcm_readi(alsa_rec, buff_in, frames_to_read);
		if (rc == -EPIPE) {
			/* EPIPE means overrun */
			fprintf(stderr, "RECORD overrun occurred\n");
			snd_pcm_prepare(alsa_rec);
			fprintf(stderr, "error from read: %s\n", snd_strerror(rc));
			continue;
		} else if (rc < 0) {
			fprintf(stderr, "error from read: %s\n", snd_strerror(rc));
			continue;
		} else if (rc != frames_to_read) {
			fprintf(stderr, "RECORD short read, read %d frames\n", rc);
			continue;
		}

		// send the audio
		vcrypt_queue_audio(ctx, (char*) buff_in,
				frames_to_read * VCRYPT_AUDIO_CHANNELS * sizeof(int16_t));
	}

	audio_ctx_close(&ctx->call_ctx.audio_ctx);
	alsa_close(alsa_rec);
	dolog(0, "audio thread ended\n");
	audio_sending = 0;
	return NULL ;
}

void callback_call_status_change(const char *username, int status, int reason)
{
	dolog(D_CALLBACK, "CALLBACK: Call status for %s changed to: %s / %s\n",
			username, vcrypt_get_error(status), vcrypt_get_error(reason));

	if (status == -ERR_CALL_HANGUP) {
		audio_sending = 2; // initiate end

		if (f_audiorec) {
			fclose(f_audiorec);
			f_audiorec = NULL;
		}

		alsa_close(alsa_play);
		alsa_play = NULL;
	}
}

int callback_start_audio_sending()
{
//	char fname[100];
//	sprintf(fname, "/tmp/vcrypt_%s", username);
//	f_audiorec = fopen(fname, "w");

	int ret = audio_ctx_init(&v->call_ctx.audio_ctx, samplerate_rec,
			samplerate_play);
	if (ret)
		return ret;

	alsa_rec = alsa_setup_rec(alsa_dev_rec, SND_PCM_STREAM_CAPTURE,
			samplerate_rec, v->call_ctx.audio_ctx.packet_frames_rec);
	if (!alsa_rec) {
		audio_ctx_close(&v->call_ctx.audio_ctx);
		return -ERR_UNKNOWN_AUDIO_PROBLEM;
	}

	alsa_play = alsa_setup_rec(alsa_dev_play, SND_PCM_STREAM_PLAYBACK,
			samplerate_play, v->call_ctx.audio_ctx.packet_frames_play);
	if (!alsa_play) {
		alsa_close(alsa_rec);
		audio_ctx_close(&v->call_ctx.audio_ctx);
		return -ERR_UNKNOWN_AUDIO_PROBLEM;
	}

	if (alsa_setup_play_buff(alsa_play,
			v->call_ctx.audio_ctx.packet_frames_play * 2)) {
		alsa_close(alsa_rec);
		alsa_close(alsa_play);
		audio_ctx_close(&v->call_ctx.audio_ctx);
		return -ERR_UNKNOWN_AUDIO_PROBLEM;
	}

	audio_sending = 1;
	pthread_create(&audio_thread_handle, NULL, audio_sending_thread, (void*) v);
	pthread_detach(audio_thread_handle);

	return 0;
}

void callback_audio(char *data, int data_size)
{
	if (audio_sending != 1)
		return;

//	if (f_audiorec)
//		fwrite(data, 1, data_size, f_audiorec);

	if (alsa_play) {
		int rc = snd_pcm_writei(alsa_play, data,
				data_size / VCRYPT_AUDIO_CHANNELS / sizeof(int16_t));

		if (rc < 0) {
			fprintf(stderr, "alsa play error: %s\n", snd_strerror(rc));

			if (rc == -EPIPE)
				snd_pcm_prepare(alsa_play);
		}
	}

	//dolog(0, "received audio %d bytes\n", data_size);
}

int main(int argc, char** argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char *keys = "./test_keys.der";

	if (argc < 7) {
		printf(
				"Usage: %s alsa_rec rec_samplerate alsa_play play_samplerate server username password <recipient>\n",
				argv[0]);
		exit(1);
	}

	alsa_dev_rec = argv[1];
	alsa_dev_play = argv[3];

	samplerate_rec = atoi(argv[2]);
	samplerate_play = atoi(argv[4]);

	const char *hostname = argv[5];
	username = argv[6];
	const char *password = argv[7];
	char recp[100];

	if (!samplerate_rec || !samplerate_play) {
		printf("bad samplerate(s): %d %d\n", samplerate_rec, samplerate_play);
		exit(1);
	}

	v = vcrypt_create(keys);
	assert(v);

	v->callback_server_disconnect = callback_server_disconnect;
	v->callback_start_audio_sending = callback_start_audio_sending;
	v->callback_call_status_change = callback_call_status_change;
	v->callback_audio = callback_audio;

	install_signal_handlers();

	char checksum[FLETCHER_SIZE_STR];
	int ret = vcrypt_load_keys(v, keys, checksum);
	if (ret) {
		printf("bad keys, generating....\n");
		vcrypt_generate_keys(v, keys);
		sleep(5);
		printf("done\n");
		exit(0);
	}

	printf("keys: %s\n", checksum);
	printf("connecting to server %s\n", hostname);

	vcrypt_connect_auth(v, hostname, username, password);

	int i;
	for (i = 0; i < 10 && !signal_shutdown && !connect_triggered; i++) {
		usleep(200000);
	}

	if (vcrypt_is_connected(v)) {
		if (argc >= 9) {
			strcpy(recp, argv[8]);
			printf("got recipient: %s\n", recp);

			if (argc >= 10) {
				int msg;
				for (msg = 9; msg < argc; msg++) {
					int towait = atoi(argv[msg]);

					if (towait) {
						printf("Waiting %d seconds\n", towait);
						sleep(towait);
					} else {
						ret = vcrypt_message_send(v, recp, argv[msg]);
						printf("snt msg '%s', msg result: %s\n", argv[msg],
								vcrypt_get_error(ret));
					}
				}
			}
		}

		//vcrypt_password_change(v, "laptop2pass", "laptop2pass12", "laptop2pass12");

//		printf("Generating keys....\n");
//		vcrypt_generate_keys(v, keys, checksum);
//		vcrypt_generate_keys(v, keys, checksum);
	}

	char readbuff[1 << 20];

	printf("> ");
	while (1) {
		if (fgets(readbuff, sizeof(readbuff), stdin) == NULL )
			break;

		if (signal_shutdown || !vcrypt_is_connected(v))
			break;

		if (readbuff[0] != '\n') {

			char *newl = strchr(readbuff, '\n');
			if (newl)
				*newl = 0;

			if (strcmp(readbuff, "/q") == 0) {
				signal_shutdown = 1;
				printf("Quit...\n");
				break;
			}

			int ret = vcrypt_message_send(v, recp, readbuff);

			if (ret < 0) {
				printf("snt msg '%s', msg result: %s\n", readbuff,
						vcrypt_get_error(ret));
			}
		}

		printf("> ");
	}

//	int i;
//	for (i = 0; i < 100; i++) {
//		printf("doing step %d\n", i);
//
//		vcrypt_connect_auth(v, "localhost", 5566, "laptop2",
//				"laptop2pass");
//
//		usleep(i);
//
//		ret = vcrypt_close(v, 1);
//		if (ret) {
//			printf("vcrypt close error %s\n", vcrypt_get_error(ret));
//			break;
//		}
//	}

//	cleanup: //
	dolog(0, "Closing vcrypt\n");
	ret = vcrypt_close(v, 1);
	if (ret)
		printf("vcrypt close error %s\n", vcrypt_get_error(ret));

	vcrypt_destroy(v);

	return 0;
}
