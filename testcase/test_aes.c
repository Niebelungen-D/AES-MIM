#include "./aes.h"
#include <stdio.h>
// #include <random.h>

int main() {
    uint8_t i;
	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f};

	uint8_t in[] = {
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff,

		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff,};
    uint8_t out[0x20]; // 128

    
    uint8_t *w; // expanded key

    w = AES_init(key, sizeof(key));

	printf("Plaintext message:\n");
	for (i = 0; i < 8; i++) {
		printf("%02x %02x %02x %02x ", in[4*i+0], in[4*i+1], in[4*i+2], in[4*i+3]);
    }

    uint8_t msg[0x10];
    uint8_t mac[0x10];
    bzero(msg, sizeof(msg));
    AES_set_iv(NULL);
    AES_gcm_encrypt(in,0x20,out, w, msg, mac);
    
    printf("\n");

    printf("message:\n");
    for (i = 0; i < 4; i++) {
        printf("%02x %02x %02x %02x ", msg[4*i+0], msg[4*i+1], msg[4*i+2], msg[4*i+3]);
    }
    printf("\n");
    
    
    printf("mac message:\n");
    for (i = 0; i < 4; i++) {
        printf("%02x %02x %02x %02x ", mac[4*i+0], mac[4*i+1], mac[4*i+2], mac[4*i+3]);
    }
    printf("\n");
    
    printf("Ciphertext message:\n");
    for (i = 0; i < 8; i++) {
        printf("%02x %02x %02x %02x ", out[4*i+0], out[4*i+1], out[4*i+2], out[4*i+3]);
    }

    printf("\n");

    AES_gcm_decrypt(out,0x20,in, w);

    printf("Plaintext message (after dec):\n");
    for (i = 0; i < 8; i++) {
        printf("%02x %02x %02x %02x ", in[4*i+0], in[4*i+1], in[4*i+2], in[4*i+3]);
    }

    printf("\n");
    AES_free(w);
}