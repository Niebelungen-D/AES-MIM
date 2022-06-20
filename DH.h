#include <errno.h>
#include <fcntl.h>
#include <gmp.h>
#include <stdint.h>
#include <unistd.h>

struct DH_ctx {
  mpz_t p;          // p
  mpz_t g;          // g
  mpz_t pri_key;    // a
  mpz_t pub_key;    // g^a mod p
  mpz_t s;          // s = g^(ab) mod p
};

int gen_random_bytes(uint8_t *in_buf, int size);
void generate_p(mpz_t prime);   // generate big prime
void generate_pri_key(mpz_t a); // generate private key 
int check_prime(mpz_t prime);   // check prime