#include <errno.h>
#include <fcntl.h>
#include <gmp.h>
#include <stdint.h>
#include <unistd.h>

struct DH_ctx {
  mpz_t p;  // p
  mpz_t g;  // g
};

int gen_random_bytes(uint8_t *in_buf, int size);
void generate_p(mpz_t prime);   // generate big prime
void generate_pri_key(mpz_t a); // generate private key P
int check_prime(mpz_t prime);   // check prime