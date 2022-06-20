#include "DH.h"
#include <gmp.h>

/**
 * @brief generate a real random number by /dev/random
 *
 * @param in_buf
 * @param size
 * @param fill
 * @return int
 */
int gen_random_bytes(uint8_t *in_buf, int size) {
  int fd = open("/dev/random", O_RDONLY);
  if (fd < 0) {
    perror("[!] Failed to open /dev/random");
    exit(-1);
  }
again:
  memset(in_buf, 0, size);
  read(fd, in_buf, size);
  if (in_buf[size - 1] == 0x00 // full fill all the bytes
    //   || in_buf[size - 1] == 0xff
             )  // too big, can't find prime probably
    goto again; 
  return 0;
}

/**
 * @brief convert random bytes to mpz_t struct
 *
 * @param mpz : dst mpz
 * @param in_buf : random bytes
 * @param size : size of random bytes
 */
void convert_mpz(mpz_t p, uint64_t *nums, int size) {
  mpz_t step;
  mpz_t a[size];

  mpz_init(step);
  mpz_init_set_str(step, "0x10000000000000000", 0);

  for (int i = 0; i < size; i++) {
    mpz_init(a[i]);
    mpz_set_ui(a[i], nums[i]);
  }

  mpz_clear(p); 
  for (int i = size - 1; i >= 0; i--) { // prime = (a*step + b)*step... 
    mpz_add(p, p, a[i]);
    if (i == 0)
      break;
    mpz_mul(p, p, step);
  }
}

/**
 * @brief check prime
 *
 * @param prime
 * @return int
 *  2: definitely prime,
 *  1: maybe prime,
 *  0: not prime
 */
int check_prime(mpz_t prime) { return mpz_probab_prime_p(prime, 50); }

/**
 * @brief generate p, and (make sure) it's a prime
 *      
 * @param prime 
 */
void generate_p(mpz_t prime) {
  mpz_t a[4];
  mpz_t step;
  uint64_t nums[4];

  mpz_init(step);
  gen_random_bytes((uint8_t *)nums, 0x20);
  convert_mpz(prime, nums, 4);

  do { // get a random prime
    mpz_nextprime(prime, prime);
  } while (!check_prime(prime));

  gmp_printf("[+] prime = %Zd\n\n", prime);
}
