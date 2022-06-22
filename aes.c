#include "aes.h"
#include "gmult.h"
#include <stdint.h>
#include <stdlib.h>

// /**
//  * @brief gariola multiplication
//  * 
//  * @param a 
//  * @param b 
//  * @return uint8_t 
//  */
// uint8_t gmul(uint8_t a, uint8_t b) {
//     uint8_t p = 0;
//     for (int i = 0; i < 8; i++) {
//         if (b & 1) {
//             p ^= a;
//         }
//         uint8_t hi = a & 0x80;
//         a <<= 1;
//         if (hi) {
//             a ^= 0x1b;
//         }
//         b >>= 1;
//     }
//     return p;
// }

uint8_t gadd(uint8_t a, uint8_t b) {
  return a ^ b;
}

uint8_t gsub(uint8_t a, uint8_t b) {
	return a ^ b;
}



/**
 * @brief byte substitution on a word using S-box
 *
 * @param w
 */
void sub_word(uint8_t *w) {
  uint8_t i;

  for (i = 0; i < 4; i++) {
    w[i] = s_box[w[i]];
  }
}


/**
 * @brief Rot a word
 *
 * @param w
 */
void rot_word(uint8_t *w) {
  uint8_t temp = w[0];
  w[0] = w[1];
  w[1] = w[2];
  w[2] = w[3];
  w[3] = temp;
}


/**
 * @brief AES-256 Key Expansion
 *
 * @param key original key
 * @param w expanded key
 */
void key_expansion(uint8_t *key, uint8_t *w) {
  uint8_t tmp[4];
  uint8_t i;
  uint8_t len = Nb * (Nr + 1);

  for (i = 0; i < Nk; i++) {
    w[4 * i + 0] = key[4 * i + 0];
    w[4 * i + 1] = key[4 * i + 1];
    w[4 * i + 2] = key[4 * i + 2];
    w[4 * i + 3] = key[4 * i + 3];
  }

  for (i = Nk; i < len; i++) {
    tmp[0] = w[4 * (i - 1) + 0];
    tmp[1] = w[4 * (i - 1) + 1];
    tmp[2] = w[4 * (i - 1) + 2];
    tmp[3] = w[4 * (i - 1) + 3];

    if (i % Nk == 0) {
      rot_word(tmp);
      sub_word(tmp);
      tmp[0] = tmp[0] ^ Rcon[i / Nk];
      //   coef_add(tmp, Rcon[i / Nk], tmp);

    } else if (Nk > 6 && i % Nk == 4) {
      sub_word(tmp);
    }

    w[4 * i + 0] = w[4 * (i - Nk) + 0] ^ tmp[0];
    w[4 * i + 1] = w[4 * (i - Nk) + 1] ^ tmp[1];
    w[4 * i + 2] = w[4 * (i - Nk) + 2] ^ tmp[2];
    w[4 * i + 3] = w[4 * (i - Nk) + 3] ^ tmp[3];
  }
}


/**
 * @brief add round key to state, need round number to know which key to use
 *
 * @param state
 * @param w
 * @param r
 */
void add_round_key(uint8_t *state, uint8_t *w, uint8_t r) {
  uint8_t i;

  // ? not sure if this is correct, if not debug it
  // * w and s are in a different order,
  // * that's why we use the rows of w plus the columns of s
  for (i = 0; i < Nb; i++) {
    state[Nb * 0 + i] ^= w[4 * Nb * r + 4 * i + 0];
    state[Nb * 1 + i] ^= w[4 * Nb * r + 4 * i + 1];
    state[Nb * 2 + i] ^= w[4 * Nb * r + 4 * i + 2];
    state[Nb * 3 + i] ^= w[4 * Nb * r + 4 * i + 3];
  }
}

void sub_bytes(uint8_t *state) {
  uint8_t i, j;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[Nb * i + j] = s_box[state[Nb * i + j]];
    }
  }
}

void inv_sub_bytes(uint8_t *state) {
  uint8_t i, j;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[Nb * i + j] = inv_s_box[state[Nb * i + j]];
    }
  }
}

void shift_rows(uint8_t *state) {
  uint8_t i, k, s, tmp;

  for (i = 1; i < 4; i++) {
    // shift(1,4)=1; shift(2,4)=2; shift(3,4)=3
    // shift(r, 4) = r;
    s = 0;
    while (s < i) {
      tmp = state[Nb * i + 0];  // save the first byte

      for (k = 1; k < Nb; k++) {
        state[Nb * i + k - 1] = state[Nb * i + k];
      }

      state[Nb * i + Nb - 1] = tmp;
      s++;
    }
  }
}

void inv_shift_rows(uint8_t *state) {
  uint8_t i, k, s, tmp;

  for (i = 1; i < 4; i++) {
    // shift(1,4)=1; shift(2,4)=2; shift(3,4)=3
    // shift(r, 4) = r;
    s = 0;
    while (s < i) {
      tmp = state[Nb * i + Nb - 1];  // save the last byte

      for (k = Nb - 1; k > 0; k--) {
        state[Nb * i + k] = state[Nb * i + k - 1];
      }

      state[Nb * i + 0] = tmp;
      s++;
    }
  }
}

/**
 * @brief mix columns
 * 
 * @param state 
 */
void mix_columns(uint8_t *state) {
  uint8_t a[] = {0x02, 0x03, 0x01, 0x01};

  uint8_t i, j, col[4], res[4];

  for(i = 0; i < Nb; i++) {
    for(j = 0; j < 4; j++) {
      col[j] = state[Nb * j + i];
    }

    // ? need to check if this is correct
    {
    // my implementation
    res[0] = gmul(a[0], col[0]) ^ gmul(a[1], col[1]) ^ gmul(a[2], col[2]) ^ gmul(a[3], col[3]);
    res[1] = gmul(a[3], col[0]) ^ gmul(a[0], col[1]) ^ gmul(a[1], col[2]) ^ gmul(a[2], col[3]);
    res[2] = gmul(a[2], col[0]) ^ gmul(a[3], col[1]) ^ gmul(a[0], col[2]) ^ gmul(a[1], col[3]);
    res[3] = gmul(a[1], col[0]) ^ gmul(a[2], col[1]) ^ gmul(a[3], col[2]) ^ gmul(a[0], col[3]);

    // github implementation
    // res[0] = gmul(a[0], col[0]) ^ gmul(a[3], col[1]) ^ gmul(a[2], col[2]) ^ gmul(a[1], col[3]);
    // res[1] = gmul(a[1], col[0]) ^ gmul(a[0], col[1]) ^ gmul(a[3], col[2]) ^ gmul(a[2], col[3]);
    // res[2] = gmul(a[2], col[0]) ^ gmul(a[1], col[1]) ^ gmul(a[0], col[2]) ^ gmul(a[3], col[3]);
    // res[3] = gmul(a[3], col[0]) ^ gmul(a[2], col[1]) ^ gmul(a[1], col[2]) ^ gmul(a[0], col[3]);
    }
    for(j = 0; j < Nb; j++) {
      state[Nb * j + i] = res[j];
    }
  }
}


/**
 * @brief inverse mix columns
 * 
 * @param state 
 */
void inv_mix_columns(uint8_t *state) {
  uint8_t a[] = {0x0e, 0x0b, 0x0d, 0x09};

  uint8_t i, j, col[4], res[4];

  for(i = 0; i < 4; i++) {
    for(j = 0; j < 4; j++) {
      col[j] = state[Nb * j + i];
    }

    // ? need to check if this is correct
    {
    // my implementation
    res[0] = gmul(a[0], col[0]) ^ gmul(a[1], col[1]) ^ gmul(a[2], col[2]) ^ gmul(a[3], col[3]);
    res[1] = gmul(a[3], col[0]) ^ gmul(a[0], col[1]) ^ gmul(a[1], col[2]) ^ gmul(a[2], col[3]);
    res[2] = gmul(a[2], col[0]) ^ gmul(a[3], col[1]) ^ gmul(a[0], col[2]) ^ gmul(a[1], col[3]);
    res[3] = gmul(a[1], col[0]) ^ gmul(a[2], col[1]) ^ gmul(a[3], col[2]) ^ gmul(a[0], col[3]);

    // github implementation
    // res[0] = gmul(a[0], col[0]) ^ gmul(a[3], col[1]) ^ gmul(a[2], col[2]) ^ gmul(a[1], col[3]);
    // res[1] = gmul(a[1], col[0]) ^ gmul(a[0], col[1]) ^ gmul(a[3], col[2]) ^ gmul(a[2], col[3]);
    // res[2] = gmul(a[2], col[0]) ^ gmul(a[1], col[1]) ^ gmul(a[0], col[2]) ^ gmul(a[3], col[3]);
    // res[3] = gmul(a[3], col[0]) ^ gmul(a[2], col[1]) ^ gmul(a[1], col[2]) ^ gmul(a[0], col[3]);
    }
    for(j = 0; j < 4; j++) {
      state[Nb * j + i] = res[j];
    }
  }
}


/**
 * @brief allocate memory for expanded key
 *      aes-256: 4*15*4 = 240 bytes
 * @param key_size
 * @return uint8_t*
 */
uint8_t *AES_init(size_t key_size) {
  uint8_t *key = (uint8_t *)malloc(Nb * (Nr + 1) * 4);

  return key;
}
/**
 * @brief free memory for expanded key
 * 
 * @param key 
 */
void AES_free(uint8_t *key) {
  free(key);
}

/**
 * @brief encrypt 16-byte block
 * 
 * @param in 
 * @param out 
 * @param w expanded key
 */
void aes_cipher(uint8_t *in, uint8_t *out, uint8_t *w) {
  uint8_t state[4 * Nb];
  uint8_t r, i, j;

  // copy in to state
  for(i = 0; i < 4 * Nb; i++) {
    state[i] = in[i];
  }

  // add round key
  add_round_key(state, w, 0);

  // round 1 to Nr
  for (r = 1; r < Nr; r++) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, w, r);
  }

  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, w, Nr);

  // copy state to out
  for (i = 0; i < 4 * Nb; i++) {
    out[i] = state[i];
  }
}

void aes_inv_cipher(uint8_t *in, uint8_t *out, uint8_t *w) {
  uint8_t state[4 * Nb];
  uint8_t r, i, j;

  // copy in to state
  for(i = 0; i < 4 * Nb; i++) {
    state[i] = in[i];
  }

  // add round key
  add_round_key(state, w, Nr);

  // round 1 to Nr
  for (r = Nr - 1; r > 0; r--) {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, w, r);
    inv_mix_columns(state);
  }

  inv_shift_rows(state);
  inv_sub_bytes(state);
  add_round_key(state, w, 0);

  // copy state to out
  for (i = 0; i < 4 * Nb; i++) {
    out[i] = state[i];
  }
  
}






