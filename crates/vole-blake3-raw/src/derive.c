/* Vole-owned one-shot adapter to the installed official BLAKE3 C API. */
#include "blake3.h"

void vole_blake3_raw_derive(const unsigned char *context, size_t context_len,
                            const unsigned char *material, size_t material_len,
                            unsigned char output[32]) {
  blake3_hasher hasher;
  blake3_hasher_init_derive_key_raw(&hasher, context, context_len);
  blake3_hasher_update(&hasher, material, material_len);
  blake3_hasher_finalize(&hasher, output, 32);

  /* Erase this adapter's state without optimizing the stores away. This does
     not promise erasure of temporaries inside the unmodified upstream code. */
  volatile unsigned char *state = (volatile unsigned char *)&hasher;
  for (size_t i = 0; i < sizeof(hasher); ++i) {
    state[i] = 0;
  }
}
