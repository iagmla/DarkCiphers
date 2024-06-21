/* Jiyajbe */
/* meaning (I don't understand) in Klingon */
/* by KryptoMagick (Karl Zander) */
/* 256 bit key / 512 bit state / 128 bit nonce */
/* 256 bit output block */
/* 16 rounds */

uint32_t jiyajbe_Q0[4] = {0xed21b71b, 0xe3b4d73a, 0x85f2eb43, 0x9b5240c2};

struct jiyajbe_state {
    uint32_t r[16];
    uint32_t o[8];
    uint32_t y[16];
    int rounds;
};

uint32_t jiyajbe_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t jiyajbe_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void jiyajbe_update(struct jiyajbe_state *state) {
    for (int i = 0; i < state->rounds; i++) {
        state->r[8] ^= jiyajbe_rotl((state->r[10] + state->r[3]), 7);
        state->r[15] += jiyajbe_rotl((state->r[14] ^ state->r[6]), 21);
        state->r[9] += jiyajbe_rotl((state->r[11] ^ state->r[0]), 17);
        state->r[5] += jiyajbe_rotl((state->r[7] ^ state->r[12]), 9);
        state->r[2] ^= jiyajbe_rotl((state->r[2] + state->r[9]), 13);
        state->r[11] += jiyajbe_rotl((state->r[9] ^ state->r[2]), 19);
        state->r[4] ^= jiyajbe_rotl((state->r[4] + state->r[15]), 6);
        state->r[6] ^= jiyajbe_rotl((state->r[6] + state->r[13]), 14);
        state->r[13] += jiyajbe_rotl((state->r[12] ^ state->r[4]), 9);
        state->r[0] ^= jiyajbe_rotl((state->r[0] + state->r[11]), 7);
        state->r[7] += jiyajbe_rotl((state->r[5] ^ state->r[14]), 21);
        state->r[14] += jiyajbe_rotl((state->r[13] + state->r[5]), 14);
        state->r[10] += jiyajbe_rotl((state->r[8] + state->r[1]), 13);
        state->r[3] += jiyajbe_rotl((state->r[1] ^ state->r[10]), 19);
        state->r[12] ^= jiyajbe_rotl((state->r[15] + state->r[7]), 6);
        state->r[1] += jiyajbe_rotl((state->r[3] ^ state->r[8]), 17);
    }

    state->o[0] = state->r[0] ^ state->r[8];
    state->o[1] = state->r[1] ^ state->r[9];
    state->o[2] = state->r[2] ^ state->r[10];
    state->o[3] = state->r[3] ^ state->r[11];
    state->o[4] = state->r[4] ^ state->r[12];
    state->o[5] = state->r[5] ^ state->r[13];
    state->o[6] = state->r[6] ^ state->r[14];
    state->o[7] = state->r[7] ^ state->r[15];

    state->y[0] = state->r[0];
    state->y[1] = state->r[1];
    state->y[2] = state->r[2];
    state->y[3] = state->r[3];
    state->y[4] = state->r[4];
    state->y[5] = state->r[5];
    state->y[6] = state->r[6];
    state->y[7] = state->r[7];
    state->y[8] = state->r[8];
    state->y[9] = state->r[9];
    state->y[10] = state->r[10];
    state->y[11] = state->r[11];
    state->y[12] = state->r[12];
    state->y[13] = state->r[13];
    state->y[14] = state->r[14];
    state->y[15] = state->r[15];

    state->r[0] = state->y[1];
    state->r[1] = state->y[2];
    state->r[2] = state->y[3];
    state->r[3] = state->y[4];
    state->r[4] = state->y[5];
    state->r[5] = state->y[6];
    state->r[6] = state->y[7];
    state->r[7] = state->y[8];
    state->r[8] = state->y[9];
    state->r[9] = state->y[10];
    state->r[10] = state->y[11];
    state->r[11] = state->y[12];
    state->r[12] = state->y[13];
    state->r[13] = state->y[14];
    state->r[14] = state->y[15];
    state->r[15] = state->y[0];

}

void jiyajbe_keysetup(struct jiyajbe_state *state, uint8_t *key, uint8_t *nonce) {
    state->rounds = 16;
    state->r[0] = ((uint32_t)(key[0]) << 24) + ((uint32_t)key[1] << 16) + ((uint32_t)key[2] << 8) + ((uint32_t)key[3]);
    state->r[2] = ((uint32_t)(key[4]) << 24) + ((uint32_t)key[5] << 16) + ((uint32_t)key[6] << 8) + ((uint32_t)key[7]);
    state->r[4] = ((uint32_t)(key[8]) << 24) + ((uint32_t)key[9] << 16) + ((uint32_t)key[10] << 8) + ((uint32_t)key[11]);
    state->r[6] = ((uint32_t)(key[12]) << 24) + ((uint32_t)key[13] << 16) + ((uint32_t)key[14] << 8) + ((uint32_t)key[15]);
    state->r[8] = ((uint32_t)(key[16]) << 24) + ((uint32_t)key[17] << 16) + ((uint32_t)key[18] << 8) + ((uint32_t)key[19]);
    state->r[10] = ((uint32_t)(key[20]) << 24) + ((uint32_t)key[21] << 16) + ((uint32_t)key[22] << 8) + ((uint32_t)key[23]);
    state->r[12] = ((uint32_t)(key[24]) << 24) + ((uint32_t)key[25] << 16) + ((uint32_t)key[26] << 8) + ((uint32_t)key[27]);
    state->r[14] = ((uint32_t)(key[28]) << 24) + ((uint32_t)key[29] << 16) + ((uint32_t)key[30] << 8) + ((uint32_t)key[31]);

    state->r[1] = ((uint32_t)(nonce[0]) << 24) + ((uint32_t)nonce[1] << 16) + ((uint32_t)nonce[2] << 8) + ((uint32_t)nonce[3]);
    state->r[3] = ((uint32_t)(nonce[4]) << 24) + ((uint32_t)nonce[5] << 16) + ((uint32_t)nonce[6] << 8) + ((uint32_t)nonce[7]);
    state->r[5] = ((uint32_t)(nonce[8]) << 24) + ((uint32_t)nonce[9] << 16) + ((uint32_t)nonce[10] << 8) + ((uint32_t)nonce[11]);
    state->r[7] = ((uint32_t)(nonce[12]) << 24) + ((uint32_t)nonce[13] << 16) + ((uint32_t)nonce[14] << 8) + ((uint32_t)nonce[15]);

    state->r[9] = jiyajbe_Q0[0];
    state->r[11] = jiyajbe_Q0[1];
    state->r[13] = jiyajbe_Q0[2];
    state->r[15] = jiyajbe_Q0[3];

}

void jiyajbe_xor_block(struct jiyajbe_state *state, uint8_t *block) {
    block[0] ^= (state->o[0] & 0xFF000000) >> 24;
    block[1] ^= (state->o[0] & 0x00FF0000) >> 16;
    block[2] ^= (state->o[0] & 0x0000FF00) >> 8;
    block[3] ^= (state->o[0] & 0x000000FF);
    block[4] ^= (state->o[1] & 0xFF000000) >> 24;
    block[5] ^= (state->o[1] & 0x00FF0000) >> 16;
    block[6] ^= (state->o[1] & 0x0000FF00) >> 8;
    block[7] ^= (state->o[1] & 0x000000FF);
    block[8] ^= (state->o[2] & 0xFF000000) >> 24;
    block[9] ^= (state->o[2] & 0x00FF0000) >> 16;
    block[10] ^= (state->o[2] & 0x0000FF00) >> 8;
    block[11] ^= (state->o[2] & 0x000000FF);
    block[12] ^= (state->o[3] & 0xFF000000) >> 24;
    block[13] ^= (state->o[3] & 0x00FF0000) >> 16;
    block[14] ^= (state->o[3] & 0x0000FF00) >> 8;
    block[15] ^= (state->o[3] & 0x000000FF);
    block[16] ^= (state->o[4] & 0xFF000000) >> 24;
    block[17] ^= (state->o[4] & 0x00FF0000) >> 16;
    block[18] ^= (state->o[4] & 0x0000FF00) >> 8;
    block[19] ^= (state->o[4] & 0x000000FF);
    block[20] ^= (state->o[5] & 0xFF000000) >> 24;
    block[21] ^= (state->o[5] & 0x00FF0000) >> 16;
    block[22] ^= (state->o[5] & 0x0000FF00) >> 8;
    block[23] ^= (state->o[5] & 0x000000FF);
    block[24] ^= (state->o[6] & 0xFF000000) >> 24;
    block[25] ^= (state->o[6] & 0x00FF0000) >> 16;
    block[26] ^= (state->o[6] & 0x0000FF00) >> 8;
    block[27] ^= (state->o[6] & 0x000000FF);
    block[28] ^= (state->o[7] & 0xFF000000) >> 24;
    block[29] ^= (state->o[7] & 0x00FF0000) >> 16;
    block[30] ^= (state->o[7] & 0x0000FF00) >> 8;
    block[31] ^= (state->o[7] & 0x000000FF);
}
