/* Nuqvam */
/* meaning (weapon) in Klingon */
/* by KryptoMagick (Karl Zander) */
/* 256 bit key / 512 bit state / 128 bit nonce */
/* 256 bit output block */
/* 16 rounds */

uint32_t nuqvam_Q0[4] = {0xcaf26468, 0xce9637c2, 0xb052d5d9, 0xda2116df};

struct nuqvam_state {
    uint32_t S[4][4];
    uint32_t O[8];
    uint32_t Y[4][4];
    int rounds;
};

uint32_t nuqvam_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t nuqvam_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void nuqvam_update(struct nuqvam_state *state) {
    for (int i = 0; i < state->rounds; i++) {

        state->S[1][1] += state->S[3][2];
        state->S[2][2] = nuqvam_rotl(state->S[2][2] ^ state->S[1][1], 7);
        state->S[3][3] += state->S[0][3];
        state->S[0][0] = nuqvam_rotl(state->S[0][0] ^ state->S[3][3], 13);
        state->S[2][0] += state->S[1][0];
        state->S[3][1] = nuqvam_rotl(state->S[3][1] ^ state->S[2][0], 29);
        state->S[0][2] += state->S[2][1];
        state->S[1][3] = nuqvam_rotl(state->S[1][3] ^ state->S[0][2], 31);

        state->S[2][1] += state->S[2][0];
        state->S[3][2] = nuqvam_rotl(state->S[3][2] ^ state->S[2][1], 7);
        state->S[0][3] ^= state->S[3][1];
        state->S[1][0] = nuqvam_rotl(state->S[1][0] + state->S[0][3], 13);
        state->S[3][0] += state->S[0][2];   
        state->S[0][1] = nuqvam_rotl(state->S[0][1] ^ state->S[3][0], 29);
        state->S[1][2] ^= state->S[1][3];
        state->S[2][3] = nuqvam_rotl(state->S[2][3] + state->S[1][2], 31);

        state->S[3][1] += state->S[0][1];
        state->S[0][2] = nuqvam_rotl(state->S[0][2] ^ state->S[3][1], 7);
        state->S[1][3] += state->S[1][2];
        state->S[2][0] = nuqvam_rotl(state->S[2][0] ^ state->S[1][3], 13);
        state->S[0][0] += state->S[2][3];
        state->S[1][1] = nuqvam_rotl(state->S[1][1] ^ state->S[0][0], 29);
        state->S[2][2] += state->S[3][0];
        state->S[3][3] = nuqvam_rotl(state->S[3][3] ^ state->S[2][2], 31);

        state->S[2][1] += state->S[1][1];
        state->S[3][2] = nuqvam_rotl(state->S[3][2] ^ state->S[2][1], 7);
        state->S[0][3] ^= state->S[2][2];
        state->S[1][0] = nuqvam_rotl(state->S[1][0] + state->S[0][3], 13);
        state->S[3][0] += state->S[3][3];
        state->S[0][1] = nuqvam_rotl(state->S[0][1] ^ state->S[3][0], 29);
        state->S[1][2] ^= state->S[0][0];
        state->S[2][3] = nuqvam_rotl(state->S[2][3] + state->S[1][2], 31);

        state->Y[0][0] = state->S[0][0];
        state->Y[0][1] = state->S[0][1];
        state->Y[0][2] = state->S[0][2];
        state->Y[0][3] = state->S[0][3];
        state->Y[1][0] = state->S[1][0];
        state->Y[1][1] = state->S[1][1];
        state->Y[1][2] = state->S[1][2];
        state->Y[1][3] = state->S[1][3];
        state->Y[2][0] = state->S[2][0];
        state->Y[2][1] = state->S[2][1];
        state->Y[2][2] = state->S[2][2];
        state->Y[2][3] = state->S[2][3];
        state->Y[3][0] = state->S[3][0];
        state->Y[3][1] = state->S[3][1];
        state->Y[3][2] = state->S[3][2];
        state->Y[3][3] = state->S[3][3];

        state->S[0][0] = state->Y[1][0];
        state->S[0][1] = state->Y[1][1];
        state->S[0][2] = state->Y[1][2];
        state->S[0][3] = state->Y[1][3];
        state->S[1][0] = state->Y[2][0];
        state->S[1][1] = state->Y[2][1];
        state->S[1][2] = state->Y[2][2];
        state->S[1][3] = state->Y[2][3];
        state->S[2][0] = state->Y[3][0];
        state->S[2][1] = state->Y[3][1];
        state->S[2][2] = state->Y[3][2];
        state->S[2][3] = state->Y[3][3];
        state->S[3][0] = state->Y[0][1];
        state->S[3][1] = state->Y[0][2];
        state->S[3][2] = state->Y[0][3];
        state->S[3][3] = state->Y[0][0];
    }

    state->O[0] = state->S[0][0] ^ state->S[2][0];
    state->O[1] = state->S[0][1] ^ state->S[2][1];
    state->O[2] = state->S[0][2] ^ state->S[2][2];
    state->O[3] = state->S[0][3] ^ state->S[2][3];
    state->O[4] = state->S[1][0] ^ state->S[3][0];
    state->O[5] = state->S[1][1] ^ state->S[3][1];
    state->O[6] = state->S[1][2] ^ state->S[3][2];
    state->O[7] = state->S[1][3] ^ state->S[3][3];

}

void nuqvam_keysetup(struct nuqvam_state *state, uint8_t *key, uint8_t *nonce) {
    state->rounds = 16;
    state->S[0][0] = ((uint32_t)(key[0]) << 24) + ((uint32_t)key[1] << 16) + ((uint32_t)key[2] << 8) + ((uint32_t)key[3]);
    state->S[1][1] = ((uint32_t)(key[4]) << 24) + ((uint32_t)key[5] << 16) + ((uint32_t)key[6] << 8) + ((uint32_t)key[7]);
    state->S[2][2] = ((uint32_t)(key[8]) << 24) + ((uint32_t)key[9] << 16) + ((uint32_t)key[10] << 8) + ((uint32_t)key[11]);
    state->S[3][3] = ((uint32_t)(key[12]) << 24) + ((uint32_t)key[13] << 16) + ((uint32_t)key[14] << 8) + ((uint32_t)key[15]);
    state->S[0][1] = ((uint32_t)(key[16]) << 24) + ((uint32_t)key[17] << 16) + ((uint32_t)key[18] << 8) + ((uint32_t)key[19]);
    state->S[1][2] = ((uint32_t)(key[20]) << 24) + ((uint32_t)key[21] << 16) + ((uint32_t)key[22] << 8) + ((uint32_t)key[23]);
    state->S[2][3] = ((uint32_t)(key[24]) << 24) + ((uint32_t)key[25] << 16) + ((uint32_t)key[26] << 8) + ((uint32_t)key[27]);
    state->S[3][0] = ((uint32_t)(key[28]) << 24) + ((uint32_t)key[29] << 16) + ((uint32_t)key[30] << 8) + ((uint32_t)key[31]);

    state->S[0][2] = ((uint32_t)(nonce[0]) << 24) + ((uint32_t)nonce[1] << 16) + ((uint32_t)nonce[2] << 8) + ((uint32_t)nonce[3]);
    state->S[1][3] = ((uint32_t)(nonce[4]) << 24) + ((uint32_t)nonce[5] << 16) + ((uint32_t)nonce[6] << 8) + ((uint32_t)nonce[7]);
    state->S[2][0] = ((uint32_t)(nonce[8]) << 24) + ((uint32_t)nonce[9] << 16) + ((uint32_t)nonce[10] << 8) + ((uint32_t)nonce[11]);
    state->S[3][1] = ((uint32_t)(nonce[12]) << 24) + ((uint32_t)nonce[13] << 16) + ((uint32_t)nonce[14] << 8) + ((uint32_t)nonce[15]);

    state->S[0][3] = nuqvam_Q0[0];
    state->S[1][0] = nuqvam_Q0[1];
    state->S[2][1] = nuqvam_Q0[2];
    state->S[3][2] = nuqvam_Q0[3];

}

void nuqvam_xor_block(struct nuqvam_state *state, uint8_t *block) {
    block[0] ^= (state->O[0] & 0xFF000000) >> 24;
    block[1] ^= (state->O[0] & 0x00FF0000) >> 16;
    block[2] ^= (state->O[0] & 0x0000FF00) >> 8;
    block[3] ^= (state->O[0] & 0x000000FF);
    block[4] ^= (state->O[1] & 0xFF000000) >> 24;
    block[5] ^= (state->O[1] & 0x00FF0000) >> 16;
    block[6] ^= (state->O[1] & 0x0000FF00) >> 8;
    block[7] ^= (state->O[1] & 0x000000FF);
    block[8] ^= (state->O[2] & 0xFF000000) >> 24;
    block[9] ^= (state->O[2] & 0x00FF0000) >> 16;
    block[10] ^= (state->O[2] & 0x0000FF00) >> 8;
    block[11] ^= (state->O[2] & 0x000000FF);
    block[12] ^= (state->O[3] & 0xFF000000) >> 24;
    block[13] ^= (state->O[3] & 0x00FF0000) >> 16;
    block[14] ^= (state->O[3] & 0x0000FF00) >> 8;
    block[15] ^= (state->O[3] & 0x000000FF);
    block[16] ^= (state->O[4] & 0xFF000000) >> 24;
    block[17] ^= (state->O[4] & 0x00FF0000) >> 16;
    block[18] ^= (state->O[4] & 0x0000FF00) >> 8;
    block[19] ^= (state->O[4] & 0x000000FF);
    block[20] ^= (state->O[5] & 0xFF000000) >> 24;
    block[21] ^= (state->O[5] & 0x00FF0000) >> 16;
    block[22] ^= (state->O[5] & 0x0000FF00) >> 8;
    block[23] ^= (state->O[5] & 0x000000FF);
    block[24] ^= (state->O[6] & 0xFF000000) >> 24;
    block[25] ^= (state->O[6] & 0x00FF0000) >> 16;
    block[26] ^= (state->O[6] & 0x0000FF00) >> 8;
    block[27] ^= (state->O[6] & 0x000000FF);
    block[28] ^= (state->O[7] & 0xFF000000) >> 24;
    block[29] ^= (state->O[7] & 0x00FF0000) >> 16;
    block[30] ^= (state->O[7] & 0x0000FF00) >> 8;
    block[31] ^= (state->O[7] & 0x000000FF);
}
