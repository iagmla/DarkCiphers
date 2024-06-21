/* Advanced KryptoMagick Standard 2 (AKMS2) */
/* by KryptoMagick (Karl Zander) */
/* 256 bit key / 128 bit block size */
/* 64 rounds */

uint32_t akms2_C0[4] = {0xb5232c67, 0xabdd2f50, 0xab790aaa, 0xe8395ac0};

struct akms2_state {
    uint32_t S[4];
    uint32_t T[4];
    uint32_t K[64][4];
    uint32_t last[4];
    uint32_t next[4];
    int rounds;
};

uint32_t akms2_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t akms2_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void akms2_ksa(struct akms2_state *state, uint8_t *key) {
    state->rounds = 64;

    state->K[0][0] = ((key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3]);
    state->K[0][1] = ((key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7]);
    state->K[0][2] = ((key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11]);
    state->K[0][3] = ((key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15]);
    state->K[63][0] = ((key[16] << 24) + (key[17] << 16) + (key[18] << 8) + key[19]);
    state->K[63][1] = ((key[20] << 24) + (key[21] << 16) + (key[22] << 8) + key[23]);
    state->K[63][2] = ((key[24] << 24) + (key[25] << 16) + (key[26] << 8) + key[27]);
    state->K[63][3] = ((key[28] << 24) + (key[29] << 16) + (key[30] << 8) + key[31]);

    state->S[0] = state->K[0][0] + akms2_C0[0];
    state->S[1] = state->K[0][1] + akms2_C0[1];
    state->S[2] = state->K[0][2] + akms2_C0[2];
    state->S[3] = state->K[0][3] + akms2_C0[3];

    state->T[0] = state->K[63][0];
    state->T[1] = state->K[63][1];
    state->T[2] = state->K[63][2];
    state->T[3] = state->K[63][3];

    int i = 0;
    for (int r = 1; r < state->rounds - 1; r++) {
        state->S[i & 0x03] ^= akms2_rotl(state->T[i & 0x03], 6) + akms2_rotl(state->S[(i + 3) & 0x03], 5);
        state->S[(i + 1) & 0x03] ^= akms2_rotl(state->T[(i + 1) & 0x03], 10) + akms2_rotl(state->S[(i + 2) & 0x03], 9);
        state->S[(i + 2) & 0x03] ^= akms2_rotl(state->T[(i + 2) & 0x03], 7) + akms2_rotl(state->S[i & 0x03], 6);
        state->S[(i + 3) & 0x03] ^= akms2_rotl(state->T[(i + 3) & 0x03], 12) + akms2_rotl(state->S[(i + 1) & 0x03], 11);

        state->T[i & 0x03] ^= akms2_rotl(state->S[i & 0x03], 6) + akms2_rotl(state->T[(i + 3) & 0x03], 5);
        state->T[(i + 1) & 0x03] ^= akms2_rotl(state->S[(i + 1) & 0x03], 10) + akms2_rotl(state->T[i & 0x03], 9);
        state->T[(i + 2) & 0x03] ^= akms2_rotl(state->S[(i + 2) & 0x03], 7) + akms2_rotl(state->T[(i + 1) & 0x03], 6);
        state->T[(i + 3) & 0x03] ^= akms2_rotl(state->S[(i + 3) & 0x03], 12) + akms2_rotl(state->T[(i + 2) & 0x03], 11);

        state->K[r][0] = state->S[0];
        state->K[r][1] = state->S[1];
        state->K[r][2] = state->S[2];
        state->K[r][3] = state->S[3];
        i += 1;
    }
}

void akms2_encrypt_block(struct akms2_state *state) {
    for (int r = 0; r < state->rounds; r++) {
        state->S[1] += state->S[2];
        state->S[1] = akms2_rotl(state->S[1], 5);
        state->S[1] ^= state->S[0];
        state->S[1] ^= state->K[r][1];
        state->S[2] += state->S[1];
        state->S[2] = akms2_rotl(state->S[2], 9);
        state->S[2] ^= state->S[3];
        state->S[2] ^= state->K[r][2];
        state->S[0] += state->S[2];
        state->S[0] = akms2_rotr(state->S[0], 6);
        state->S[0] ^= state->S[3];
        state->S[0] ^= state->K[r][0];
        state->S[3] += state->S[0];
        state->S[3] = akms2_rotr(state->S[3], 11);
        state->S[3] ^= state->S[1];
        state->S[3] ^= state->K[r][3];
    }
}

void akms2_decrypt_block(struct akms2_state *state) {
    for (int r = state->rounds - 1; r != -1; r--) {
        state->S[3] ^= state->K[r][3];
        state->S[3] ^= state->S[1];
        state->S[3] = akms2_rotl(state->S[3], 11);
        state->S[3] -= state->S[0];
        state->S[0] ^= state->K[r][0];
        state->S[0] ^= state->S[3];
        state->S[0] = akms2_rotl(state->S[0], 6);
        state->S[0] -= state->S[2];
        state->S[2] ^= state->K[r][2];
        state->S[2] ^= state->S[3];
        state->S[2] = akms2_rotr(state->S[2], 9);
        state->S[2] -= state->S[1];
        state->S[1] ^= state->K[r][1];
        state->S[1] ^= state->S[0];
        state->S[1] = akms2_rotr(state->S[1], 5);
        state->S[1] -= state->S[2];
    }
}

void akms2_load_block(struct akms2_state *state, uint8_t *block) {
    state->S[0] = ((block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3]);
    state->S[1] = ((block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7]);
    state->S[2] = ((block[8] << 24) + (block[9] << 16) + (block[10] << 8) + block[11]);
    state->S[3] = ((block[12] << 24) + (block[13] << 16) + (block[14] << 8) + block[15]);
}

void akms2_unload_block(struct akms2_state *state, uint8_t *block) {
    block[0] = state->S[0] >> 24;
    block[1] = state->S[0] >> 16;
    block[2] = state->S[0] >> 8;
    block[3] = state->S[0];
    block[4] = state->S[1] >> 24;
    block[5] = state->S[1] >> 16;
    block[6] = state->S[1] >> 8;
    block[7] = state->S[1];
    block[8] = state->S[2] >> 24;
    block[9] = state->S[2] >> 16;
    block[10] = state->S[2] >> 8;
    block[11] = state->S[2];
    block[12] = state->S[3] >> 24;
    block[13] = state->S[3] >> 16;
    block[14] = state->S[3] >> 8;
    block[15] = state->S[3];
}

void akms2_load_iv(struct akms2_state *state, uint8_t *iv) {
    state->last[0] = ((iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3]);
    state->last[1] = ((iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7]);
    state->last[2] = ((iv[8] << 24) + (iv[9] << 16) + (iv[10] << 8) + iv[11]);
    state->last[3] = ((iv[12] << 24) + (iv[13] << 16) + (iv[14] << 8) + iv[15]);
}

void akms2_cbc_last(struct akms2_state *state) {
    state->S[0] ^= state->last[0];
    state->S[1] ^= state->last[1];
    state->S[2] ^= state->last[2];
    state->S[3] ^= state->last[3];
}

void akms2_cbc_next(struct akms2_state *state) {
    state->last[0] = state->S[0];
    state->last[1] = state->S[1];
    state->last[2] = state->S[2];
    state->last[3] = state->S[3];
}

void akms2_cbc_next_inv(struct akms2_state *state) {
    state->next[0] = state->S[0];
    state->next[1] = state->S[1];
    state->next[2] = state->S[2];
    state->next[3] = state->S[3];
}

void akms2_cbc_last_inv(struct akms2_state *state) {
    state->last[0] = state->next[0];
    state->last[1] = state->next[1];
    state->last[2] = state->next[2];
    state->last[3] = state->next[3];
}
