/* SatanX */
/* Symmetric Advanced Tiny Algorithm Network X */
/* by KryptoMagick (Karl Zander) */
/* Key lengths (128/192/256/512) bit */
/* 256 bit block size */
/* 64 rounds 128 bit */
/* 69 rounds 192 bit */
/* 72 rounds 256 bit */
/* 80 rounds 512 bit */

uint64_t satanx_c0[8] = {0xa00f3050f2a18c8f, 0x8268adc2d69397b9, 0xcfbbc9437bcd9379, 0xbe4f3c1f65e2125d, 0x8275e501f230b8d5, 0xf8882200cdb4f256, 0xbcf86e0d3dc199bb, 0xf49868f3bbc76141};

struct satanx_state {
    uint64_t K[80][4];
    uint64_t S[4];
    uint64_t T[4];
    uint64_t last[4];
    uint64_t next[4];
    int rounds;
};

struct satanx_ksa_state {
    uint64_t r[8];
    uint64_t t[8];
    uint64_t o[4];
};

uint64_t satanx_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

void satanx_F(struct satanx_state *state) {
    state->S[0] ^= (~satanx_rotl(state->S[2], 3) & satanx_rotl(state->S[3], 7));
    state->S[1] ^= (~state->S[3] & satanx_rotl(state->S[2], 13));
}

void satanx_ksa_update(struct satanx_ksa_state *state) {
    state->r[0] ^= (~satanx_rotl(state->r[4], 2) & satanx_rotl(state->r[5], 3));
    state->r[1] ^= (~state->r[5] & satanx_rotl(state->r[4], 6));
    state->r[2] ^= (~satanx_rotl(state->r[7], 4) & state->r[6]);
    state->r[3] ^= (~satanx_rotl(state->r[6], 11) & satanx_rotl(state->r[7], 8));

    state->r[4] ^= state->r[7];
    state->r[5] ^= state->r[4];
    state->r[6] ^= state->r[5];
    state->r[7] ^= state->r[6];

    state->o[0] = state->r[0] ^ state->r[4];
    state->o[1] = state->r[1] ^ state->r[5];
    state->o[2] = state->r[2] ^ state->r[6];
    state->o[3] = state->r[3] ^ state->r[7];

    state->t[0] = state->r[0];
    state->t[1] = state->r[1];
    state->t[2] = state->r[2];
    state->t[3] = state->r[3];
    state->t[4] = state->r[4];
    state->t[5] = state->r[5];
    state->t[6] = state->r[6];
    state->t[7] = state->r[7];

    state->r[0] = state->t[4];
    state->r[1] = state->t[5];
    state->r[2] = state->t[6];
    state->r[3] = state->t[7];
    state->r[4] = state->t[0];
    state->r[5] = state->t[1];
    state->r[6] = state->t[2];
    state->r[7] = state->t[3];
}

void satanx_ksa(struct satanx_state * state, uint8_t * key, int keylen) {
    struct satanx_ksa_state kstate;
    int c = 0;
    int i, s;
    state->rounds = 72;
    memset(state->K, 0, state->rounds*(4*sizeof(uint64_t)));
    memset(&kstate.r, 0, 8*sizeof(uint64_t));
    kstate.r[0] = satanx_c0[0];
    kstate.r[1] = satanx_c0[1];
    kstate.r[2] = satanx_c0[2];
    kstate.r[3] = satanx_c0[3];
    kstate.r[4] = satanx_c0[4];
    kstate.r[5] = satanx_c0[5];
    kstate.r[6] = satanx_c0[6];
    kstate.r[7] = satanx_c0[7];

    for (i = 0; i < (keylen / 8); i++) {
        kstate.r[i] ^= ((uint64_t)key[c] << 56) + ((uint64_t)key[c+1] << 48) + ((uint64_t)key[c+2] << 40) + ((uint64_t)key[c+3] << 32) + ((uint64_t)key[c+4] << 24) + ((uint64_t)key[c+5] << 16) + ((uint64_t)key[c+6] << 8) + (uint64_t)key[c+7];
        c += 8;
    }
    for (i = 0; i < state->rounds; i++) {
        satanx_ksa_update(&kstate);
        state->K[i][0] = kstate.o[0];
        state->K[i][1] = kstate.o[1];
        state->K[i][2] = kstate.o[2];
        state->K[i][3] = kstate.o[3];
    }
}

void satanx_encrypt_block(struct satanx_state * state) {
    for (int r = 0; r < state->rounds; r++) {

        satanx_F(state);
        
        state->S[0] ^= state->K[r][0];
        state->S[1] ^= state->K[r][1];
        state->S[2] ^= state->K[r][2];
        state->S[3] ^= state->K[r][3];

        state->T[0] = state->S[0];
        state->T[1] = state->S[1];
        state->T[2] = state->S[2];
        state->T[3] = state->S[3];

        state->S[0] = state->T[2];
        state->S[1] = state->T[3];
        state->S[2] = state->T[0];
        state->S[3] = state->T[1];

    }
}

void satanx_decrypt_block(struct satanx_state * state) {
    for (int r = (state->rounds - 1); r != -1; r--) {

        state->T[0] = state->S[0];
        state->T[1] = state->S[1];
        state->T[2] = state->S[2];
        state->T[3] = state->S[3];

        state->S[0] = state->T[2];
        state->S[1] = state->T[3];
        state->S[2] = state->T[0];
        state->S[3] = state->T[1];

        state->S[3] ^= state->K[r][3];
        state->S[2] ^= state->K[r][2];
        state->S[1] ^= state->K[r][1];
        state->S[0] ^= state->K[r][0];

        satanx_F(state);

    }
}

void satanx_load_block(struct satanx_state *state, uint8_t *block) {
    state->S[0] = ((uint64_t)block[0] << 56) + ((uint64_t)block[1] << 48) + ((uint64_t)block[2] << 40) + ((uint64_t)block[3] << 32) + ((uint64_t)block[4] << 24) + ((uint64_t)block[5] << 16) + ((uint64_t)block[6] << 8) + (uint64_t)block[7];
    state->S[1] = ((uint64_t)block[8] << 56) + ((uint64_t)block[9] << 48) + ((uint64_t)block[10] << 40) + ((uint64_t)block[11] << 32) + ((uint64_t)block[12] << 24) + ((uint64_t)block[13] << 16) + ((uint64_t)block[14] << 8) + (uint64_t)block[15];
    state->S[2] = ((uint64_t)block[16] << 56) + ((uint64_t)block[17] << 48) + ((uint64_t)block[18] << 40) + ((uint64_t)block[19] << 32) + ((uint64_t)block[20] << 24) + ((uint64_t)block[21] << 16) + ((uint64_t)block[22] << 8) + (uint64_t)block[23];
    state->S[3] = ((uint64_t)block[24] << 56) + ((uint64_t)block[25] << 48) + ((uint64_t)block[26] << 40) + ((uint64_t)block[27] << 32) + ((uint64_t)block[28] << 24) + ((uint64_t)block[29] << 16) + ((uint64_t)block[30] << 8) + (uint64_t)block[31];
}

void satanx_unload_block(struct satanx_state *state, uint8_t *block) {
    block[0] = (state->S[0] & 0xFF00000000000000) >> 56;
    block[1] = (state->S[0] & 0x00FF000000000000) >> 48;
    block[2] = (state->S[0] & 0x0000FF0000000000) >> 40;
    block[3] = (state->S[0] & 0x000000FF00000000) >> 32;
    block[4] = (state->S[0] & 0x00000000FF000000) >> 24;
    block[5] = (state->S[0] & 0x0000000000FF0000) >> 16;
    block[6] = (state->S[0] & 0x000000000000FF00) >> 8;
    block[7] = (state->S[0] & 0x00000000000000FF);
    block[8] = (state->S[1] & 0xFF00000000000000) >> 56;
    block[9] = (state->S[1] & 0x00FF000000000000) >> 48;
    block[10] = (state->S[1] & 0x0000FF0000000000) >> 40;
    block[11] = (state->S[1] & 0x000000FF00000000) >> 32;
    block[12] = (state->S[1] & 0x00000000FF000000) >> 24;
    block[13] = (state->S[1] & 0x0000000000FF0000) >> 16;
    block[14] = (state->S[1] & 0x000000000000FF00) >> 8;
    block[15] = (state->S[1] & 0x00000000000000FF);
    block[16] = (state->S[2] & 0xFF00000000000000) >> 56;
    block[17] = (state->S[2] & 0x00FF000000000000) >> 48;
    block[18] = (state->S[2] & 0x0000FF0000000000) >> 40;
    block[19] = (state->S[2] & 0x000000FF00000000) >> 32;
    block[20] = (state->S[2] & 0x00000000FF000000) >> 24;
    block[21] = (state->S[2] & 0x0000000000FF0000) >> 16;
    block[22] = (state->S[2] & 0x000000000000FF00) >> 8;
    block[23] = (state->S[2] & 0x00000000000000FF);
    block[24] = (state->S[3] & 0xFF00000000000000) >> 56;
    block[25] = (state->S[3] & 0x00FF000000000000) >> 48;
    block[26] = (state->S[3] & 0x0000FF0000000000) >> 40;
    block[27] = (state->S[3] & 0x000000FF00000000) >> 32;
    block[28] = (state->S[3] & 0x00000000FF000000) >> 24;
    block[29] = (state->S[3] & 0x0000000000FF0000) >> 16;
    block[30] = (state->S[3] & 0x000000000000FF00) >> 8;
    block[31] = (state->S[3] & 0x00000000000000FF);
}

void satanx_load_iv(struct satanx_state *state, uint8_t *iv) {
    state->last[0] = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    state->last[1] = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];
    state->last[2] = ((uint64_t)iv[16] << 56) + ((uint64_t)iv[17] << 48) + ((uint64_t)iv[18] << 40) + ((uint64_t)iv[19] << 32) + ((uint64_t)iv[20] << 24) + ((uint64_t)iv[21] << 16) + ((uint64_t)iv[22] << 8) + (uint64_t)iv[23];
    state->last[3] = ((uint64_t)iv[24] << 56) + ((uint64_t)iv[25] << 48) + ((uint64_t)iv[26] << 40) + ((uint64_t)iv[27] << 32) + ((uint64_t)iv[28] << 24) + ((uint64_t)iv[29] << 16) + ((uint64_t)iv[30] << 8) + (uint64_t)iv[31];
}

void satanx_cbc_last(struct satanx_state *state) {
    state->S[0] ^= state->last[0];
    state->S[1] ^= state->last[1];
    state->S[2] ^= state->last[2];
    state->S[3] ^= state->last[3];
}

void satanx_cbc_next(struct satanx_state *state) {
    state->last[0] = state->S[0];
    state->last[1] = state->S[1];
    state->last[2] = state->S[2];
    state->last[3] = state->S[3];
}

void satanx_cbc_next_inv(struct satanx_state *state) {
    state->next[0] = state->S[0];
    state->next[1] = state->S[1];
    state->next[2] = state->S[2];
    state->next[3] = state->S[3];
}

void satanx_cbc_last_inv(struct satanx_state *state) {
    state->last[0] = state->next[0];
    state->last[1] = state->next[1];
    state->last[2] = state->next[2];
    state->last[3] = state->next[3];
}
