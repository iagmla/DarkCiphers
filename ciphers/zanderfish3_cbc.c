/* ZanderFish3 */
/* by KryptoMagick (Karl Zander) */
/* Key lengths (256/512) bit */
/* 256 bit block size */
/* 56 rounds 256 bit */
/* 64 rounds 512 bit */

uint64_t c0[8] = {0x960197a5259271e3, 0xf709d2bf05fa7062, 0xf85e97d298dc5738, 0xbf7f2dfcfd287281, 0xf2b28a5c657627ce, 0xfb25129e749adfac, 0xff1cd21a0d77cfa5, 0x982199f72c4174c3};

struct zander3_state {
    uint64_t K[80][4];
    uint64_t D[4];
    uint64_t S[4];
    uint64_t last[4];
    uint64_t next[4];
    int rounds;
};

struct z3ksa_state {
    uint64_t r[8];
    uint64_t o;
};

uint64_t zander3_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t zander3_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void zander3_ksa_update(struct z3ksa_state *state) {
    state->r[0] ^= zander3_rotl(state->r[3], 18) + state->r[4];
    state->r[1] += zander3_rotl(state->r[0], 26) ^ state->r[5];
    state->r[2] ^= zander3_rotl(state->r[1] + state->r[6], 13);
    state->r[3] += zander3_rotl(state->r[2] ^ state->r[7], 29);
    state->r[4] ^= zander3_rotl(state->r[6], 34) + state->r[0];
    state->r[5] += zander3_rotl(state->r[7], 28) ^ state->r[1];
    state->r[6] ^= zander3_rotl(state->r[4] + state->r[2], 17);
    state->r[7] += zander3_rotl(state->r[5] ^ state->r[3], 45);

    state->o = 0;
    state->o ^= state->r[0];
    state->o ^= state->r[1];
    state->o ^= state->r[2];
    state->o ^= state->r[3];
    state->o ^= state->r[4];
    state->o ^= state->r[5];
    state->o ^= state->r[6];
    state->o ^= state->r[7];
}

void zander3_ksa(struct zander3_state * state, uint8_t * key, int keylen) {
    struct z3ksa_state kstate;
    int c = 0;
    int i, s;
    state->rounds = ((keylen / 4) + ((keylen / 8) + (48 - (keylen / 8))));
    memset(state->K, 0, state->rounds*(4*sizeof(uint64_t)));
    memset(&kstate.r, 0, 8*sizeof(uint64_t));
    memset(&kstate.o, 0, sizeof(uint64_t));
    kstate.r[0] = c0[0];
    kstate.r[1] = c0[1];
    kstate.r[2] = c0[2];
    kstate.r[3] = c0[3];
    kstate.r[4] = c0[4];
    kstate.r[5] = c0[5];
    kstate.r[6] = c0[6];
    kstate.r[7] = c0[7];

    for (i = 0; i < (keylen / 8); i++) {
        kstate.r[i] ^= ((uint64_t)key[c] << 56) + ((uint64_t)key[c+1] << 48) + ((uint64_t)key[c+2] << 40) + ((uint64_t)key[c+3] << 32) + ((uint64_t)key[c+4] << 24) + ((uint64_t)key[c+5] << 16) + ((uint64_t)key[c+6] << 8) + (uint64_t)key[c+7];
        c += 8;
    }
    for (i = 0; i < state->rounds; i++) {
        for (s = 0; s < 4; s++) {
            zander3_ksa_update(&kstate);
            state->K[i][s] = kstate.o;
        }
    }
    for (s = 0; s < 4; s++) {
        zander3_ksa_update(&kstate);
        state->D[s] = kstate.o;
    }
}

void zander3_encrypt_block(struct zander3_state * state) {
    for (int r = 0; r < state->rounds; r++) {

        state->S[1] += state->S[2];
        state->S[3] += state->S[1];
        state->S[0] = zander3_rotl(state->S[0], 18) ^ state->S[3];

        state->S[0] += state->S[2];
        state->S[2] += state->S[0];
        state->S[1] = zander3_rotl(state->S[1], 26) ^ state->S[2];

        state->S[0] += state->S[3];
        state->S[2] = zander3_rotl(state->S[2], 13) ^ state->S[0];

        state->S[1] += state->S[2];
        state->S[3] = zander3_rotl(state->S[3], 29) ^ state->S[1];

        state->S[1] += state->S[3];
        state->S[0] = zander3_rotl(state->S[0], 34) ^ state->S[1];

        state->S[3] += state->S[0];
        state->S[2] = zander3_rotl(state->S[2], 28) ^ state->S[3];

        state->S[0] += state->S[2];
        state->S[0] ^= state->K[r][0];
        state->S[3] = zander3_rotl(state->S[3], 17) ^ state->S[0];
        state->S[3] ^= state->K[r][3];

        state->S[2] += state->S[3];
        state->S[2] ^= state->K[r][2];
        state->S[1] = zander3_rotl(state->S[1], 45) ^ state->S[2];
        state->S[1] ^= state->K[r][1];

        state->S[3] ^= state->S[2];
        state->S[2] ^= state->S[3];
        state->S[1] ^= state->S[0];
        state->S[0] ^= state->S[1];

    }
    state->S[0] ^= state->D[0];
    state->S[1] ^= state->D[1];
    state->S[2] ^= state->D[2];
    state->S[3] ^= state->D[3];
}

void zander3_decrypt_block(struct zander3_state * state) {
    uint64_t temp;

    state->S[3] ^= state->D[3];
    state->S[2] ^= state->D[2];
    state->S[1] ^= state->D[1];
    state->S[0] ^= state->D[0];

    for (int r = (state->rounds - 1); r != -1; r--) {

        state->S[0] ^= state->S[1];
        state->S[1] ^= state->S[0];
        state->S[2] ^= state->S[3];
        state->S[3] ^= state->S[2];

        state->S[1] ^= state->K[r][1];
        temp = state->S[1] ^ state->S[2];
        state->S[1] = zander3_rotr(temp, 45);
        state->S[2] ^= state->K[r][2];
        state->S[2] -= state->S[3];

        state->S[3] ^= state->K[r][3];
        temp = state->S[3] ^ state->S[0];
        state->S[3] = zander3_rotr(temp, 17);
        state->S[0] ^= state->K[r][0];
        state->S[0] -= state->S[2];

        temp = state->S[2] ^ state->S[3];
        state->S[2] = zander3_rotr(temp, 28);
        state->S[3] -= state->S[0];

        temp = state->S[0] ^ state->S[1];
        state->S[0] = zander3_rotr(temp, 34);
        state->S[1] -= state->S[3];

        temp = state->S[3] ^ state->S[1];
        state->S[3] = zander3_rotr(temp, 29);
        state->S[1] -= state->S[2];

        temp = state->S[2] ^ state->S[0];
        state->S[2] = zander3_rotr(temp, 13);
        state->S[0] -= state->S[3];

        temp = state->S[1] ^ state->S[2];
        state->S[1] = zander3_rotr(temp, 26);
        state->S[2] -= state->S[0];
        state->S[0] -= state->S[2];

        temp = state->S[0] ^ state->S[3];
        state->S[0] = zander3_rotr(temp, 18);
        state->S[3] -= state->S[1];
        state->S[1] -= state->S[2];

    }
}

void zander3_load_block(struct zander3_state *state, uint8_t *block) {
    state->S[0] = ((uint64_t)block[0] << 56) + ((uint64_t)block[1] << 48) + ((uint64_t)block[2] << 40) + ((uint64_t)block[3] << 32) + ((uint64_t)block[4] << 24) + ((uint64_t)block[5] << 16) + ((uint64_t)block[6] << 8) + (uint64_t)block[7];
    state->S[1] = ((uint64_t)block[8] << 56) + ((uint64_t)block[9] << 48) + ((uint64_t)block[10] << 40) + ((uint64_t)block[11] << 32) + ((uint64_t)block[12] << 24) + ((uint64_t)block[13] << 16) + ((uint64_t)block[14] << 8) + (uint64_t)block[15];
    state->S[2] = ((uint64_t)block[16] << 56) + ((uint64_t)block[17] << 48) + ((uint64_t)block[18] << 40) + ((uint64_t)block[19] << 32) + ((uint64_t)block[20] << 24) + ((uint64_t)block[21] << 16) + ((uint64_t)block[22] << 8) + (uint64_t)block[23];
    state->S[3] = ((uint64_t)block[24] << 56) + ((uint64_t)block[25] << 48) + ((uint64_t)block[26] << 40) + ((uint64_t)block[27] << 32) + ((uint64_t)block[28] << 24) + ((uint64_t)block[29] << 16) + ((uint64_t)block[30] << 8) + (uint64_t)block[31];
}

void zander3_unload_block(struct zander3_state *state, uint8_t *block) {
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

void zander3_load_iv(struct zander3_state *state, uint8_t *iv) {
    state->last[0] = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    state->last[1] = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];
    state->last[2] = ((uint64_t)iv[16] << 56) + ((uint64_t)iv[17] << 48) + ((uint64_t)iv[18] << 40) + ((uint64_t)iv[19] << 32) + ((uint64_t)iv[20] << 24) + ((uint64_t)iv[21] << 16) + ((uint64_t)iv[22] << 8) + (uint64_t)iv[23];
    state->last[3] = ((uint64_t)iv[24] << 56) + ((uint64_t)iv[25] << 48) + ((uint64_t)iv[26] << 40) + ((uint64_t)iv[27] << 32) + ((uint64_t)iv[28] << 24) + ((uint64_t)iv[29] << 16) + ((uint64_t)iv[30] << 8) + (uint64_t)iv[31];
}

void zander3_cbc_last(struct zander3_state *state) {
    state->S[0] ^= state->last[0];
    state->S[1] ^= state->last[1];
    state->S[2] ^= state->last[2];
    state->S[3] ^= state->last[3];
}

void zander3_cbc_next(struct zander3_state *state) {
    state->last[0] = state->S[0];
    state->last[1] = state->S[1];
    state->last[2] = state->S[2];
    state->last[3] = state->S[3];
}

void zander3_cbc_next_inv(struct zander3_state *state) {
    state->next[0] = state->S[0];
    state->next[1] = state->S[1];
    state->next[2] = state->S[2];
    state->next[3] = state->S[3];
}

void zander3_cbc_last_inv(struct zander3_state *state) {
    state->last[0] = state->next[0];
    state->last[1] = state->next[1];
    state->last[2] = state->next[2];
    state->last[3] = state->next[3];
}
