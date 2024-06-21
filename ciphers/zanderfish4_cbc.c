/*  ZanderFish4 */
/* by KryptoMagick (Karl Zander) */
/* Key lengths (128/256) bit */
/* 128 bit block size */
/* 56 rounds for 128 bits */
/* 64 rounds for 256 bits */

uint64_t zanderfish4_c0[4] = {0xc930a011903b456e, 0xbf7eb1f5d119a477, 0xfd0c814081b3fcfd, 0x853064b0a89aecbd};

struct zanderfish4_state {
    uint64_t K[64][2];
    uint64_t D[2];
    uint64_t S[2];
    uint64_t last[2];
    uint64_t next[2];
    int rounds;
};

struct z4ksa_state {
    uint64_t r[4];
    uint64_t o;
};

uint64_t zanderfish4_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t zanderfish4_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void zanderfish4_ksa_update(struct z4ksa_state *state) {
    state->r[0] ^= zanderfish4_rotl(state->r[3], 1) + state->r[2];
    state->r[1] += zanderfish4_rotl(state->r[0], 3) ^ state->r[3];
    state->r[2] ^= zanderfish4_rotl(state->r[1] + state->r[0], 6);
    state->r[3] += zanderfish4_rotl(state->r[2] ^ state->r[1], 11);

    state->o = 0;
    state->o ^= state->r[0];
    state->o ^= state->r[1];
    state->o ^= state->r[2];
    state->o ^= state->r[3];
}

uint64_t zanderfish4_F(uint64_t right) {
    uint8_t t[8];
    t[0] = (right & 0xFF00000000000000) >> 56;
    t[1] = (right & 0x00FF000000000000) >> 48;
    t[2] = (right & 0x0000FF0000000000) >> 40;
    t[3] = (right & 0x000000FF00000000) >> 32;
    t[4] = (right & 0x00000000FF000000) >> 24;
    t[5] = (right & 0x0000000000FF0000) >> 16;
    t[6] = (right & 0x000000000000FF00) >> 8;
    t[7] = (right & 0x00000000000000FF);
    t[1] += t[3];
    t[3] += t[5];
    t[5] += t[7];
    t[0] += t[2];
    t[2] += t[4];
    t[4] += t[6];
    return ((uint64_t)t[0] << 56) + ((uint64_t)t[1] << 48) + ((uint64_t)t[2] << 40) + ((uint64_t)t[3] << 32) + ((uint64_t)t[4] << 24) + ((uint64_t)t[5] << 16) + ((uint64_t)t[6] << 8) + (uint64_t)t[7];
    
}

void zanderfish4_ksa(struct zanderfish4_state * state, uint8_t * key, int keylen) {
    struct z4ksa_state kstate;
    int c = 0;
    int i, s;
    state->rounds = 64;
    memset(state->K, 0, state->rounds*(2*sizeof(uint64_t)));
    memset(&kstate.r, 0, 4*sizeof(uint64_t));
    memset(&kstate.o, 0, sizeof(uint64_t));
    kstate.r[0] = zanderfish4_c0[0];
    kstate.r[1] = zanderfish4_c0[1];
    kstate.r[2] = zanderfish4_c0[2];
    kstate.r[3] = zanderfish4_c0[3];

    for (i = 0; i < (keylen / 8); i++) {
        kstate.r[i] ^= ((uint64_t)key[c] << 56) + ((uint64_t)key[c+1] << 48) + ((uint64_t)key[c+2] << 40) + ((uint64_t)key[c+3] << 32) + ((uint64_t)key[c+4] << 24) + ((uint64_t)key[c+5] << 16) + ((uint64_t)key[c+6] << 8) + (uint64_t)key[c+7];
        c += 8;
    }
    for (i = 0; i < state->rounds; i++) {
        for (s = 0; s < 2; s++) {
            zanderfish4_ksa_update(&kstate);
            state->K[i][s] = kstate.o;
        }
    }
    for (s = 0; s < 2; s++) {
        zanderfish4_ksa_update(&kstate);
        state->D[s] = kstate.o;
    }
}

void zanderfish4_encrypt_block(struct zanderfish4_state * state) {
    uint64_t temp;
    for (int r = 0; r < state->rounds; r++) {

        state->S[0] ^= zanderfish4_F(state->S[1]);
        state->S[0] = zanderfish4_rotl(state->S[0], 14);
        state->S[0] += state->S[1];
        state->S[0] ^= state->K[r][0];
        state->S[1] += state->S[0];
        state->S[1] = zanderfish4_rotr(state->S[1], 17);
        state->S[1] ^= state->K[r][1];
        state->S[0] ^= state->S[1];
        state->S[1] ^= state->S[0];

        temp = state->S[1];
        state->S[1] = state->S[0];
        state->S[0] = temp;

    }
    state->S[0] ^= state->D[0];
    state->S[1] ^= state->D[1];
}

void zanderfish4_decrypt_block(struct zanderfish4_state * state) {
    uint64_t temp;

    state->S[1] ^= state->D[1];
    state->S[0] ^= state->D[0];

    for (int r = (state->rounds - 1); r != -1; r--) {

        temp = state->S[1];
        state->S[1] = state->S[0];
        state->S[0] = temp;

        state->S[1] ^= state->S[0];
        state->S[0] ^= state->S[1];
        state->S[1] ^= state->K[r][1];
        state->S[1] = zanderfish4_rotl(state->S[1], 17);
        state->S[1] -= state->S[0];
        state->S[0] ^= state->K[r][0];
        state->S[0] -= state->S[1];
        state->S[0] = zanderfish4_rotr(state->S[0], 14);
        state->S[0] ^= zanderfish4_F(state->S[1]);

    }
}

void zanderfish4_load_block(struct zanderfish4_state *state, uint8_t *block) {
    state->S[0] = ((uint64_t)block[0] << 56) + ((uint64_t)block[1] << 48) + ((uint64_t)block[2] << 40) + ((uint64_t)block[3] << 32) + ((uint64_t)block[4] << 24) + ((uint64_t)block[5] << 16) + ((uint64_t)block[6] << 8) + (uint64_t)block[7];
    state->S[1] = ((uint64_t)block[8] << 56) + ((uint64_t)block[9] << 48) + ((uint64_t)block[10] << 40) + ((uint64_t)block[11] << 32) + ((uint64_t)block[12] << 24) + ((uint64_t)block[13] << 16) + ((uint64_t)block[14] << 8) + (uint64_t)block[15];
}

void zanderfish4_unload_block(struct zanderfish4_state *state, uint8_t *block) {
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
}

void zanderfish4_load_iv(struct zanderfish4_state *state, uint8_t *iv) {
    state->last[0] = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    state->last[1] = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];
}

void zanderfish4_cbc_last(struct zanderfish4_state *state) {
    state->S[0] ^= state->last[0];
    state->S[1] ^= state->last[1];
}

void zanderfish4_cbc_next(struct zanderfish4_state *state) {
    state->last[0] = state->S[0];
    state->last[1] = state->S[1];
}

void zanderfish4_cbc_next_inv(struct zanderfish4_state *state) {
    state->next[0] = state->S[0];
    state->next[1] = state->S[1];
}

void zanderfish4_cbc_last_inv(struct zanderfish4_state *state) {
    state->last[0] = state->next[0];
    state->last[1] = state->next[1];
}
