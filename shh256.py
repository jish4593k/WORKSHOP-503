import struct
import hashlib

class SHA256:
    def __init__(self):
        self.sha256_k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        self.SHA224_256_BLOCK_SIZE = 64
        self.DIGEST_SIZE = 32
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        self.block = bytearray(2 * self.SHA224_256_BLOCK_SIZE)
        self.len = 0
        self.tot_len = 0

    def _sha256_transform(self, block):
        w = [0] * 64
        wv = [0] * 8
        t1, t2 = 0, 0
        sub_block = bytearray(64)
        i, j = 0, 0

        for i in range(0, 64, 4):
            w[j] = struct.unpack('>I', block[i:i + 4])[0]
            j += 1

        for j in range(16, 64):
            w[j] = self._sha256_f4(w[j - 2]) + w[j - 7] + self._sha256_f3(w[j - 15]) + w[j - 16]

        for i in range(8):
            wv[i] = self.h[i]

        for j in range(64):
            t1 = wv[7] + self._sha256_f2(wv[4]) + self._sha256_ch(wv[4], wv[5], wv[6]) + self.sha256_k[j] + w[j]
            t2 = self._sha256_f1(wv[0]) + self._sha256_maj(wv[0], wv[1], wv[2])
            wv[7], wv[6], wv[5], wv[4], wv[3], wv[2], wv[1], wv[0] = wv[6], wv[5], wv[4], wv[3] + t1, wv[2], wv[1], wv[0], t1 + t2

        for i in range(8):
            self.h[i] += wv[i]

    def _rotr(self, x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def _sha256_ch(self, x, y, z):
        return ((x & y) ^ (~x & z)) & 0xFFFFFFFF

    def _sha256_maj(self, x, y, z):
        return ((x & y) ^ (x & z) ^ (y & z)) & 0xFFFFFFFF

    def _sha256_f1(self, x):
        return (self._rotr(x, 2) ^ self._rotr(x, 13) ^ self._rotr(x, 22)) & 0xFFFFFFFF

    def _sha256_f2(self, x):
        return (self._rotr(x, 6) ^ self._rotr(x, 11) ^ self._rotr(x, 25)) & 0xFFFFFFFF

    def _sha256_f3(self, x):
        return (self._rotr(x, 7) ^ self._rotr(x, 18) ^ (x >> 3)) & 0xFFFFFFFF

    def _sha256_f4(self, x):
        return (self._rotr(x, 17) ^ self._rotr(x, 19) ^ (x >> 10)) & 0xFFFFFFFF

    def update(self, message):
        message_len = len(message)
        index = 0
        self.tot_len += message_len

        while index < message_len:
            self.block[self.len] = message[index]
            self.len += 1
            index += 1

            if self.len == self.SHA224_256_BLOCK_SIZE:
                self._sha256_transform(self.block)
                self.block = bytearray(2 * self.SHA224_256_BLOCK_SIZE)
                self.len = 0

    def final(self):
        padding_len = self.SHA224_256_BLOCK_SIZE - self.len
        if padding_len <= 8:
            padding_len += self.SHA224_256_BLOCK_SIZE

        self.block[self.len] = 0x80
        self.len += 1

        self.block[self.SHA224_256_BLOCK_SIZE - 8:self.SHA224_256_BLOCK_SIZE] = struct.pack('>Q', self.tot_len * 8)

        self._sha256_transform(self.block)

        digest = bytearray(32)
        for i in range(8):
            digest[i * 4:i * 4 + 4] = struct.pack('>I', self.h[i])

        return digest

def sha256(input_string):
    sha256_hash = SHA256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.final()
