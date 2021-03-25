from os import system
import preprocessing as pr
import numpy as np



def rotr(n, k):
    for i in range(0,k):
    	bit = np.uint32(n & 0x00000001)
    	n >>= np.uint32(1)
    	n |= bit << np.uint32(31)
    return n

def SHA256(password):
	password = password.encode('utf-8')
	password = pr.Pre_processing(password)
	password = pr.cut(password)
	rows = len(password)
	cols = 64
	s = []
	w = [[0 for col in range(cols)] for row in range(rows)]
	data = str(rows)

	for _ in range(rows):
		password[_]  = pr.cut(password[_], 32)
		for i in range(len(password[_])):
			password[_][i] = int(password[_][i], base=2)
			data += ' ' + str(password[_][i])
			s.append(password[_][i])

	for i in range(rows):
		for j in range(16):
			w[i][j] = np.uint32(s[i*16 + j])

	H = np.array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19], dtype=np.uint32)

	k = np.array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
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
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2], dtype=np.uint32)

	for j in range(rows):
		for i in range(16, 64):
			s0 = np.uint32(rotr(w[j][i-15], 7) ^ rotr(w[j][i-15], 18) ^ (w[j][i-15] >> 3)) % 4294967296
			s1 = np.uint32(rotr(w[j][i-2], 17) ^ rotr(w[j][i-2], 19) ^ (w[j][i-2] >> 10)) % 4294967296
			w[j][i] = (w[j][i-16] + s0 + w[j][i-7] + s1) % 4294967296
		a = np.uint32(H[0])
		b = np.uint32(H[1])
		c = np.uint32(H[2])
		d = np.uint32(H[3])
		e = np.uint32(H[4])
		f = np.uint32(H[5])
		g = np.uint32(H[6])
		h = np.uint32(H[7])

		for i in range(64):
			E0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) % 4294967296
			Ma = ((a & b) ^ (a & c) ^ (b & c)) % 4294967296
			t2 = (E0 + Ma) % 4294967296
			E1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) % 4294967296
			Ch = ((e & f) ^ ((~e) & g)) % 4294967296
			t1 = (h + E1 + Ch + k[i] + w[j][i]) % 4294967296

			h = g
			g = f
			f = e
			e = (d + t1) % 4294967296
			d = c
			c = b
			b = a
			a = (t1 + t2) % 4294967296
		H[0] = (H[0] + a) % 4294967296
		H[1] = (H[1] + b) % 4294967296
		H[2] = (H[2] + c) % 4294967296
		H[3] = (H[3] + d) % 4294967296
		H[4] = (H[4] + e) % 4294967296
		H[5] = (H[5] + f) % 4294967296
		H[6] = (H[6] + g) % 4294967296
		H[7] = (H[7] + h) % 4294967296

	digest = []
	for _ in range(8):
		digest.append(str(hex(H[_]))[2:])

	for _ in range(8):
		if len(digest[_]) < 8:
			while len(digest[_]) < 8:
				digest[_] = '0' + digest[_]

	return ''.join(digest)


if __name__ == '__main__':
	print(SHA256("feffrwgddddddddddddddddddddddddddddddddddddddd"))
	import hashlib
	m = hashlib.sha256(b"feffrwgddddddddddddddddddddddddddddddddddddddd")
	print(m.hexdigest())
	input()