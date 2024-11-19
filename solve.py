from bitarray import bitarray

decode_mms43 = {
    b'+0+': '0000',
    b'0-0': '0000',
    b'0-+': '0001',
    b'+-0': '0010',
    b'00+': '0011',
    b'--0': '0011',
    b'-+0': '0100',
    b'0++': '0101',
    b'-00': '0101',
    b'-++': '0110',
    b'--+': '0110',
    b'-0+': '0111',
    b'+00': '1000',
    b'0--': '1000',
    b'+-+': '1001',
    b'---': '1001',
    b'++-': '1010',
    b'+--': '1010',
    b'+0-': '1011',
    b'+++': '1100',
    b'-+-': '1100',
    b'0+0': '1101',
    b'-0-': '1101',
    b'0+-': '1110',
    b'++0': '1111',
    b'00-': '1111'
}

class MMS43Encoder:
    cnt = 0
    buffer = 0
    dc_offset = 0

    def __init__(self):
        self.pool = []

    def inject(self, bit):
        self.buffer = (self.buffer << 1) | bit;
        self.cnt += 1;

        if self.cnt == 4:
            c = self.encode_buffer();
            self.pool.insert(0, c[2]);
            self.pool.insert(0, c[1]);
            self.pool.insert(0, c[0]);
            self.cnt = 0;
            self.buffer = 0;

    def extract(self):
        x = self.pool.pop()
        #print(f"extracting: {x.decode()}")
        return x[0]

    

    def encode_buffer(self):
        if self.buffer == 0b0000:
            if self.dc_offset >= 0:
                self.dc_offset -= 1
                return [b'0',b'-',b'0']
            else:
                self.dc_offset += 2
                return [b'+',b'0',b'+']
        elif self.buffer == 0b0001:
            return [b'0',b'-',b'+']
        elif self.buffer == 0b0010:
            return [b'+',b'-',b'0']
        elif self.buffer == 0b0011:
            if self.dc_offset < 2:
                self.dc_offset += 1
                return [b'0',b'0',b'+']
            else:
                self.dc_offset -= 2
                return [b'-',b'-',b'0']
        elif self.buffer == 0b0100:
            return [b'-',b'+',b'0']
        elif self.buffer == 0b0101:
            if self.dc_offset == -1:
                self.dc_offset += 2
                return [b'0',b'+',b'+']
            else:
                self.dc_offset -= 1
                return [b'-',b'0',b'0']
        elif self.buffer == 0b0110:
            if self.dc_offset <= 0:
                self.dc_offset += 1
                return [b'-',b'+',b'+']
            else:
                self.dc_offset -= 1
                return [b'-',b'-',b'+']
        elif self.buffer == 0b0111:
            return [b'-',b'0',b'+']
        elif self.buffer == 0b1000:
            if self.dc_offset == 2:
                self.dc_offset -= 2
                return [b'0',b'-',b'-']
            else:
                self.dc_offset += 1
                return [b'+',b'0',b'0']
        elif self.buffer == 0b1001:
            if self.dc_offset == 2:
                self.dc_offset -= 3
                return [b'-',b'-',b'-']
            else:
                self.dc_offset += 1
                return [b'+',b'-',b'+']
        elif self.buffer == 0b1010:
            if self.dc_offset >= 1:
                self.dc_offset -= 1
                return [b'+',b'-',b'-']
            else:
                self.dc_offset += 1
                return [b'+',b'+',b'-']
        elif self.buffer == 0b1011:
            return [b'+',b'0',b'-']
        elif self.buffer == 0b1100:
            if self.dc_offset == -1:
                self.dc_offset += 3
                return [b'+',b'+',b'+']
            else:
                self.dc_offset -= 1
                return [b'-',b'+',b'-']
        elif self.buffer == 0b1101:
            if self.dc_offset < 2:
                self.dc_offset += 1
                return [b'0',b'+',b'0']
            else:
                self.dc_offset -= 2
                return [b'-',b'0',b'-']
        elif self.buffer == 0b1110:
            return [b'0',b'+',b'-']
        elif self.buffer == 0b1111:
            if self.dc_offset >= 0:
                self.dc_offset -= 1
                return [b'0',b'0',b'-']
            else:
                self.dc_offset += 2
                return [b'+',b'+',b'0']


plaintext = b"ptm{m4yb3_d1z?__https://www.youtube.com/watch?v=S8z9mgIkqBA}"
ciphertext = bytes.fromhex("237d4019d71fda61037c631c5930743db95f977c5898fa1f24735a8d7f4487a85841611e20655d7dcc4cb6d7580dcc0d51ee51cbbf4c6a695af1454d")
nonce = 1510137493

flag = "ptm{this_should_be_actually_working}"
flag_nonce = 2896002489
flag_ciphertext = bytes.fromhex("e2c95d19a845da7074e0634206664f6db84e7db64826c1519eb949cc7444b16b42cd6f50")


# recover keystream from plaintext and ciphertext
assert len(plaintext) == len(ciphertext)
keystream = bytes([p ^ c for p, c in zip(plaintext, ciphertext)])

# recover encoded state bits
keystream_bits = bitarray(''.join([bin(c)[2:].zfill(8) for c in keystream]))
encoded_state = bytes([])
for _ in range(0, len(keystream_bits), 12):
    keystream_bits <<= 4
    encoded_state += keystream_bits[:8].tobytes()
    keystream_bits <<= 8

# check enough bits of state are leaked
assert len(encoded_state) // 3 * 4 >= 48

# reverse each group of 3 symbols and build bitarray decoding MMS43
encoded_state = [encoded_state[i:i+3][::-1] for i in range(0, len(encoded_state), 3)]
if len(encoded_state[-1]) < 3:
    encoded_state = encoded_state[:-1]

leaked_state = bitarray(''.join([decode_mms43[s] for s in encoded_state]))[:48]

# recover initial state
def next_bit(state: bitarray):
    return (
        state[2] ^ state[3] ^ state[6] ^ state[7] ^ state[8]
        ^ state[16] ^ state[22] ^ state[23] ^ state[26] ^ state[30] ^ state[41]
        ^ state[42] ^ state[43] ^ state[46] ^ state[47] ^ state[0]
    )


def rollback_bit(state: bitarray):
    return (
        state[1] ^ state[2] ^ state[5] ^ state[6] ^ state[7]
        ^ state[15] ^ state[21] ^ state[22] ^ state[25] ^ state[29] ^ state[40]
        ^ state[41] ^ state[42] ^ state[45] ^ state[46] ^ state[47]
    )

initial_state = leaked_state.copy()
for _ in range(41):
    recovered_bit = rollback_bit(initial_state)
    initial_state = bitarray(bin(recovered_bit)[2:]) + initial_state[:-1]

i = 0
for bit in initial_state:
    i = (i << 1) | bit

key_recovered = i ^ nonce

# decrypt flag
lfsr = bitarray(bin(key_recovered ^ flag_nonce)[2:].zfill(48))
keystream_bits = bitarray()
encoder = MMS43Encoder()


def fa(state: bitarray, idxs: list):
    box = [1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0]
    num = state[idxs[0]] << 3 ^ state[idxs[1]] << 2 ^ state[idxs[2]] << 1 ^ state[idxs[3]]
    return box[num]

def fb(state: bitarray, idxs: list):
    box = [1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1]
    num = state[idxs[0]] << 3 ^ state[idxs[1]] << 2 ^ state[idxs[2]] << 1 ^ state[idxs[3]]
    return box[num]

def fc(state: bitarray, idxs: list):
    box = [0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0]
    num = state[idxs[0]] << 4 ^ state[idxs[1]] << 3 ^ state[idxs[2]] << 2 ^ state[idxs[3]] << 1 ^ state[idxs[4]]
    return box[num]


def keystream_bit(state: bitarray):
    out = fc([
        fa(state, [2,3,5,6]),
        fb(state, [8,12,14,15]),
        fb(state, [17,21,23,26]),
        fb(state, [28,29,31,33]),
        fa(state, [34,43,44,46])
    ], [0,1,2,3,4])
    next = next_bit(state)
    encoder.inject(state[41])
    state = state[1:] + bitarray(bin(next)[2:])
    return out, state

buff = 0
while(True):
    bit, lfsr = keystream_bit(lfsr)
    buff = (buff << 1) | bit
    bit, lfsr = keystream_bit(lfsr)
    buff = (buff << 1) | bit
    bit, lfsr = keystream_bit(lfsr)
    buff = (buff << 1) | bit
    bit, lfsr = keystream_bit(lfsr)
    buff = (buff << 1) | bit
    buff = (buff << 8) | encoder.extract()
    bit, lfsr = keystream_bit(lfsr)
    buff = (buff << 1) | bit
    bit, lfsr = keystream_bit(lfsr)
    buff = (buff << 1) | bit
    bit, lfsr = keystream_bit(lfsr)
    buff = (buff << 1) | bit
    bit, lfsr = keystream_bit(lfsr)
    buff = (buff << 1) | bit
    keystream_bits += bitarray(bin(buff)[2:].zfill(16))
    buff = 0
    keystream_bits += bitarray(bin(encoder.extract())[2:].zfill(8))

    if len(keystream_bits) >= len(flag_ciphertext) * 8:
        break

keystream_bits = keystream_bits[:len(flag_ciphertext) * 8]
flag_plaintext = bytes([p ^ c for p, c in zip(flag_ciphertext, keystream_bits.tobytes())])
print(flag_plaintext.decode())