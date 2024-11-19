use crate::encoding_machine::EncodingMachine;

const ID: u32 = 0x0deadbeef;

#[allow(dead_code)]
pub struct Cipher {
    lfsr: u64,
    encoder: EncodingMachine
}

#[allow(dead_code)]
impl Cipher {

    pub fn new(k: u64, nonce: u32) -> Cipher {
        let mut lfsr: u64 = 0;

        lfsr |= ID as u64;
        lfsr <<= 16;
        lfsr &= 0xffffffffffff;
        lfsr |= ((k >> 32) & 0xffff) as u64;

        lfsr <<= 32;
        lfsr &= 0xffffffffffff;
        lfsr |= k & 0xffffffff;
        lfsr ^= nonce as u64;
        
        Cipher { lfsr, encoder: EncodingMachine::new() }
    }

    #[inline(always)]
    fn get_bit(&self, i: u8) -> u8 {
        ((self.lfsr >> (47 - i)) & 1) as u8
    }

    fn keystream_bit(&mut self) -> u8 {
        let out = fc(
            fa(
                self.get_bit(2),
                self.get_bit(3),
                self.get_bit(5),
                self.get_bit(6)
            ),
            fb(
                self.get_bit(8),
                self.get_bit(12),
                self.get_bit(14),
                self.get_bit(15)
            ),
            fb(
                self.get_bit(17),
                self.get_bit(21),
                self.get_bit(23),
                self.get_bit(26)
            ),
            fb(
                self.get_bit(28),
                self.get_bit(29),
                self.get_bit(31),
                self.get_bit(33)
            ),
            fa(
                self.get_bit(34),
                self.get_bit(43),
                self.get_bit(44),
                self.get_bit(46)
            )
        );

        let next = self.get_bit(0)
            ^ self.get_bit(2)
            ^ self.get_bit(3)
            ^ self.get_bit(6)
            ^ self.get_bit(7)
            ^ self.get_bit(8)
            ^ self.get_bit(16)
            ^ self.get_bit(22)
            ^ self.get_bit(23)
            ^ self.get_bit(26)
            ^ self.get_bit(30)
            ^ self.get_bit(41)
            ^ self.get_bit(42)
            ^ self.get_bit(43)
            ^ self.get_bit(46)
            ^ self.get_bit(47);
        self.encoder.inject(self.get_bit(41));
        self.lfsr <<= 1;
        self.lfsr &= 0xffffffffffff;
        self.lfsr |= next as u64;
        out
    }

    pub fn get_keystream(&mut self, byte_len: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut buff: u16 = 0;

        loop {
            let mut bit = self.keystream_bit();
            buff = (buff << 1) | bit as u16;
            bit = self.keystream_bit();
            buff = (buff << 1) | bit as u16;
            bit = self.keystream_bit();
            buff = (buff << 1) | bit as u16;
            bit = self.keystream_bit();
            buff = (buff << 1) | bit as u16;
            let char = self.encoder.extract() as u8;
            buff = (buff << 8) | char as u16;
            bit = self.keystream_bit();
            buff = (buff << 1) | bit as u16;
            bit = self.keystream_bit();
            buff = (buff << 1) | bit as u16;
            bit = self.keystream_bit();
            buff = (buff << 1) | bit as u16;
            bit = self.keystream_bit();
            buff = (buff << 1) | bit as u16;
            
            out.push((buff >> 8) as u8);
            out.push((buff & 0xff) as u8);
            buff = 0;
            out.push(self.encoder.extract() as u8);
           
            if out.len() >= byte_len {
                break;
            }
        }
        out.truncate(byte_len);
        out
    }

}

#[inline(always)]
fn fa(x1: u8, x2: u8, x3: u8, x4: u8) -> u8 {
    let x = (x1 << 3) ^ (x2 << 2) ^ (x3 << 1) ^ x4;
    let sbox: [u8; 16] = [1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0];
    sbox[x as usize]
}

#[inline(always)]
fn fb(x1: u8, x2: u8, x3: u8, x4: u8) -> u8 {
    let x = (x1 << 3) ^ (x2 << 2) ^ (x3 << 1) ^ x4;
    let sbox: [u8; 16] = [1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1];
    sbox[x as usize]
}

#[inline(always)]
fn fc(x1: u8, x2: u8, x3: u8, x4: u8, x5: u8) -> u8 {
    let x = (x1 << 4) ^ (x2 << 3) ^ (x3 << 2) ^ (x4 << 1) ^ x5;
    let sbox: [u8; 32] = [0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0];
    sbox[x as usize]
}
