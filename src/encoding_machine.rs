#[allow(dead_code)]
pub struct EncodingMachine {
    buffer: u8,
    cnt: u8,
    pool: Vec<char>,
    dc_offset: i8
}

#[allow(dead_code)]
impl EncodingMachine {

    pub fn new() -> EncodingMachine {
        let pool = Vec::new();
        EncodingMachine { buffer: 0, cnt: 0, pool, dc_offset: 0 }
    }

    pub fn inject(&mut self, bit: u8) {
        self.buffer = (self.buffer << 1) | bit;
        self.cnt += 1;

        if self.cnt == 4 {
            let c: [char; 3] = self.encode_buffer();
            self.pool.insert(0, c[2]);
            self.pool.insert(0, c[1]);
            self.pool.insert(0, c[0]);
            self.cnt = 0;
            self.buffer = 0;
        }
    }

    fn encode_buffer(&mut self) -> [char; 3] {
        match self.buffer {
            0b0000 => {
                if self.dc_offset >= 0 {
                    self.dc_offset -= 1;
                    ['0','-','0']
                } else {
                    self.dc_offset += 2;
                    ['+','0','+']
                }
            },
            0b0001 => ['0','-','+'],
            0b0010 => ['+','-','0'],
            0b0011 => {
                if self.dc_offset < 2 {
                    self.dc_offset += 1;
                    ['0','0','+']
                } else {
                    self.dc_offset -= 2;
                    ['-','-','0']
                }
            },
            0b0100 => ['-','+','0'],
            0b0101 => {
                if self.dc_offset == -1 {
                    self.dc_offset += 2;
                    ['0','+','+']
                } else {
                    self.dc_offset -= 1;
                    ['-','0','0']
                }
            },
            0b0110 => {
                if self.dc_offset <= 0 {
                    self.dc_offset += 1;
                    ['-','+','+']
                } else {
                    self.dc_offset -= 1;
                    ['-','-','+']
                }
            },
            0b0111 => ['-','0','+'],
            0b1000 => {
                if self.dc_offset == 2 {
                    self.dc_offset -= 2;
                    ['0','-','-']
                } else {
                    self.dc_offset += 1;
                    ['+','0','0']
                }
            },
            0b1001 => {
                if self.dc_offset == 2 {
                    self.dc_offset -= 3;
                    ['-','-','-']
                } else {
                    self.dc_offset += 1;
                    ['+','-','+']
                }
            },
            0b1010 => {
                if self.dc_offset >= 1 {
                    self.dc_offset -= 1;
                    ['+','-','-']
                } else {
                    self.dc_offset += 1;
                    ['+','+','-']
                }
            },
            0b1011 => ['+','0','-'],
            0b1100 => {
                if self.dc_offset == -1 {
                    self.dc_offset += 3;
                    ['+', '+', '+']
                } else {
                    self.dc_offset -= 1;
                    ['-','+','-']
                }
            },
            0b1101 => {
                if self.dc_offset < 2 {
                    self.dc_offset += 1;
                    ['0','+','0']
                } else {
                    self.dc_offset -= 2;
                    ['-','0','-']
                }
            },
            0b1110 => ['0','+','-'],
            0b1111 => {
                if self.dc_offset >= 0 {
                    self.dc_offset -= 1;
                    ['0','0','-']
                } else {
                    self.dc_offset += 2;
                    ['+','+','0']
                }
            },
            _ => ['x','x','x']
        }
    }

    pub fn extract(&mut self) -> char {
        let x = self.pool.pop().unwrap_or('x');
        //print!("{}", x);
        x
    }
}