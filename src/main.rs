mod cipher;
mod encoding_machine;

use cipher::Cipher;
use std::env;

fn main() {
    let mut rng = urandom::new();

    let key = rng.next::<u64>() & 0xffffffffffff;
    eprintln!("key: {}", key);

    let nonce = rng.next::<u32>();
    let mut cipher = Cipher::new(key, nonce);

    let plaintext = Vec::from("ptm{m4yb3_d1z?__https://www.youtube.com/watch?v=S8z9mgIkqBA}".as_bytes());
    let keystream = cipher.get_keystream(plaintext.len());

    // xor plaintext and keystream
    let mut ciphertext = Vec::new();
    for i in 0..plaintext.len() {
        ciphertext.push(plaintext[i] ^ keystream[i]);
    }

    println!("nonce: {}", nonce);
    print!("ciphertext: ");
    for i in 0..ciphertext.len() {
        print!("{:02x}", ciphertext[i]);
    }
    println!("");

    println!("--- and now the flag! ---");

    let flag = Vec::from(env::args().nth(1).unwrap().as_bytes());
    let flag_nonce = rng.next::<u32>();
    let mut flag_cipher = Cipher::new(key, flag_nonce);

    let flag_keystream = flag_cipher.get_keystream(flag.len());

    let mut flag_ciphertext = Vec::new();
    for i in 0..flag.len() {
        flag_ciphertext.push(flag[i] ^ flag_keystream[i]);
    }

    println!("nonce: {}", flag_nonce);
    print!("flag: ");
    for i in 0..flag_ciphertext.len() {
        print!("{:02x}", flag_ciphertext[i]);
    }
    println!("");
}
