// Made by Aydon Fauscett

function rotate(v, c) {
    return (v << c) >>> 0 | v >>> (32 - c);
}

function quarterRound(x, a, b, c, d) {
    x[a] = (x[a] + x[b]) >>> 0;
    x[d] = rotate(x[d] ^ x[a], 16);

    x[c] = (x[c] + x[d]) >>> 0;
    x[b] = rotate(x[b] ^ x[c], 12);

    x[a] = (x[a] + x[b]) >>> 0;
    x[d] = rotate(x[d] ^ x[a], 8);

    x[c] = (x[c] + x[d]) >>> 0;
    x[b] = rotate(x[b] ^ x[c], 7);
}

function chacha20Block(key, counter, iv) {
    const constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    
    const keySt = [];
    for (let i = 0; i < key.length; i += 4) {
        keySt.push(key.readUInt32LE(i));
    }

    const ivSt = [];
    for (let i = 0; i < iv.length; i += 4) {
        ivSt.push(iv.readUInt32LE(i));
    }

    const state = [...constants, ...keySt, counter, ...ivSt];
    let workingState = state.slice();

    for (let i = 0; i < 10; i++) {
        quarterRound(workingState, 0, 4, 8, 12);
        quarterRound(workingState, 1, 5, 9, 13);
        quarterRound(workingState, 2, 6, 10, 14);
        quarterRound(workingState, 3, 7, 11, 15);
        quarterRound(workingState, 0, 5, 10, 15);
        quarterRound(workingState, 1, 6, 11, 12);
        quarterRound(workingState, 2, 7, 8, 13);
        quarterRound(workingState, 3, 4, 9, 14);
    }

    const result = Buffer.alloc(64);
    for (let i = 0; i < 16; i++) {
        result.writeUInt32LE((workingState[i] + state[i]) >>> 0, i * 4);
    }
    
    return result;
}

function chachaEncrypt(key, counter, iv, plaintext) {
    let encrypted = Buffer.alloc(0);
    const blockSize = 64;
    
    for (let i = 0; i < plaintext.length; i += blockSize) {
        const block = chacha20Block(key, counter, iv);
        const toEncrypt = plaintext.slice(i, i + blockSize);
        const encryptedBlock = Buffer.from(
            toEncrypt.map((byte, idx) => byte ^ block[idx])
        );
        encrypted = Buffer.concat([encrypted, encryptedBlock]);
        counter += 1;
    }
    
    return encrypted;
}

function poly1305KeyGen(key, iv) {
    return chacha20Block(key, 0, iv).slice(0, 32);
}

function clampR(r) {
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
}

function poly1305Mac(key, msg) {
    let r = Array.from(key.slice(0, 16));
    clampR(r);
    const s = BigInt(key.readUInt32LE(16));

    const p = BigInt('0x3fffffffffffffffffffffffffffffffb');
    let acc = 0n;

    for (let i = 0; i < msg.length; i += 16) {
        const block = Buffer.concat([msg.slice(i, i + 16), Buffer.from([1])]);
        const n = BigInt('0x' + block.reverse().toString('hex'));  // Ensure little-endian
        const rVal = BigInt('0x' + Buffer.from(r).reverse().toString('hex')); // Ensure little-endian
        acc = (acc + n) * rVal % p;
    }

    acc = (acc + s) % (1n << 128n);

    const accBuf = Buffer.alloc(16);
    accBuf.writeBigUInt64LE(acc & BigInt('0xffffffffffffffff'), 0);
    accBuf.writeBigUInt64LE(acc >> 64n, 8);

    return accBuf;
}


function pad16(data) {
    if (data.length % 16 !== 0) {
        return Buffer.concat([data, Buffer.alloc(16 - (data.length % 16), 0)]);
    }
    return data;
}

function encrypt(key, iv, plaintext, aad) {
    key = Buffer.from(key, 'utf-8');
    aad = Buffer.from(aad, 'utf-8');
    iv = Buffer.from(iv, 'utf-8');
    let counter = 1;
    
    const ciphertext = chachaEncrypt(key, counter, iv, plaintext);
    
    const polyKey = poly1305KeyGen(key, iv);

    const aadLen = Buffer.alloc(8);
    aadLen.writeUInt32LE(aad.length, 0);
    const ciphertextLen = Buffer.alloc(8);
    ciphertextLen.writeUInt32LE(ciphertext.length, 0);

    const macData = Buffer.concat([pad16(aad), pad16(ciphertext), aadLen, ciphertextLen]);
    
    const tag = poly1305Mac(polyKey, macData).toString('hex');
    
    return { ciphertext, tag };
}

function decrypt(key, iv, ciphertext, aad, tag) {
    key = Buffer.from(key, 'utf-8');
    aad = Buffer.from(aad, 'utf-8');
    iv = Buffer.from(iv, 'utf-8');
    tag = Buffer.from(tag, 'hex');
    let counter = 1;
    const polyKey = poly1305KeyGen(key, iv);

    const aadLen = Buffer.alloc(8);
    aadLen.writeUInt32LE(aad.length, 0);
    const ciphertextLen = Buffer.alloc(8);
    ciphertextLen.writeUInt32LE(ciphertext.length, 0);

    const macData = Buffer.concat([pad16(aad), pad16(ciphertext), aadLen, ciphertextLen]);
    const plaintext = chachaEncrypt(key, counter, iv, ciphertext);
    
    if (!poly1305Mac(polyKey, macData).equals(tag)) {
        const warning = "Tag authentication failed. Data may be corrupt or tampered with.";
        return { plaintext, warning };
    }
    
    return { plaintext };
}

/* All of the code below is for testing. */

const crypto = require('crypto'); // For comparison with Node.js built-in crypto

function testChaCha20Poly1305() {
    const key = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'); // 32-byte key
    const iv = Buffer.from('000000000000000000000000', 'hex');       // 12-byte IV
    const plaintext = Buffer.from('This is a test message.', 'utf-8'); // Plaintext
    const aad = Buffer.from('Additional authenticated data.', 'utf-8'); // AAD

    const { ciphertext, tag } = encrypt(key, iv, plaintext, aad);

    console.log('Ciphertext:', ciphertext.toString('hex'));
    console.log('Tag:', tag);

    const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv);
    cipher.setAAD(aad);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tagCrypto = cipher.getAuthTag();

    console.log('Ciphertext (crypto):', encrypted.toString('hex'));
    console.log('Tag (crypto):', tagCrypto.toString('hex'));

    const { plaintext: decryptedText, warning } = decrypt(key, iv, ciphertext, aad, tag);

    console.log('Decrypted plaintext:', decryptedText.toString('utf-8'));

    if (warning) {
        console.warn(warning);
    }
}

// Run the test
testChaCha20Poly1305();
