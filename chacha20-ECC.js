const crypto = require('crypto');

class EllipticCurve {
    constructor(a, b, p) {
        this.a = BigInt(a);
        this.b = BigInt(b);
        this.p = BigInt(p);
    }

    modInverse(value, mod) {
        return this.modPow(value, mod - 2n, mod);
    }

    modPow(base, exp, mod) {
        let result = 1n;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2n === 1n) {
                result = (result * base) % mod;
            }
            exp = exp >> 1n;
            base = (base * base) % mod;
        }
        return result;
    }

    add(P, Q) {
        if (P[0] === null && P[1] === null) return Q;
        if (Q[0] === null && Q[1] === null) return P;

        let [x1, y1] = P;
        let [x2, y2] = Q;

        x1 = BigInt(x1);
        y1 = BigInt(y1);
        x2 = BigInt(x2);
        y2 = BigInt(y2);

        let m;
        if (x1 === x2 && y1 === y2) {
            m = (3n * x1 ** 2n + this.a) * this.modInverse(2n * y1, this.p) % this.p;
        } else {
            m = (y2 - y1) * this.modInverse(x2 - x1, this.p) % this.p;
        }

        let x3 = (m ** 2n - x1 - x2) % this.p;
        let y3 = (m * (x1 - x3) - y1) % this.p;

        return [x3, y3];
    }

    multiply(P, k) {
        let Q = [null, null];
        let R = P;

        k = BigInt(k);

        while (k > 0n) {
            if (k % 2n === 1n) {
                Q = this.add(Q, R);
            }
            R = this.add(R, R);
            k = k >> 1n;
        }

        return Q;
    }
}

class EllipticOperations {
    constructor() {
        this.G = [
            0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66n,
            0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650n
        ];
        this.n = 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409n;
        this.hashValues = [];
        this.k = [];
        this.initializeConstants();
    }

    initializeConstants() {
        const maxWord = Math.pow(2, 32);
        let primeCounter = this.k.length;

        const isPrime = (num) => {
            for (let factor = 2, limit = Math.sqrt(num); factor <= limit; ++factor) {
                if (num % factor === 0) return false;
            }
            return true;
        };

        const getFractionalBits = (num) => ((num - Math.floor(num)) * maxWord) | 0;

        for (let candidate = 2; primeCounter < 64; candidate++) {
            if (isPrime(candidate)) {
                if (primeCounter < 8) {
                    this.hashValues[primeCounter] = getFractionalBits(Math.sqrt(candidate));
                }
                this.k[primeCounter++] = getFractionalBits(Math.cbrt(candidate));
            }
        }
    }

    rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }

    hash(ascii) {
        const lengthProperty = 'length';
        let result = '';
        const words = [];
        const asciiBitLength = ascii[lengthProperty] * 8;

        this.hashValues = this.hashValues.length ? this.hashValues : Array(8).fill(0);

        ascii += '\x80';
        while (ascii[lengthProperty] % 64 - 56) ascii += '\x00';
        
        for (let i = 0; i < ascii[lengthProperty]; i++) {
            const j = ascii.charCodeAt(i);
            if (j >> 8) return;
            words[i >> 2] = (words[i >> 2] || 0) | (j << ((3 - i) % 4) * 8);
        }
        words[words.length] = ((asciiBitLength / Math.pow(2, 32)) | 0);
        words[words.length] = (asciiBitLength);

        for (let j = 0; j < words.length;) {
            const w = words.slice(j, j += 16);
            const oldHash = this.hashValues.slice(0);

            for (let i = 16; i < 64; i++) {
                const s0 = this.rightRotate(w[i - 15], 7) ^ this.rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
                const s1 = this.rightRotate(w[i - 2], 17) ^ this.rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
            }

            for (let i = 0; i < 64; i++) {
                const s1 = this.rightRotate(this.hashValues[4], 6) ^ this.rightRotate(this.hashValues[4], 11) ^ this.rightRotate(this.hashValues[4], 25);
                const ch = (this.hashValues[4] & this.hashValues[5]) ^ (~this.hashValues[4] & this.hashValues[6]);
                const temp1 = (this.hashValues[7] + s1 + ch + this.k[i] + w[i]) | 0;
                const s0 = this.rightRotate(this.hashValues[0], 2) ^ this.rightRotate(this.hashValues[0], 13) ^ this.rightRotate(this.hashValues[0], 22);
                const maj = (this.hashValues[0] & this.hashValues[1]) ^ (this.hashValues[0] & this.hashValues[2]) ^ (this.hashValues[1] & this.hashValues[2]);
                const temp2 = (s0 + maj) | 0;

                this.hashValues = [(temp1 + temp2) | 0].concat(this.hashValues);
                this.hashValues[4] = (this.hashValues[4] + temp1) | 0;
            }

            for (let i = 0; i < 8; i++) {
                this.hashValues[i] = (this.hashValues[i] + oldHash[i]) | 0;
            }
        }

        for (let i = 0; i < 8; i++) {
            for (let j = 3; j + 1; j--) {
                const b = (this.hashValues[i] >> (j * 8)) & 255;
                result += ((b < 16) ? '0' : '') + b.toString(16);
            }
        }
        return result;
    }

    bigIntArrayToBase64(bigIntArray) {
        let bigIntStr = bigIntArray.map(b => b.toString()).join(',');
        let encoder = new TextEncoder();
        let encodedBytes = encoder.encode(bigIntStr);
        return btoa(String.fromCharCode(...encodedBytes));
    }

    base64ToBigIntArray(base64Str) {
        let decodedStr = atob(base64Str);
        let decodedBytes = new Uint8Array([...decodedStr].map(c => c.charCodeAt(0)));
        let decoder = new TextDecoder();
        let bigIntStr = decoder.decode(decodedBytes);
        return bigIntStr.split(',').map(s => BigInt(s));
    }

    bigIntToBase64(bigInt) {
        let bigIntStr = bigInt.toString();
        let encoder = new TextEncoder();
        let encodedBytes = encoder.encode(bigIntStr);
        return btoa(String.fromCharCode(...encodedBytes));
    }

    base64ToBigInt(base64Str) {
        let decodedStr = atob(base64Str);
        let decodedBytes = new Uint8Array([...decodedStr].map(c => c.charCodeAt(0)));
        let decoder = new TextDecoder();
        let bigIntStr = decoder.decode(decodedBytes);
        return BigInt(bigIntStr);
    }

    generateKeypair() {
        let privateKey = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % this.n;
        let publicKey = this.bigIntArrayToBase64(curve.multiply(this.G, privateKey));
        privateKey = this.bigIntToBase64(privateKey);
        return { privateKey, publicKey };
    }

    generateChachaKeys(privateKey, publicKey) {
        let sharedSecret = curve.multiply(this.base64ToBigIntArray(publicKey), this.base64ToBigInt(privateKey));
        const hash = this.hash(this.bigIntToBase64(sharedSecret[0]));
        const key = hash.substring(0, 32);
        const IV = hash.substring(32, 44);
        return {key, IV};
    }
}

class ChaCha20 {
    constructor(key, nonce) {
        if (!Buffer.isBuffer(key)) {
            key = Buffer.from(key);
        }
        if (!Buffer.isBuffer(nonce)) {
            nonce = Buffer.from(nonce);
        }
        
        this.state = new Uint32Array(16);
        this.key = new Uint32Array(8);
        this.nonce = new Uint32Array(3);

        this.state[0] = 0x61707865;
        this.state[1] = 0x3320646e;
        this.state[2] = 0x79622d32;
        this.state[3] = 0x6b206574;

        for (let i = 0; i < 8; i++) {
            this.key[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        }

        for (let i = 0; i < 8; i++) {
            this.state[i + 4] = this.key[i];
        }

        for (let i = 0; i < 3; i++) {
            this.nonce[i] = (nonce[i * 4] << 24) | (nonce[i * 4 + 1] << 16) | (nonce[i * 4 + 2] << 8) | nonce[i * 4 + 3];
        }
        this.state[13] = 0;
        this.state[14] = this.nonce[0];
        this.state[15] = this.nonce[1];
    }

    rotl(v, c) {
        return (v << c) | (v >>> (32 - c));
    }

    quarterRound(a, b, c, d) {
        this.state[a] += this.state[b];
        this.state[d] = this.rotl((this.state[d] ^ this.state[a]), 16);
        this.state[c] += this.state[d];
        this.state[b] = this.rotl((this.state[b] ^ this.state[c]), 12);
        this.state[a] += this.state[b];
        this.state[d] = this.rotl((this.state[d] ^ this.state[a]), 8);
        this.state[c] += this.state[d];
        this.state[b] = this.rotl((this.state[b] ^ this.state[c]), 7);
    }

    chachaBlock() {
        const workingState = new Uint32Array(this.state);

        for (let i = 0; i < 10; i++) {
            this.quarterRound(0, 4, 8, 12);
            this.quarterRound(1, 5, 9, 13);
            this.quarterRound(2, 6, 10, 14);
            this.quarterRound(3, 7, 11, 15);
            this.quarterRound(0, 5, 10, 15);
            this.quarterRound(1, 6, 11, 12);
            this.quarterRound(2, 7, 8, 13);
            this.quarterRound(3, 4, 9, 14);
        }

        for (let i = 0; i < 16; i++) {
            workingState[i] += this.state[i];
        }

        return workingState;
    }

    hexToUint8Array(hex) {
        hex = hex.toUpperCase().replace(/^0x/, '');
        if (hex.length % 2 !== 0) {
            throw new Error('Invalid hex string length');
        }

        const uint8Array = new Uint8Array(hex.length / 2);

        for (let i = 0; i < hex.length; i += 2) {
            uint8Array[i / 2] = parseInt(hex.substr(i, 2), 16);
        }

        return uint8Array;
    }

    hexToString(hex) {
        hex = hex.toUpperCase().replace(/^0x/, '');
        if (hex.length % 2 !== 0) {
            throw new Error('Invalid hex string length');
        }

        let bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.substr(i, 2), 16));
        }

        let decoder = new TextDecoder('utf-8');
        return decoder.decode(new Uint8Array(bytes));
    }

    encrypt(plaintext) {
		plaintext = Buffer.from(plaintext);
        const ciphertext = new Uint8Array(plaintext.length);
        let keyStream = new Uint8Array(64);
        let keyStreamIndex = 64;

        for (let i = 0; i < plaintext.length; i++) {
            if (keyStreamIndex === 64) {
                keyStream = new Uint8Array(this.chachaBlock().buffer);
                keyStreamIndex = 0;
                this.state[12]++;
                if (this.state[12] === 0) {
                    this.state[13]++;
                }
            }
            ciphertext[i] = plaintext[i] ^ keyStream[keyStreamIndex++];
        }

        return Buffer.from(ciphertext).toString('hex');
    }

    decrypt(ciphertext) {
        return this.hexToString(this.encrypt(this.hexToUint8Array(ciphertext)));
    }
}

// secp521r1 parameters
let a = -3n;
let b = 0x51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF07F71E19F48ABBA982FBAEBB88F9AB05En;
let p = 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn;

let curve = new EllipticCurve(a, b, p);
let ECCops = new EllipticOperations();
let ECCops2 = new EllipticOperations();

// Example Diffie-Hellman exchange

let A_keypair = ECCops.generateKeypair();
console.log("Party A's Public Key:\n", A_keypair.publicKey);
console.log("Party A's Private Key:\n", A_keypair.privateKey);

// NOTE: base64ToBigIntArray is the reverse of bigIntArrayToBase64 (Public Key)
// Same goes for base64ToBigInt and bigIntToBase64 (Private key)

console.log("\nPublic Key Raw Example:\n", ECCops.base64ToBigIntArray(A_keypair.publicKey));
console.log("Private Key Raw Example:\n", ECCops.base64ToBigInt(A_keypair.privateKey));

let B_keypair = ECCops.generateKeypair();
console.log("\nParty B's Public Key:\n", B_keypair.publicKey);
console.log("Party B's Private Key:\n", B_keypair.privateKey);

let chachakeys = ECCops.generateChachaKeys(A_keypair.privateKey, B_keypair.publicKey);

// You need to use seperate ECCops objects only when generating
// chacha keys so that the SHA256 hash variables can reset

let chachakeys2 = ECCops2.generateChachaKeys(B_keypair.privateKey, A_keypair.publicKey);

console.log("\nChacha key:\n", chachakeys.key);
console.log("\nChacha IV:\n", chachakeys.IV);

console.log("\nChacha key:\n", chachakeys2.key);
console.log("\nChacha IV:\n", chachakeys2.IV);

let chacha = new ChaCha20(chachakeys.key, chachakeys.IV);
let plaintext = "Hello world!";
let ciphertext = chacha.encrypt(plaintext);

console.log("\nPlaintext:\n", plaintext);
console.log("\nCiphertext:\n", ciphertext);

chacha = new ChaCha20(chachakeys.key, chachakeys.IV);
console.log("\nDecrypted Plaintext:\n", chacha.decrypt(ciphertext));