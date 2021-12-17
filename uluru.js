var crypto = typeof crypto == "object" ? crypto : typeof global == "object" ? function () {
    var cryp = require("crypto");
    return {
        getRandomValues(data) {
            cryp.randomFillSync(data);
            return data;
        }
    };
}() : undefined;
var Uluru;
(function (Uluru) {
    let enc;
    (function (enc) {
        class Ascii {
            encode(str) {
                let u8array = new Uint8Array(str.length);
                for (let i = 0, l = str.length; i < l; i++)
                    u8array[i] = str.charCodeAt(i);
                return u8array;
            }
            decode(bytes) {
                bytes = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
                let str = Array(bytes.length);
                for (let i = 0, l = bytes.length; i < l; i++)
                    str[i] = String.fromCharCode(bytes[i]);
                return str.join("");
            }
        }
        enc.Ascii = Ascii;
    })(enc = Uluru.enc || (Uluru.enc = {}));
})(Uluru || (Uluru = {}));
var Uluru;
(function (Uluru) {
    let enc;
    (function (enc) {
        let b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        let b64paddings = ["", "=", "=="];
        let b64codes = new Uint8Array(256);
        for (let c = 0; c < 64; c++)
            b64codes[b64chars.charCodeAt(c)] = c;
        class Base64 {
            encode(str) {
                if (typeof atob == "function")
                    return new enc.Ascii().encode(atob(str));
                str = str.replace(/[^A-Za-z0-9\+\/]/g, "");
                let outlen = str.length * 3 + 1 >>> 2;
                let bytes = new Uint8Array(outlen);
                let mod3, mod4, out24 = 0, outidx = 0;
                for (let i = 0, l = str.length; i < l; i++) {
                    mod4 = i & 3;
                    out24 |= b64codes[str.charCodeAt(i)] << 6 * (3 - mod4);
                    if (mod4 == 3 || str.length - i == 1) {
                        for (mod3 = 0; mod3 < 3 && outidx < outlen; mod3++, outidx++)
                            bytes[outidx] = out24 >>> (16 >>> mod3 & 24) & 0xff;
                        out24 = 0;
                    }
                }
                return bytes;
            }
            decode(bytes) {
                bytes = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
                if (typeof btoa == "function")
                    return btoa(new enc.Ascii().decode(bytes));
                let str = [];
                let mod3 = 2, u24 = 0;
                for (let i = 0, l = bytes.length; i < l; i++) {
                    mod3 = i % 3;
                    u24 |= bytes[i] << (16 >>> mod3 & 24);
                    if (mod3 == 2 || bytes.length - i == 1) {
                        str.push(b64chars.charAt(u24 >>> 18 & 0x3f) +
                            b64chars.charAt(u24 >>> 12 & 0x3f) +
                            b64chars.charAt(u24 >>> 6 & 0x3f) +
                            b64chars.charAt(u24 & 0x3f));
                        u24 = 0;
                    }
                }
                str = str.join("");
                return str.slice(0, str.length - 2 + mod3) + b64paddings[2 - mod3];
            }
        }
        enc.Base64 = Base64;
    })(enc = Uluru.enc || (Uluru.enc = {}));
})(Uluru || (Uluru = {}));
var Uluru;
(function (Uluru) {
    const CONSTS = new Uint32Array(new Uluru.enc.Ascii().encode("expand 32-byte k").buffer);
    class ChaCha20 {
        constructor(key, mac = true, nonce = new Uint32Array(3), counter = 0) {
            this.state = new Uint32Array(16);
            this.state.set(CONSTS);
            this.state.set(new Uint32Array(key.buffer, key.byteOffset, key.byteLength >> 2), 4);
            this.state.set(new Uint32Array(nonce.buffer, nonce.byteOffset, nonce.byteLength >> 2), 12);
            for (let init = 0; init < 8; init++) {
                for (let ev = 0; ev < 4; ev++)
                    this.QR(this.state, ev, ev + 4, ev + 8, ev + 12);
                for (let od = 0; od < 16; od += 4)
                    this.QR(this.state, od, od + 1, od + 2, od + 3);
            }
            this.prectr = this.state[15];
            this.state[15] ^= counter;
            this.ctr = counter;
            this.domac = !!mac;
            this.reset();
        }
        reset() {
            this.xstate = new Uint32Array(16);
            this.pmac = this.domac ? new Uint32Array(CONSTS) : false;
            this.cmac = this.domac ? new Uint32Array(CONSTS) : false;
            this.data = new Uint32Array(0);
            this.pointer = 0;
            this.sigbytes = 0;
        }
        QR(state, A, B, C, D) {
            state[A] += state[B];
            state[D] ^= state[A];
            state[D] = state[D] << 16 | state[D] >>> 16;
            state[C] += state[D];
            state[B] ^= state[C];
            state[B] = state[B] << 12 | state[B] >>> 20;
            state[A] += state[B];
            state[D] ^= state[A];
            state[D] = state[D] << 8 | state[D] >>> 24;
            state[C] += state[D];
            state[B] ^= state[C];
            state[B] = state[B] << 7 | state[B] >>> 25;
        }
        getmac() {
            if (!this.domac)
                return false;
            let pm = this.pmac, cm = this.cmac;
            let mac = new Uint32Array([
                pm[0] ^ cm[0],
                pm[1] ^ cm[1],
                pm[2] ^ cm[2],
                pm[3] ^ cm[3],
            ]);
            for (let mr = 0; mr < 4; mr++) {
                this.QR(mac, 0, 1, 2, 3);
                this.QR(mac, 3, 0, 1, 2);
                this.QR(mac, 2, 3, 0, 1);
                this.QR(mac, 1, 2, 3, 0);
            }
            for (let re = 0; re < 4; re++)
                mac[re] += pm[re] + cm[re];
            return new Uint8Array(mac.buffer);
        }
        process(flush = false) {
            let blocks = (flush ? Math.ceil : Math.floor)((this.sigbytes - this.pointer) / 16);
            let ptw, ctw;
            let end = Math.ceil(this.sigbytes / 4) - 1;
            let erase = 4 - this.sigbytes % 4;
            this.state[15] = this.prectr ^ (this.ctr + (this.pointer >> 4));
            for (let b = 0; b < blocks; b++) {
                let xs = this.xstate;
                xs.set(this.state);
                for (let drnd = 0; drnd < 20; drnd += 2) {
                    this.QR(xs, 0, 4, 8, 12);
                    this.QR(xs, 1, 5, 9, 13);
                    this.QR(xs, 2, 6, 10, 14);
                    this.QR(xs, 3, 7, 11, 15);
                    this.QR(xs, 0, 5, 10, 15);
                    this.QR(xs, 1, 6, 11, 12);
                    this.QR(xs, 2, 7, 8, 13);
                    this.QR(xs, 3, 4, 9, 14);
                }
                for (let i = 0; i < 16 && this.pointer + i <= end; i++) {
                    ptw = this.data[this.pointer + i];
                    ctw = ptw ^ (this.xstate[i] + this.state[i]);
                    if (this.pointer + i == end)
                        ctw = ctw << erase * 8 >>> erase * 8;
                    this.data[this.pointer + i] = ctw;
                    if (this.domac) {
                        this.pmac[i & 3] ^= ptw + this.xstate[i];
                        this.cmac[i & 3] ^= ctw + this.xstate[i];
                        this.QR(this.pmac, i & 3, (i + 1) & 3, (i + 2) & 3, (i + 3) & 3);
                        this.QR(this.cmac, i & 3, (i + 1) & 3, (i + 2) & 3, (i + 3) & 3);
                    }
                }
                this.pointer += 16;
                this.state[15]++;
            }
        }
        append(data) {
            data = typeof data == "string" ? new Uluru.enc.Utf8().encode(data) : data;
            let old = this.data;
            let newlen = Math.ceil((this.sigbytes + data.byteLength) / 64) * 64;
            this.data = new Uint8Array(newlen);
            this.data.set(new Uint8Array(old.buffer, 0, this.sigbytes));
            this.data.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength), this.sigbytes);
            this.data = new Uint32Array(this.data.buffer);
            this.sigbytes += data.byteLength;
        }
        update(data) {
            this.append(data);
            this.process(false);
            return this;
        }
        finalize() {
            this.process(true);
            return {
                data: new Uint8Array(this.data.buffer, 0, this.sigbytes),
                mac: this.getmac()
            };
        }
    }
    Uluru.ChaCha20 = ChaCha20;
})(Uluru || (Uluru = {}));
var Uluru;
(function (Uluru) {
    const SALTsize = 6;
    function encrypt(plaintext, password) {
        let salt = new Uluru.Random().fill(new Uint8Array(SALTsize));
        let key = new Uluru.Pbkdf(32, 1000).compute(new Uluru.enc.Utf8().encode(password), salt).result;
        let encryptor = new Uluru.ChaCha20(key, true, salt);
        encryptor.update(new Uluru.enc.Utf8().encode(plaintext));
        let encrypted = encryptor.finalize();
        return new Uluru.enc.Hex().decode(salt) +
            new Uluru.enc.Base64().decode(encrypted.data) +
            new Uluru.enc.Hex().decode(encrypted.mac);
    }
    Uluru.encrypt = encrypt;
    function decrypt(ciphertext, password) {
        let salt, cdata, macstr;
        try {
            salt = new Uluru.enc.Hex().encode(ciphertext.slice(0, SALTsize * 2));
            cdata = new Uluru.enc.Base64().encode(ciphertext.slice(SALTsize * 2, -32));
            macstr = ciphertext.slice(-32);
        }
        catch (e) {
            throw "Incorrectly formated ciphertext";
        }
        let key = new Uluru.Pbkdf(32, 1000).compute(new Uluru.enc.Utf8().encode(password), salt).result;
        let decryptor = new Uluru.ChaCha20(key, true, salt);
        decryptor.update(cdata);
        let decrypted = decryptor.finalize();
        if (new Uluru.enc.Hex().decode(decrypted.mac) != macstr)
            throw "Invalid authentication";
        return new Uluru.enc.Utf8().decode(decrypted.data);
    }
    Uluru.decrypt = decrypt;
    function hash(text) {
        return new Uluru.Keccak800().update(new Uluru.enc.Utf8().encode(text)).finalize().toString(new Uluru.enc.Hex);
    }
    Uluru.hash = hash;
    function rsaGenerate() {
        return Uluru.RSAKeyPair.generate(3072).toString();
    }
    Uluru.rsaGenerate = rsaGenerate;
    function rsaSign(message, privkeystr) {
        return new Uluru.enc.Base64().decode(Uluru.RSAKey.fromString(privkeystr).sign(new Uluru.enc.Utf8().encode(message)).signature);
    }
    Uluru.rsaSign = rsaSign;
    function rsaVerify(message, signature, pubkeystr) {
        return Uluru.RSAKey.fromString(pubkeystr).verify(new Uluru.enc.Utf8().encode(message), new Uluru.enc.Base64().encode(signature));
    }
    Uluru.rsaVerify = rsaVerify;
    function rsaEncrypt(message, pubkeystr) {
        let key = Uluru.RSAKey.fromString(pubkeystr);
        let symkey = new Uluru.Random().fill(new Uint8Array(32));
        let encsymkey = new Uluru.enc.Base64().decode(key.encrypt(symkey).data);
        let encptx = new Uluru.ChaCha20(symkey, true).update(new Uluru.enc.Utf8().encode(message)).finalize();
        return encsymkey + "|" + new Uluru.enc.Base64().decode(encptx.data) + new Uluru.enc.Hex().decode(encptx.mac);
    }
    Uluru.rsaEncrypt = rsaEncrypt;
    function rsaDecrypt(message, privkeystr) {
        let key, symkey, encptx, mac, splitted;
        try {
            key = Uluru.RSAKey.fromString(privkeystr);
            splitted = message.split("|");
            symkey = new Uluru.enc.Base64().encode(splitted[0]);
            encptx = new Uluru.enc.Base64().encode(splitted[1].slice(0, -32));
            mac = new Uluru.enc.Hex().encode(splitted[1].slice(-32));
        }
        catch (e) {
            throw "Incorrectly formatted RSA ciphertext";
        }
        symkey = key.decrypt(symkey).data;
        encptx = new Uluru.ChaCha20(symkey, true).update(encptx).finalize();
        if (encptx.mac.join(",") != mac.join(","))
            throw "Invalid RSA message authentication code";
        return new Uluru.enc.Utf8().decode(encptx.data);
    }
    Uluru.rsaDecrypt = rsaDecrypt;
})(Uluru || (Uluru = {}));
var Uluru;
(function (Uluru) {
    let enc;
    (function (enc) {
        let hexcodes = Array(256);
        let hexmap = {};
        for (let h = 0; h < 256; h++) {
            hexcodes[h] = ("00" + h.toString(16)).slice(-2);
            hexmap[hexcodes[h]] = h;
        }
        class Hex {
            encode(str) {
                str = str.replace(/[^A-Fa-f0-9\+\/]/g, "").toLowerCase();
                let bytes = new Uint8Array(str.length >> 1);
                for (let hxcode = 0; hxcode < str.length; hxcode += 2)
                    bytes[hxcode >> 1] = hexmap[str.slice(hxcode, hxcode + 2)];
                return bytes;
            }
            decode(bytes) {
                bytes = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
                let str = Array(bytes.length);
                for (let byte = 0; byte < bytes.length; byte++)
                    str[byte] = hexcodes[bytes[byte]];
                return str.join("");
            }
        }
        enc.Hex = Hex;
    })(enc = Uluru.enc || (Uluru.enc = {}));
})(Uluru || (Uluru = {}));
var Uluru;
(function (Uluru) {
    const RHOoffets = new Uint8Array([
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14
    ]);
    const RCs = new Uint32Array([
        0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009,
        0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
        0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008
    ]);
    const XMP1 = new Uint8Array(25);
    const XMM1 = new Uint8Array(25);
    const XYP = new Uint8Array(25);
    const XP1 = new Uint8Array(25);
    const XP2 = new Uint8Array(25);
    let nx, ny;
    for (let n = 0; n < 25; n++) {
        nx = n % 5;
        ny = Math.floor(n / 5);
        XMP1[n] = (nx + 1) % 5;
        XMM1[n] = (nx + 4) % 5;
        XYP[n] = ny * 5 + (2 * nx + 3 * ny) % 5;
        XP1[n] = ((nx + 1) % 5) * 5 + ny;
        XP2[n] = ((nx + 2) % 5) * 5 + ny;
    }
    class Keccak800 {
        constructor() {
            this.reset();
        }
        reset() {
            this.state = new Uint32Array(25);
            this.temp = new Uint32Array(25);
            this.theta = new Uint32Array(5);
            this.data = new Uint32Array(0);
            this.pointer = 0;
            this.padblock = new Uint32Array(16);
            this.padsigbytes = 0;
        }
        keccakF(state) {
            let temp = this.temp, theta = this.theta;
            let off, tmp;
            for (let round = 0; round < 22; round++) {
                theta[0] = state[0] ^ state[1] ^ state[2] ^ state[3] ^ state[4];
                theta[1] = state[5] ^ state[6] ^ state[7] ^ state[8] ^ state[9];
                theta[2] = state[10] ^ state[11] ^ state[12] ^ state[13] ^ state[14];
                theta[3] = state[15] ^ state[16] ^ state[17] ^ state[18] ^ state[19];
                theta[4] = state[20] ^ state[21] ^ state[22] ^ state[23] ^ state[24];
                for (let i = 0; i < 25; i++) {
                    tmp = theta[XMP1[i]];
                    state[i] ^= theta[XMM1[i]] ^ (tmp << 1 | tmp >>> 31);
                    off = RHOoffets[i];
                    tmp = state[i];
                    temp[XYP[i]] = tmp << off | tmp >>> (32 - off);
                }
                for (let i = 0; i < 25; i++)
                    state[i] = temp[i] ^ (~temp[XP1[i]] & temp[XP2[i]]);
                state[0] ^= RCs[round];
            }
        }
        process(flush = false) {
            let blocks = (this.data.length - this.pointer) / 16;
            for (let b = 0; b < blocks; b++) {
                for (let w = 0; w < 16; w++)
                    this.state[w] ^= this.data[this.pointer + w];
                this.keccakF(this.state);
                this.pointer += 16;
            }
            if (flush) {
                for (let w = 0; w < 16; w++)
                    this.state[w] ^= this.padblock[w];
                this.keccakF(this.state);
            }
        }
        append(data) {
            data = typeof data == "string" ? new Uluru.enc.Utf8().encode(data) : data;
            let padblock = this.padblock;
            let padsigbytes = this.padsigbytes;
            if (data.byteLength + padsigbytes < 64) {
                padblock = new Uint8Array(padblock.buffer);
                padblock.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength), padsigbytes);
                padblock[padblock.length - 1] = 0x80;
                padblock[data.byteLength + padsigbytes] ^= 0x06;
                this.padblock = new Uint32Array(padblock.buffer);
                this.padsigbytes += data.byteLength;
            }
            else {
                let newlen = (padsigbytes + data.byteLength) >> 6 << 6;
                let overflow = (padsigbytes + data.byteLength) % 64;
                this.data = this.data.byteLength > newlen ? new Uint8Array(this.data.buffer, 0, newlen) : new Uint8Array(newlen);
                this.data.set(new Uint8Array(padblock.buffer, 0, padsigbytes));
                this.data.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength - overflow), padsigbytes);
                this.data = new Uint32Array(this.data.buffer, 0, newlen >> 2);
                padblock.fill(0);
                this.padsigbytes = 0;
                this.append(new Uint8Array(data.buffer, data.byteOffset + data.byteLength - overflow, overflow));
            }
        }
        update(data) {
            this.append(data);
            this.process(false);
            return this;
        }
        finalize(outputbytes = 32) {
            this.process(true);
            let len = Math.ceil(outputbytes / 64) * 16;
            let result = new Uint32Array(len);
            for (let i = 0; i < len; i += 16) {
                result.set(new Uint32Array(this.state.buffer, 0, 16), i);
                this.keccakF(this.state);
            }
            return {
                toString(encoder = new Uluru.enc.Hex) {
                    return encoder.decode(this.hash);
                },
                hash: new Uint8Array(result.buffer, 0, outputbytes)
            };
        }
    }
    Uluru.Keccak800 = Keccak800;
})(Uluru || (Uluru = {}));
var Uluru;
(function (Uluru) {
    const SEEDlen = 12;
    const HASHlen = 16;
    const HDRlen = SEEDlen + HASHlen + 4;
    function merge(...bufferviews) {
        let len = 0;
        for (let i = 0; i < bufferviews.length; i++)
            len += bufferviews[i].byteLength;
        let result = new Uint8Array(len);
        let pointer = 0;
        for (let i = 0; i < bufferviews.length; i++) {
            result.set(new Uint8Array(bufferviews[i].buffer, bufferviews[i].byteOffset, bufferviews[i].byteLength), pointer);
            pointer += bufferviews[i].byteLength;
        }
        return result;
    }
    class OAEP {
        pad(data, len) {
            let padxdata = new Uint8Array(len - HDRlen);
            padxdata.set(data);
            if (len <= HDRlen)
                throw "OAEP message length too small";
            let datalen = new Uint32Array([data.byteLength]);
            let seed = new Uluru.Random().fill(new Uint8Array(SEEDlen));
            let hash = new Uluru.Keccak800().update(padxdata).update(datalen).update(seed).finalize(HASHlen).hash;
            let header = merge(datalen, seed, hash);
            let mask = new Uluru.Keccak800().update(header).finalize(len - HDRlen).hash;
            for (let m0 = 0; m0 < len - HDRlen; m0++)
                padxdata[m0] ^= mask[m0];
            mask = new Uluru.Keccak800().update(padxdata).finalize(HDRlen).hash;
            for (let m1 = 0; m1 < HDRlen; m1++)
                header[m1] ^= mask[m1];
            return {
                data: merge(header, padxdata)
            };
        }
        unpad(data) {
            let len = data.byteLength;
            let header = new Uint8Array(data.buffer, 0, HDRlen).slice();
            let padxdata = new Uint8Array(data.buffer, HDRlen).slice();
            let mask = new Uluru.Keccak800().update(padxdata).finalize(HDRlen).hash;
            for (let m1 = 0; m1 < HDRlen; m1++)
                header[m1] ^= mask[m1];
            mask = new Uluru.Keccak800().update(header).finalize(len - HDRlen).hash;
            for (let m0 = 0; m0 < len - HDRlen; m0++)
                padxdata[m0] ^= mask[m0];
            let datalen = new Uint32Array(header.buffer, 0, 1);
            let seed = new Uint8Array(header.buffer, 4, SEEDlen);
            let hash = new Uint8Array(header.buffer, 4 + SEEDlen, HASHlen);
            let rehash = new Uluru.Keccak800().update(padxdata).update(datalen).update(seed).finalize(HASHlen).hash;
            if (rehash.join(",") != hash.join(","))
                throw "OAEP invalid padding hash";
            return {
                data: new Uint8Array(padxdata.buffer, 0, datalen[0])
            };
        }
    }
    OAEP.seedlen = SEEDlen;
    OAEP.hashlen = HASHlen;
    OAEP.hdrlen = HDRlen;
    Uluru.OAEP = OAEP;
})(Uluru || (Uluru = {}));
var Uluru;
(function (Uluru) {
    class Pbkdf {
        constructor(outputbytes = 32, iterations = 1000) {
            this.outputbytes = outputbytes;
            this.iterations = iterations;
        }
        compute(password, salt = new Uint32Array()) {
            let result = new Uint8Array(this.outputbytes);
            let block;
            let hasher = new Uluru.Keccak800();
            hasher.update(salt);
            hasher.finalize(0);
            for (let i = 0; i < this.iterations; i++) {
                hasher.update(password);
                block = hasher.finalize(this.outputbytes).hash;
                for (let b = 0; b < result.length; b++)
                    result[b] ^= block[b];
            }
            return { result };
        }
    }
    Uluru.Pbkdf = Pbkdf;
})(Uluru || (Uluru = {}));
var Uluru;
(function (Uluru) {
    const CAPACITY = 16300;
    let Pool = new Uint32Array(CAPACITY);
    let Pointer = 0;
    function reset() {
        Pointer = 0;
        if (Random.secure)
            crypto.getRandomValues(Pool);
        else
            for (let i = 0, l = CAPACITY; i < l; i++)
                Pool[i] = Math.floor(Math.random() * 0x100000000);
    }
    class Random {
        static get secure() {
            return typeof crypto == "object" && typeof crypto["getRandomValues"] == "function";
        }
        word() {
            if (Pointer >= CAPACITY)
                reset();
            return Pool[Pointer++];
        }
        fill(arr) {
            if (ArrayBuffer.isView(arr)) {
                reset();
                let wrds = new Uint32Array(arr.buffer, arr.byteOffset, arr.byteLength >> 2);
                for (let i = 0, l = wrds.length; i < l; i += CAPACITY) {
                    wrds.set(new Uint32Array(Pool.buffer, 0, Math.min((l - i), CAPACITY)), i);
                    reset();
                }
                let bytes = new Uint8Array(arr.buffer, arr.byteLength >> 2 << 2, arr.byteLength - (arr.byteLength >> 2 << 2));
                for (let i = 0, l = bytes.length; i < l; i++)
                    bytes[i] = this.word();
            }
            else {
                for (let i = 0, l = arr.length; i < l; i++)
                    arr[i] = this.word();
            }
            return arr;
        }
    }
    Random.capacity = CAPACITY;
    Uluru.Random = Random;
    reset();
})(Uluru || (Uluru = {}));
var Uluru;
(function (Uluru) {
    const Bi = BigInt;
    const n1 = Bi(1);
    const n0 = Bi(0);
    const mask = bitlen => (n1 << Bi(bitlen)) - n1;
    function bitLen(x) {
        let bits = 0;
        let bits32 = Bi(0x100000000);
        let stillbigger = true;
        while (x) {
            stillbigger = stillbigger && x > bits32;
            bits += stillbigger ? 32 : 1;
            x >>= Bi(stillbigger ? 32 : 1);
        }
        return bits;
    }
    function modPow(base, exponent, modulus) {
        let result = n1;
        while (exponent) {
            if ((exponent & n1) == n1)
                result = (result * base) % modulus;
            exponent >>= n1;
            base = (base * base) % modulus;
        }
        return result;
    }
    function randomBi(bitlength) {
        let result = n0;
        let rand = new Uluru.Random();
        for (let w = 0; w * 32 < bitlength; w++)
            result = (result << Bi(32)) | Bi(rand.word());
        return result & mask(bitlength);
    }
    let smallprimes = [Bi(2)];
    small: for (let n = 3; n < 1024; n += 2) {
        for (let co = 1; co < smallprimes.length; co++)
            if (Bi(n) % smallprimes[co] === BigInt(0))
                continue small;
        smallprimes.push(Bi(n));
    }
    function fermat(prime, iterations = 6) {
        let randsize = Math.min(16, bitLen(prime) - 1);
        let base;
        while (iterations--) {
            base = randomBi(randsize) + Bi(5);
            if (modPow(base, prime - n1, prime) != n1)
                return false;
        }
        return true;
    }
    function millerRabin(prime, iterations = 6) {
        let s = n0, d = prime - n1;
        let randsize = Math.min(16, bitLen(prime) - 1);
        while (!((d & n1) != n1)) {
            d >>= n1;
            s++;
        }
        let a, x;
        let cant1 = n1, cant2 = prime - n1;
        iter: while (iterations--) {
            a = randomBi(randsize) + Bi(5);
            x = modPow(a, d, prime);
            if (x == cant1 || x == cant2)
                continue iter;
            for (let i = n0, l = s - n1; i < l; i++) {
                x = modPow(x, Bi(2), prime);
                if (x == cant1)
                    return false;
                if (x == cant2)
                    continue iter;
            }
            return false;
        }
        return true;
    }
    function isPrime(prime, iterations = 6) {
        for (let i = 0, l = smallprimes.length; i < l; i++)
            if (prime % smallprimes[i] == n0)
                return prime == smallprimes[i];
        return millerRabin(prime, iterations) && fermat(prime, iterations);
    }
    function prime(bitlength, iterations = 6, attempts = 100000) {
        let candidate;
        for (let i = 0; i < attempts; i++) {
            candidate = randomBi(bitlength) | n1 | (n1 << Bi(bitlength - 1));
            if (isPrime(candidate, iterations))
                return candidate;
        }
        throw "Cannot find a prime";
    }
    function modInv(int, modulus) {
        let mod0 = modulus;
        let y = n0, x = n1;
        let quot, temp;
        while (int > 1) {
            quot = int / modulus;
            temp = modulus;
            modulus = int % modulus;
            int = temp;
            temp = y;
            y = x - quot * y;
            x = temp;
        }
        return x < 0 ? x + mod0 : x;
    }
    function buffviewToBi(bufferview) {
        return Bi("0x" + new Uluru.enc.Hex().decode(new Uint8Array(bufferview.buffer, bufferview.byteOffset || 0, bufferview.byteLength || 0)));
    }
    function biToBuffview(bigint) {
        let stred = bigint.toString(16);
        return new Uluru.enc.Hex().encode((stred.length % 2 == 1 ? "0" : "") + stred);
    }
    class RSAKey {
        constructor(exponent, mod) {
            this.E = Bi(exponent);
            this.M = Bi(mod);
        }
        static fromBufferViews(bufferview1, bufferview2) {
            return new this(buffviewToBi(bufferview1), buffviewToBi(bufferview2));
        }
        static fromString(str) {
            let splitted = str.split("<")[1].split(">")[0].split("|");
            return this.fromBufferViews(new Uluru.enc.Base64().encode(splitted[0]), new Uluru.enc.Base64().encode(splitted[1]));
        }
        toString() {
            return "<" +
                new Uluru.enc.Base64().decode(biToBuffview(this.E)) +
                "|" +
                new Uluru.enc.Base64().decode(biToBuffview(this.M)) +
                ">";
        }
        process(data) {
            let databi = buffviewToBi(data);
            if (databi >= this.M)
                throw "Data integer too large";
            return biToBuffview(modPow(databi, this.E, this.M));
        }
        encrypt(data) {
            data = typeof data == "string" ? new Uluru.enc.Utf8().encode(data) : data;
            let msglen = (bitLen(this.M) >> 3) - 2 - Uluru.OAEP.hdrlen;
            if (data.byteLength > msglen)
                throw "Message too long";
            return {
                data: this.process(new Uluru.OAEP().pad(data, msglen).data)
            };
        }
        decrypt(data) {
            return {
                data: new Uluru.OAEP().unpad(this.process(data)).data
            };
        }
        sign(data) {
            data = typeof data == "string" ? new Uluru.enc.Utf8().encode(data) : data;
            let hash = new Uluru.Keccak800().update(data).finalize(64).hash;
            return {
                data,
                signature: this.encrypt(hash).data
            };
        }
        verify(data, signature) {
            try {
                data = typeof data == "string" ? new Uluru.enc.Utf8().encode(data) : data;
                let hash = new Uluru.Keccak800().update(data).finalize(64).hash;
                let authcode = this.decrypt(signature).data;
                return hash.join(",") == authcode.join(",");
            }
            catch (e) {
                return false;
            }
        }
    }
    Uluru.RSAKey = RSAKey;
    const PUBEXP = Bi(0x101);
    const PUBLICprefix = ["\n==BEGIN ULURU PUBLIC KEY==\n", "\n==END ULURU PUBLIC KEY==\n"];
    const PRIVATEprefix = ["\n==BEGIN ULURU PRIVATE KEY==\n", "\n==END ULURU PRIVATE KEY==\n"];
    class RSAKeyPair {
        constructor(publickey, privatekey) {
            this.public = publickey;
            this.private = privatekey;
        }
        static fromString(str) {
            return new this(RSAKey.fromString(str.split(PUBLICprefix[0])[1].split(PUBLICprefix[1])[0]), RSAKey.fromString(str.split(PRIVATEprefix[0])[1].split(PRIVATEprefix[1])[0]));
        }
        static generate(bitlength) {
            if (!bitlength)
                return;
            bitlength >>= 1;
            let E = PUBEXP;
            let prime1 = prime(bitlength), prime2 = prime(bitlength);
            let N = prime1 * prime2;
            let phi = (prime1 - n1) * (prime2 - n1);
            let D = modInv(E, phi);
            return new this(new RSAKey(E, N), new RSAKey(D, N));
        }
        toString() {
            return PUBLICprefix[0] + this.public.toString() + PUBLICprefix[1] + "\n" +
                PRIVATEprefix[0] + this.private.toString() + PRIVATEprefix[1];
        }
    }
    RSAKeyPair.pubexp = PUBEXP;
    RSAKeyPair.publicprefix = PUBLICprefix;
    RSAKeyPair.privateprefix = PRIVATEprefix;
    Uluru.RSAKeyPair = RSAKeyPair;
    const MODPgroup = buffviewToBi(new Uluru.enc.Base64().encode("///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxObIlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjftawv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXTmmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhghfDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYMfbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshqZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEIARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBIHNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0BjGZ//////////8="));
    const GENERATOR = Bi(2);
    class DiffieHellman {
        constructor() {
            this.E = randomBi(384) | (Bi(1) << Bi(383));
        }
        send() {
            return biToBuffview(modPow(GENERATOR, this.E, MODPgroup));
        }
        receive(data) {
            this.secret = modPow(buffviewToBi(data), this.E, MODPgroup);
        }
        finalize(length = 32) {
            if (typeof this.secret != "bigint")
                throw "Key exchange cannot finalize without receiving";
            return new Uluru.Pbkdf(length, 10).compute(biToBuffview(this.secret));
        }
    }
    Uluru.DiffieHellman = DiffieHellman;
})(Uluru || (Uluru = {}));
var Uluru;
(function (Uluru) {
    let enc;
    (function (enc) {
        class Utf8 {
            encode(str) {
                if (typeof TextEncoder == "function")
                    return new TextEncoder().encode(str);
                let bytes = new Uint8Array(str.length * 4);
                let pos = 0;
                let code;
                for (let i = 0, l = str.length; i < l; i++) {
                    code = str.codePointAt(i);
                    if (code > 0x1000)
                        i++;
                    if (code <= 0x7f)
                        bytes[pos++] = code;
                    else if (code <= 0x7ff) {
                        bytes[pos++] = 0xc0 | ((code >>> 6) & 0x1f);
                        bytes[pos++] = 0x80 | (code & 0x3f);
                    }
                    else if (code <= 0xffff) {
                        bytes[pos++] = 0xe0 | ((code >>> 12) & 0x0f);
                        bytes[pos++] = 0x80 | ((code >>> 6) & 0x3f);
                        bytes[pos++] = 0x80 | (code & 0x3f);
                    }
                    else {
                        bytes[pos++] = 0xf0 | ((code >>> 18) & 0x07);
                        bytes[pos++] = 0x80 | ((code >>> 12) & 0x3f);
                        bytes[pos++] = 0x80 | ((code >>> 6) & 0x3f);
                        bytes[pos++] = 0x80 | (code & 0x3f);
                    }
                }
            }
            decode(bytes) {
                bytes = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
                if (typeof TextDecoder == "function")
                    return new TextDecoder().decode(bytes);
                let str = [];
                let ucpoint;
                for (let i = 0, l = bytes.length; i < l;) {
                    if (bytes[i] < 0x80)
                        str.push(String.fromCharCode(bytes[i++]));
                    else if (bytes[i] >= 0xc0 && bytes[i] < 0xe0)
                        str.push(String.fromCharCode(((bytes[i++] & 0x1f) << 6) | (bytes[i++] & 0x3f)));
                    else if (bytes[i] >= 0xe0 && bytes[i] < 0xf0)
                        str.push(String.fromCharCode(((bytes[i++] & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f)));
                    else if (bytes[i] >= 0xf0 && bytes[i] < 0xf7) {
                        ucpoint = ((bytes[i++] & 0x07) << 18) | ((bytes[i++] & 0x3f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f);
                        str.push(String.fromCodePoint(ucpoint));
                    }
                    else
                        i++;
                }
                return str.join("");
            }
        }
        enc.Utf8 = Utf8;
    })(enc = Uluru.enc || (Uluru.enc = {}));
})(Uluru || (Uluru = {}));
if (typeof define === "function" && define.amd)
    define("Uluru", [], () => Uluru);
if (typeof module != "undefined")
    module.exports = Uluru;
