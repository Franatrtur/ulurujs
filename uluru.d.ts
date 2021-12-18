declare var crypto: Crypto;
declare namespace Uluru {
    interface algorithm {
        update: (data: ArrayBufferView | string) => algorithm;
        finalize: (...args: any) => object;
        [key: string]: any;
    }
}
declare namespace Uluru {
    namespace enc {
        class Ascii implements encoding {
            encode(str: any): Uint8Array;
            decode(bytes: any): string;
        }
    }
}
declare namespace Uluru {
    namespace enc {
        class Base64 implements encoding {
            encode(str: any): Uint8Array;
            decode(bytes: any): string;
        }
    }
}
declare namespace Uluru {
    class ChaCha20 implements algorithm {
        private state;
        private xstate;
        private mask;
        domac: boolean;
        private cmac;
        private pmac;
        private data;
        pointer: number;
        sigbytes: number;
        reset(): void;
        constructor(key: ArrayBufferView, mac?: boolean, nonce?: ArrayBufferView, counter?: number);
        get counter(): number;
        set counter(ctr: number);
        private QR;
        getmac(): false | Uint8Array;
        private process;
        private append;
        verify(mac: ArrayBufferView): boolean;
        update(data: string | ArrayBufferView): this;
        finalize(): {
            data: Uint8Array;
            mac: boolean | Uint8Array;
        };
    }
}
declare namespace Uluru {
    function encrypt(plaintext: any, password: string): string;
    function decrypt(ciphertext: string, password: string): any;
    function hash(text: any): string;
    function rsaGenerate(): string;
    function rsaSign(message: any, privkeystr: any): string;
    function rsaVerify(message: any, signature: any, pubkeystr: any): boolean;
    function rsaEncrypt(message: any, pubkeystr: any): string;
    function rsaDecrypt(message: any, privkeystr: any): string;
}
declare namespace Uluru {
    namespace enc {
        interface encoding {
            encode: (str: string) => Uint8Array;
            decode: (u8array: ArrayBufferView) => string;
        }
    }
}
declare namespace Uluru {
    namespace enc {
        class Hex implements encoding {
            encode(str: any): Uint8Array;
            decode(bytes: any): string;
        }
    }
}
declare namespace Uluru {
    class Keccak800 implements algorithm {
        private state;
        private temp;
        private theta;
        data: Uint32Array | Uint8Array;
        pointer: number;
        private padblock;
        private padsigbytes;
        reset(): void;
        constructor();
        private keccakF;
        private process;
        private append;
        update(data: string | ArrayBufferView): this;
        finalize(outputbytes?: number): {
            toString(encoder?: enc.encoding): string;
            hash: Uint8Array;
        };
    }
}
declare namespace Uluru {
    class OAEP {
        static seedlen: number;
        static hashlen: number;
        static hdrlen: number;
        pad(data: any, len: any): {
            data: Uint8Array;
        };
        unpad(data: any): {
            data: Uint8Array;
        };
    }
}
declare namespace Uluru {
    class Pbkdf {
        outputbytes: number;
        iterations: number;
        constructor(outputbytes?: number, iterations?: number);
        compute(password: ArrayBufferView | string, salt?: ArrayBufferView): {
            result: Uint8Array;
        };
    }
}
declare namespace Uluru {
    class Random {
        static capacity: number;
        static get secure(): boolean;
        word(): number;
        fill(arr: Uint32Array | Uint8Array | Uint16Array): Uint8Array | Uint16Array | Uint32Array;
    }
}
declare namespace Uluru {
    class RSAKey {
        static fromBufferViews(bufferview1: ArrayBufferView, bufferview2: ArrayBufferView): RSAKey;
        static fromString(str: string): RSAKey;
        private E;
        M: bigint;
        constructor(exponent: bigint | number, mod: bigint | number);
        toString(): string;
        private process;
        encrypt(data: ArrayBufferView | string): {
            data: Uint8Array;
        };
        decrypt(data: ArrayBufferView): {
            data: Uint8Array;
        };
        sign(data: ArrayBufferView | string): {
            data: ArrayBufferView;
            signature: Uint8Array;
        };
        verify(data: ArrayBufferView | string, signature: ArrayBufferView): boolean;
    }
    class RSAKeyPair {
        static pubexp: bigint;
        static publicprefix: string[];
        static privateprefix: string[];
        static fromString(str: string): RSAKeyPair;
        static generate(bitlength: number): RSAKeyPair;
        public: RSAKey;
        private private;
        constructor(publickey: RSAKey, privatekey: RSAKey);
        toString(): string;
    }
    class DiffieHellman {
        E: bigint;
        secret: bigint;
        send(): Uint8Array;
        receive(data: any): void;
        finalize(length?: number): {
            result: Uint8Array;
        };
    }
}
declare namespace Uluru {
    namespace enc {
        class Utf8 implements encoding {
            encode(str: any): Uint8Array;
            decode(bytes: any): string;
        }
    }
}
