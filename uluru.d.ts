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
        private data;
        private state;
        private xstate;
        private prectr;
        private ctr;
        private cmac;
        private pmac;
        domac: boolean;
        pointer: number;
        sigbytes: number;
        reset(): void;
        constructor(key: any, mac?: boolean, nonce?: number, counter?: number);
        QR(state: any, A: any, B: any, C: any, D: any): void;
        getmac(): false | Uint8Array;
        process(flush?: boolean): void;
        append(data: any): void;
        update(data: any): this;
        finalize(): {
            data: Uint8Array;
            mac: boolean | Uint8Array;
        };
    }
}
declare namespace Uluru {
    function encrypt(plaintext: any, password: any): string;
    function decrypt(ciphertext: any, password: any): string;
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
            decode: (u8array: Uint8Array) => string;
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
        keccakF(state: any): void;
        process(flush?: boolean): void;
        append(data: any): void;
        update(data: any): this;
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
        compute(password: ArrayBufferView | string, salt?: number): {
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
        protected process(data: ArrayBufferView): Uint8Array;
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
}
declare namespace Uluru {
    namespace enc {
        class Utf8 implements encoding {
            encode(str: any): Uint8Array;
            decode(bytes: any): string;
        }
    }
}
