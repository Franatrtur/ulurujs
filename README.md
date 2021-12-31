
<img src="https://i.ibb.co/p1K4cDf/final.png" alt="drawing" height="80"/><br>
Uluru crypto - a self-containted universal cryptolibrary designed with simplicity of usage in mind.
# Uluru in javascript
![GitHub](https://img.shields.io/github/license/Franatrtur/ulurujs?style=for-the-badge)  ![npm](https://img.shields.io/npm/v/uluru-crypto?label=npm%20version&style=for-the-badge) ![npm bundle size](https://img.shields.io/bundlephobia/min/uluru-crypto?style=for-the-badge)

Uluru JS is written in [typescript](https://www.typescriptlang.org/), and can be used both in node and browser without any external dependencies.
## Quick start
```bash
$ npm install uluru-crypto
```
```html
<script src="https://cdn.jsdelivr.net/npm/uluru-crypto/uluru.js"></script>
```
```javascript
//in node use require("uluru-crypto"), in browser use the ready Uluru object:
const {encrypt, decrypt, hash} = Uluru
let encrypted = encrypt("some sensitive data!", "secret password")
let decrypted = decrypt(encrypted, "secret password") //"some sensitive data!"
let checksum = hash("some string to hash") //"00d5c7aff4b3f0c...
```
# Docs
## Table of contents
 1. [Including Uluru in your project](#including-uluru-in-your-project)
	 - [Node](#node)
	 - [Browser](#browser) (or requireJS)
	 - [Custom compilation](#custom-compilation)
 2. [String encodings](#string-encodings)
 3. [Hashing](#hashing)
 4. [Symmetric encryption](#symmetric-encryption)
 5. [Asymmetric encryption](#asymmetric-encryption)
	 - [Generating an RSA keypair](#generating-an-rsa-keypair)
	 - [RSA encryption and decryption](#rsa-encryption-and-decryption)
	 - [RSA signatures](#rsa-signatures)
 6. [Key derivation](#key-derivation)
 7. [Key exchange](#key-exchange)
 8. [Random generation](#random-generation)
## Including Uluru in your project
### Node
Installation with npm
```bash
$ npm install uluru-crypto
```
Usage in node
```javascript
//require the exported object
const Uluru = require("uluru-crypto")

//or require specific functionalities that are needed
const {ChaCha20, Keccak800} = require("uluru-crypto")
```
Type declarations are present as well, located in the uluru.d.ts file.
### Browser
This will create a `Uluru` object in the global scope that can be used right away:
```html
<!--using jsderlivr to get the entry point of the npm package of the latest version-->
<script src="https://cdn.jsdelivr.net/npm/uluru-crypto/uluru.js"></script>

<!--automatically minified alternative-->
<script src="https://cdn.jsdelivr.net/npm/uluru-crypto/uluru.min.js"></script>
```
Also compatible with the AMD [requireJS](https://requirejs.org/):
```javascript
require("Uluru", (Uluru) => { /*...*/ })
```
### Custom compilation
If you wish to modify the source code (`./src/`) or the compilation options (`./tsconfig.json`):
```bash
#clone the repository
$ git clone https://github.com/Franatrtur/ulurujs
#compile the typescript code, you can modify tsconfig.json beforehand
$ npm run build

#to create minified uluru.min.js, !requires terser
$ npm run compress
#testing, for tests in browser open /test/test.html
$ npm run test
#benchmarks and performance tests
$ npm run bench
```
## String encodings
Uluru crypto implements the following encodings, working in all environments:
 - [ASCII](https://en.wikipedia.org/wiki/ASCII) or rather [Latin1](https://cs.wikipedia.org/wiki/ISO_8859-1)
 - [UTF-8](https://en.wikipedia.org/wiki/UTF-8)
 - [Hex](https://en.wikipedia.org/wiki/Hexadecimal) (hexadecimal digit encoding - base16)
 - [Base-64](https://en.wikipedia.org/wiki/Base64)  

Uluru uses fast native functions. If they are not present, a polyfill will be used instead (under the hood).
```typescript
//pseudo typescript code
Uluru.enc.encoding{
	encode: (str: string) => Uint8Array,
	decode: (bytes: ArrayBufferView) => string
}
Uluru.enc{Ascii, Utf8, Hex, Base64} implements Uluru.enc.encoding 
```
Example usages:
```javascript
const utf8 = new Uluru.enc.Utf8() //init an encoder
let binaryData = utf8.encode("a utf8 string 🤩Ξ↝") //returns a uint8array
let stringAgain = utf8.decode(binaryData) //returns "a utf8 string 🤩Ξ↝"
//or create an anonoymous encoder
binaryData = new Uluru.enc.Hex().encode("0f5e6a2669") //returns a uint8array
stringAgain = new Uluru.enc.Hex().decode(binaryData) //returns "0f5e6a2669"
```
## Hashing
Uluru crypto implements the [Keccak algorithm](https://keccak.team/) (the winner of the [SHA3](https://en.wikipedia.org/wiki/SHA-3) contest) in the variant Keccak800. This version, using 32bit words so that it works fast in javascript, is very secure. (s = 800, r = 512, c = 288).  

Uluru also exposes a safe simplified function for hashing if you aren't comfortable with working with raw data and binary operations. You can simply pass in a string and get a string of the hash back:
```javascript
let text = "some string i wana hash 🎃"
let checksum = Uluru.hash(text) //"428b796558599e4718e91f...
```
Using the basic keccak class:
```typescript
//structure (pseudocode):
class Keccak800 {
	constructor() //no arguments needed
	reset(): void //reverts all update() and finalize() calls
	update(data: string | ArrayBufferView): this //process data
	//default outputbytes = 32, can be any positive integer
	finalize(outputbytes?: number): {hash:  Uint8Array, toString?: function}
}
```
Example usage:
```javascript
let hasher = new Uluru.Keccak800() //init the hash process
hasher.update(some_data).update(more_data) //process data
let checksum = hasher.finalize(64).hash //get 64 bytes of the hash
```
## Symmetric encryption
Uluru crypto implements the [Chacha cipher](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant), which is a very secure symmetric stream cipher. In addition, during the encryption and decryption process, a 128bit [MAC](https://en.wikipedia.org/wiki/Message_authentication_code) is computed to verify the integrity of the message. This ensures the encrypted data was not mangled with in any way.  The whole process is symmetric so encryption and decryption are performed in the same way.  

Uluru also exposes safe simplified functions for encryption if you aren't comfortable with working with raw data and binary operations. You can simply pass in a message and a password:
```javascript
let plaintext = "very sensitive data", password = "my secret key"
let encrypted = Uluru.encrypt(plaintext, password)
try{
	let decrypted = Uluru.decrypt(encrypted, password)
} catch(error){
	//unable to decrypt (wrong password/incorrectly formatted ciphertext/modified ciphertext
}
```
Using the basic chacha class:
```typescript
//structure (pseudocode):
class ChaCha20 {
	constructor(
		key: ArrayBufferView, //typed array or a dataview of 32 bytes
		mac?: boolean, //do we compute the mac?
		nonce?: ArrayBufferView, //max 12 bytes, see the uluru random generation
		counter?: number //(32bit integer), default = 0
	)
	reset(): void //reverts all update() and finalize() calls
	counter: number //getter and setter for the counter
	getmac(): Uint8Array | false //returns the mac if this.domac == true
	verify(mac: ArrayBufferView): boolean //compares two MACs, returns true if equal
	update(data: string | ArrayBufferView): this //process data (string -> utf8)
	finalize(): {data: Uint8Array, mac: Uint8Array | false} //complete the process
}
```
```javascript
let encryptor = new Uluru.ChaCha20(key, !!domac, nonce) //init, leave counter = 0
encryptor.update(some_data).update(more_data) //... same as updating the data joined
let {data, mac} = encryptor.finalize() //returns an object

//if we init with the same parameters, the object can work as a encryptor and a decryptor
let decryptor = new Uluru.ChaCha20(key, !!domac, nonce) //or encryptor.reset()
let decrypted = decryptor.update(data).finalize().data //decrypt
var ok = decryptor.verify(mac) //verify the integrity of the message
```
## Asymmetric encryption
Uluru crypto implements the [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) algorithm, a safe algorithm standing strong after decades of cryptanalysis. The implementation relies on the javascript native [BigInt](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt) type. RSA can be used for key exchanges, digital signatures and certificates.
Following basic classes are exposed as interface with RSA functionalities:
```typescript
//structure (pseudocode):
class RSAKey {
	static fromBufferViews(
		bufferview1: ArrayBufferView,
		bufferview2:  ArrayBufferView
	): RSAKey
	static fromString(str: string): RSAKey
	constructor(exponent: bigint | number, mod: bigint | number)
	toString(): string
	encrypt(data: ArrayBufferView | string): {data: Uint8Array}
	decrypt(data: ArrayBufferView): {data: Uint8Array}
	sign(data: ArrayBufferView | string): {data, signature: Uint8Array}
	verify(data: ArrayBufferView | string, signature: ArrayBufferView): boolean
}

class RSAKeyPair {
	static publicprefix, privateprefix: string[] //the string formatting
	static fromString(str: string): RSAKeyPair
	static generate(bitlength: number = 3072): RSAKeyPair
	constructor(publickey: RSAKey, privatekey: RSAKey)
	public, private: RSAKey
	toString(): string
}

//Optimal assymetric encryption padding, used by default
class OAEP {
	constructor(){} //no arguments needed
	pad(data: any, len?: number): {data: Uint8Array}
	unpad(data: an): {data: Uint8Array}
}
```
### Generating an RSA keypair
To grenerate a pair of public and private key use the `Uluru.RSAKeyPair.generate` method. The recommended bitlength is 2048-4096, default is 3072 bits. The process of generating a keypair might take over a second depending on the size.  
Uluru also provides a simplified function that returns the stringified keypair of a safe bitlength.
```javascript
//using the simplified function
let keypairstring = Uluru.rsaGenerate()
//the stringified keys are separated by "!"
let publickeystr, privatekeystr = keypairstring.split("!")

// using the basic class interface
let keypair = Uluru.RSAKeyPair.generate(2560) //the bitlength can be specified
```
### RSA encryption and decryption
RSA encryption is generally slow and not suitable for encrypting large messages, Thererefore, it is usually only used for agreeing on a key for faster [symmetric encryption](#symmetric-encryption).
Uluru also provides simplified functions for safe RSA encryption and decryption. Just pass in the plaintext/ciphertext and the string of the public/private key to encrypt/decrypt.
```javascript
//using the simplified functions
let ciphertext = Uluru.rsaEncrypt("some message :)", publickeystr)
let plaintext = Uluru.rsaDecrypt(ciphertext, privatekeystr)

//using the basic interface
/*note the public key will have to be received first*/
let ciphertextdata = keypair.public.encrypt(some_data).data
let plaintextdata = keypair.private.decrypt(ciphertextdata).data
```
### RSA signatures
Hashes of a message created with a private key can only be decrypted using the corresponding public key. This enables not only integrity verification, but identity verification as well.  
Uluru also provides safe functions for digital signatures if you aren't comfortable with working with raw data and binary operations.
```javascript
//using the simplified functions
let messageToSign = "some message that needs authentication"
let signaturestr = Uluru.rsaSign(messageToSign, privatekeystr)
var ok = Uluru.rsaVerify(messageToSign, signaturestr, publickeystr)

//using the basic interface
let signature = keypair.private.sign(some_data).signature
var ok = keypair.public.verify(some_data, signature)
```
## Key derivation
bruh
## Key exchange
Uluru crypto implements the [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange), a well trusted method of key exchange.
```typescript
//structure (pseudocode):
class DiffieHellman {
	constructor(ebits?: number) //ebits = exponent bitlength = 384
	send(): Uint8Array //send public part
	receive(data: any): void //receive other side's public part
	finalize(length?: number): {result: Uint8Array} //derive shared secret
}
```
Usage:
```javascript
let exchange = new Uluru.DiffieHellman()
let send_part = exchange.send()
exchange.receive(received_part)
let shared_secret = exchange.finalize(32).result
```
## Random generation
Uluru is flexible and manages to get cryptographically secure randomness from the [node crypto](https://nodejs.org/api/crypto.html#cryptorandomfillsyncbuffer-offset-size) or the [webcrypto](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues) APIs. If no crypto object is available, `Uluru.Random.secure` will be equal to `false` and `Math.random` will be used instead (this will never happen in modern browsers and versions of node).
```typescript
//structure (pseudocode):
class Random {
	static secure: boolean
	word(): number //get a random 32bit integer
	fill(arr: ArrayBufferView | Array): ArrayBufferView | Array
}
```
Usage:
```javascript
let rand = new Uluru.Random()
let randomInt32 = rand.word()
let randomBytes = rand.fill(new Uint8Array(69))
//0-1 like Math.random
let randomFraction = rand.word() / 0x100000000
```
## Performance
in progress
