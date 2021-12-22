
<img src="https://i.ibb.co/p1K4cDf/final.png" alt="drawing" height="80"/><br>
Uluru crypto - a universal cryptolibrary designed with simplicity of usage in mind
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

#to create minified uluru.min.js
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
//pseudo typescript code
Uluru.Keccak800 {
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
//pseudo typescript code
Uluru.ChaCha20 {
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
let ok = decryptor.verify(mac) //verify the integrity of the message
```
## Asymmetric encryption
Uluru crypto implements the [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) algorithm, a safe algorithm standing strong after decades of cryptanalysis. The implementation relies on the javascript native [BigInt](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt) type.
## Performance
in progress
