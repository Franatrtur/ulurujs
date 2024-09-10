
<img src="https://i.ibb.co/p1K4cDf/final.png" alt="drawing" height="80"/><br>
Uluru crypto - a self-containted universal cryptographic library designed with simplicity of usage in mind.

# Uluru crypto in javascript
![GitHub](https://img.shields.io/github/license/Franatrtur/ulurujs?style=for-the-badge)  ![npm version](https://img.shields.io/npm/v/uluru-crypto?label=npm%20version&style=for-the-badge) ![npm bundle size](https://img.shields.io/bundlephobia/min/uluru-crypto?style=for-the-badge)

Uluru JS is written in [typescript](https://www.typescriptlang.org/) and compiled to javascript to be used in both nodeJS (see on [npm](https://npmjs.com/package/uluru-crypto)) and the web, without any dependencies whatsoever. The uluru crypto implementation takes advantage of modern javascript features (e.g. typed arrays) for better performance.  
See [file encryption demo](https://franatrtur.github.io/file-encryption)    
   
Features:
 - symmetric encryption with ChaCha20
 - hashing, PBKDF and HMAC with Keccak800
 - RSA (asymmetric encryption, signing, key generation) and diffie hellman key exchange
 - character encodings (Utf8, Ascii, Base64, Hex)
 - secure generation of random bytes
## Quick start
Node:
```bash
$ npm install uluru-crypto
```
```javascript
import { encrypt, decrypt, hash } from "uluru-crypto" //ES modules
const { encrypt, decrypt, hash } = require("uluru-crypto") //common js

let encrypted = encrypt("some sensitive data!", "secret password")
let decrypted = decrypt(encrypted, "secret password") //"some sensitive data!"
let checksum = hash("some string to hash") //"00d5c7aff4b3f0c...
```
Browser:
```html
<script src="https://unpkg.com/uluru-crypto"></script>
<script>
	//in browser use the ready Uluru object:
	const { encrypt, decrypt, hash } = Uluru
</script>
```

## For more, see the docs at the [git wiki](https://github.com/Franatrtur/ulurujs/wiki)
