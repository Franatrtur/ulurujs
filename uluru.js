/*
Copyright (c) 2021 Franatrtur

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

/*

Uluru crypto - a lightweight cryptographic library designed to be simple to use
minimal
modern
fast
simple

*/

;((function(pkg, pkgname){

	if (typeof global != 'undefined')
		module.exports = pkg

	else if (typeof globalThis != 'undefined')
		globalThis[pkgname] = pkg

	else if (typeof window != 'undefined')
		window[pkgname] = pkg

	else
		throw "No global context found"

})((function(){

	//shortcuts for the minifier
	const U8Arr = Uint8Array
	const U32Arr = Uint32Array

	//character encodings

	class Ascii {

		encode(string){

			let u8array = new U8Arr(string.length)

			for(let i = 0, l = string.length; i < l; i++)
				u8array[i] = string.charCodeAt(i)

			return u8array
		}

		decode(u8array){

			return String.fromCharCode(...u8array)
		}
	}

	class Utf8 {

		encode(string){

			return typeof TextEncoder == "function" ?
				new TextEncoder().encode(string) :
				new Ascii().encode(unescape(encodeURIComponent(string)))
		}

		decode(u8array){

			return typeof TextDecoder == "function" ?
				new TextDecoder("utf8").decode(u8array) :
				decodeURIComponent(escape(new Ascii().decode(u8array)))
		}
	}
	//amogus

	//lookup tables for the hexadecimal encoding
	const hexchars = Array(256)
	const hexcodes = {}
	let code

	for(let c = 0; c < 256; c++){

		code = ("00" + c.toString(16)).slice(-2)
		hexchars[c] = code
		hexcodes[code] = c
	}

	class Hex {

		encode(string){

			let u8array = new U8Arr(string.length >> 1)

			for(let i = 0, l = string.length; i < l; i += 2)
				u8array[i >> 1] = hexcodes[string.slice(i, i + 2)]

			return u8array
		}

		decode(u8array){

			let string = []

			for(let i = 0, l = u8array.length; i < l; i++)
				string.push(hexchars[u8array[i]])

			return string.join("")
		}
	}

	class Base64 {

		encode(string){

			return new Ascii().encode(atob(string))
		}

		decode(u8array){

			return btoa(new Ascii().decode(u8array))
		}
	}

	const CONSTcc = new U32Arr(new Ascii().encode("expand 32-byte k").buffer) //nothing-up-my-sleeve constants

	/**
	 * a modified version of the chacha20 stream cipher
	 * the cipher uses the original chacha function and rounds
	 * except that we diffuse the entropy of the key with some 8 doublerounds of column/row rounds
	 * our nonce and counter are 32bit
	 * 
	 * it uses my custom MACing system that is *symmetrical*
	 * so the cipher can still be used in both ways, encrypting will produce the same mac as decrypting
	 * this is done by computing two checksums, one for the plaintext, other one for the ciphertext
	 * then we xor them and permute the resulting mac
	 */
	class ChaCha20 {

		reset(){

			this.xstate = new U32Arr(16)

			this.pmac = this.domac ? new U32Arr(CONSTcc) : false
			this.cmac = this.domac ? new U32Arr(CONSTcc) : false

			this.data = new U32Arr(0)
			this.pointer = 0
			this.sigbytes = 0
		}

		constructor(key, mac = true, nonce = 0, counter = 0){

			this.state = new U32Arr(16)
			let st = this.state

			st.set(CONSTcc)
			st.set(new U32Arr(key.buffer), 4)
			st[13] = nonce

			//spread entropy
			for(let sprd = 0; sprd < 8; sprd++){
				//cols
				for(let e = 0; e < 4; e++)
					this.QR(st, e, e + 4, e + 8, e + 12)
				//rows
				for(let o = 0; o < 16; o += 4)
					this.QR(st, o, o + 1, o + 2, o + 3)
	 		}

	 		this.prectr = st[15]
			st[15] ^= counter

			this.ctr = counter

			this.domac = !!mac
			this.reset()
		}

		QR(s, A, B, C, D){

			s[A] += s[B]
			s[D] ^= s[A]
			s[D] = s[D] << 16 | s[D] >>> 16
			
			s[C] += s[D]
			s[B] ^= s[C]
			s[B] = s[B] << 12 | s[B] >>> 20

			s[A] += s[B]
			s[D] ^= s[A]
			s[D] = s[D] << 8 | s[D] >>> 24
			
			s[C] += s[D]
			s[B] ^= s[C]
			s[B] = s[B] << 7 | s[B] >>> 25
		}

		getmac(){

			if(!this.pmac)
				return false

			let mac = new U32Arr([
				this.pmac[0] ^ this.cmac[0],
				this.pmac[1] ^ this.cmac[1],
				this.pmac[2] ^ this.cmac[2],
				this.pmac[3] ^ this.cmac[3],
			])

			for(let mr = 0; mr < 4; mr++){

				this.QR(mac, 0, 1, 2, 3)
				this.QR(mac, 3, 0, 1, 2)
				this.QR(mac, 2, 3, 0, 1)
				this.QR(mac, 1, 2, 3, 0)
			}

			for(let re = 0; re < 4; re++)
				mac[re] += this.pmac[re] + this.cmac[re]

			return new U8Arr(mac.buffer)
		}

		process(flush = false){

			let blocks = (flush ? Math.ceil : Math.floor)((this.sigbytes - this.pointer) / 16)

			let ptw, ctw

			let end = Math.ceil(this.sigbytes / 4) - 1
			let erase = 4 - this.sigbytes % 4

			this.state[15] = this.prectr ^ (this.ctr + (this.pointer >> 4))

			for(let b = 0; b < blocks; b++){

				let xs = this.xstate

				xs.set(this.state)

				//permute
				for(let drnd = 0; drnd < 20; drnd += 2){

					//even round - columns
					this.QR(xs, 0, 4,  8, 12)
		 			this.QR(xs, 1, 5,  9, 13)
		 			this.QR(xs, 2, 6, 10, 14)
		 			this.QR(xs, 3, 7, 11, 15)

					//odd round - diagonals
		 			this.QR(xs, 0, 5, 10, 15)
		 			this.QR(xs, 1, 6, 11, 12)
		 			this.QR(xs, 2, 7,  8, 13)
		 			this.QR(xs, 3, 4,  9, 14)
		 		}

		 		//combine
				for(let i = 0; i < 16 && this.pointer + i <= end; i++){

					ptw = this.data[this.pointer + i]
					ctw = ptw ^ (this.xstate[i] + this.state[i])

					if(this.pointer + i == end)
						ctw = ctw << erase * 8 >>> erase * 8 //erase the needless bytes, keeping in mind that uint32array is little-endian!

					this.data[this.pointer + i] = ctw

					if(this.domac){

						this.pmac[i & 3] += ptw ^ this.xstate[i] // i & 3 is the same as i % 4
						this.cmac[i & 3] += ctw ^ this.xstate[i]

						this.QR(this.pmac, i & 3, (i + 1) & 3, (i + 2) & 3, (i + 3) & 3)
						this.QR(this.cmac, i & 3, (i + 1) & 3, (i + 2) & 3, (i + 3) & 3)
					}
				}

		 		this.pointer += 16

				this.state[15]++
			}
		}

		append(data){

			data = typeof data == "string" ? new Utf8().encode(data) : data

			let old = this.data

			let newlen = Math.ceil((this.sigbytes + data.byteLength) / 64) * 64
			this.data = new U8Arr(newlen)

			this.data.set(new U8Arr(old.buffer, 0, this.sigbytes))
			this.data.set(new U8Arr(data.buffer), this.sigbytes)

			this.data = new U32Arr(this.data.buffer)
			this.sigbytes += data.byteLength
		}

		update(data){
			
			this.append(data)
			this.process(false)

			return this
		}

		finalize(){

			this.process(true)

			return {

				data: new U8Arr(this.data.buffer, 0, this.sigbytes),
				mac: this.getmac()
			}
		}

	}


	const RHOoffets = [
		 0,  1, 62, 28, 27,
		36, 44,  6, 55, 20,
		 3, 10, 43, 25, 39,
		41, 45, 15, 21,  8,
		18,  2, 61, 56, 14
	]

	const RCs = new U32Arr([
		 0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009,
		 0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
		 0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008
	])


	/*
	 * implementation of the keccak800 algorithm as accurately as i could (idk about the uint32array endianness, padding etc)
	 * smaller sibling to the keccak1600 used as sha3 (but that requires 64bit words)
	 */
	class Keccak800 {

		reset(){

			this.state = new U32Arr(25)

			this.temp = new U32Arr(25)
			this.theta = new U32Arr(5)

			this.data = new U32Arr(0)
			this.padblock = new U32Arr(16)
			this.sigbytes = 0
		}

		constructor(){

			this.reset()
		}

		keccakF(state){

			let temp = this.temp,
				theta = this.theta
			let off, tmp

			for(var round = 0; round < 22; round++){

				theta[0] = state[ 0] ^ state[ 1] ^ state[ 2] ^ state[ 3] ^ state[ 4]
				theta[1] = state[ 5] ^ state[ 6] ^ state[ 7] ^ state[ 8] ^ state[ 9]
				theta[2] = state[10] ^ state[11] ^ state[12] ^ state[13] ^ state[14]
				theta[3] = state[15] ^ state[16] ^ state[17] ^ state[18] ^ state[19]
				theta[4] = state[20] ^ state[21] ^ state[22] ^ state[23] ^ state[24]

				for(var x = 0; x < 5; x++) for(var y = 0; y < 5; y++){

					tmp = theta[(x + 1) % 5]

					state[x*5 + y] ^= theta[(x + 4) % 5] ^ (tmp << 1 | tmp >>> 31)

					off = RHOoffets[x*5 + y]
					tmp = state[x*5 + y]
					temp[y*5 + (2*x + 3*y) % 5] = tmp << off | tmp >>> (32 - off)
				}

				for(var x = 0; x < 5; x++) for(var y = 0; y < 5; y++)
					state[x*5 + y] = temp[x*5 + y] ^ ((~temp[((x + 1) % 5) * 5 + y]) & temp[((x + 2) % 5) * 5 + y])

				state[0] ^= RCs[round]
			}
		}

		process(flush = false){

			let blocks = this.data.length / 16

			for(let b = 0; b < blocks; b++){

				for(let w = 0; w < 16; w++)
					this.state[w] ^= this.data[b * 16 + w]

				this.keccakF(this.state)
			}

			if(flush){

				for(let w = 0; w < 16; w++)
					this.state[w] ^= this.padblock[w]

				this.keccakF(this.state)
			}
		}

		append(data){

			data = typeof data == "string" ? new Utf8().encode(data) : data
			let thisdata = this.data
			let thispadblock = this.padblock

			//incomplete block
			if(data.byteLength + this.sigbytes < 64){

				thispadblock = new U8Arr(thispadblock.buffer)
				thispadblock.set(new U8Arr(data.buffer), this.sigbytes)

				thispadblock[thispadblock.length - 1] = 0x80
				thispadblock[data.byteLength + this.sigbytes] ^= 0x06

				this.padblock = new U32Arr(thispadblock.buffer)
				this.sigbytes += data.byteLength
			}
			//new complete block
			else{

				let newlen = Math.floor((this.sigbytes + data.byteLength) / 64) * 64 // >> 6 << 6
				let overflow = (this.sigbytes + data.byteLength) % 64

				//optimization, use existing data buffer we can
				thisdata = thisdata.byteLength >= newlen ? new U8Arr(thisdata.buffer, 0, newlen) : new U8Arr(newlen)

				thisdata.set(new U8Arr(thispadblock.buffer, 0, this.sigbytes))
				thisdata.set(new U8Arr(data.buffer, 0, data.byteLength - overflow), this.sigbytes)

				thisdata = new U32Arr(thisdata.buffer, 0, newlen >> 2)

				//append the overflow as a new incomplete block

				thispadblock.fill(0)
				this.sigbytes = 0

				if(overflow > 0)
					this.append(new U8Arr(data.buffer, data.byteLength - overflow))
			}
		}

		update(data){

			this.append(data)
			this.process(false)

			return this
		}

		finalize(outputbytes = 32){

			this.process(true)

			let len = Math.ceil(outputbytes / 64) * 16
			let result = new U32Arr(len)

			for(let i = 0; i < len; i += 16){

				result.set(new U32Arr(this.state.buffer, 0, 16), i)
				this.keccakF(this.state)
			}

			return {

				toString(encoder){

					return new (encoder || Hex)().decode(this.hash)
				},

				hash: new U8Arr(result.buffer, 0, outputbytes)
			}
		}

	}


	//custom password-based key derivation
	//uses reseeding of a finalized hasher
	//simplified because we can have any output length
	class Pbkdf {

		constructor(outputbytes = 32, iterations = 1000){

			this.outputbytes = outputbytes
			this.iterations = iterations
		}

		compute(password, salt){

			let result = new U8Arr(this.outputbytes)
			let block
			let hasher = new Keccak800()

			hasher.update(new U32Arr([salt]))
			hasher.finalize(0)
			
			for(let i = 0; i < this.iterations; i++){

				hasher.update(password)
				block = hasher.finalize(this.outputbytes).hash

				for(let b = 0; b < result.length; b++)
					result[b] ^= block[b]
			}

			return result
		}

	}

	//functions for simplified user interaction
	//using pbkdf with 10000 iterations to slow down the key generation

	function encrypt(plaintext, password){

		//get random salt, securely if we can ඞ
		let salt = typeof crypto == "object" ? 
					crypto.getRandomValues(new U32Arr(1))[0] :
					Math.floor(Math.random() * 0x100000000)

		let key = new Pbkdf(32, 10000).compute(new Utf8().encode(password), salt)

		let encryptor = new ChaCha20(key, true, salt)

		encryptor.update(new Utf8().encode(plaintext))

		let encrypted = encryptor.finalize()

		return  new Hex().decode(new U8Arr(new U32Arr([salt]).buffer)) +
				new Base64().decode(encrypted.data) +
				new Hex().decode(encrypted.mac)
	}

	function decrypt(ciphertext, password){

		let salt, cdata, macstr

		try{

			salt = new U32Arr(new Hex().encode(ciphertext.slice(0, 8)).buffer)[0]
			cdata = new Base64().encode(ciphertext.slice(8, -32))
			macstr = ciphertext.slice(-32)
		}
		catch(e){
			throw "Incorrectly formated ciphertext"
		}

		let key = new Pbkdf(32, 10000).compute(new Utf8().encode(password), salt)

		let decryptor = new ChaCha20(key, true, salt)

		decryptor.update(cdata)

		let decrypted = decryptor.finalize()

		if(new Hex().decode(decrypted.mac) != macstr)
			throw "Invalid authentication"

		return new Utf8().decode(decrypted.data)
	}

	function hash(text){

		return new Keccak800().update(new Utf8().encode(text)).finalize().toString(Hex)
	}

	//export everything
	return {
		version: "1.0",
		author: "Franatrtur",
		enc: {
			Hex,
			Utf8,
			Ascii,
			Base64
		},
		ChaCha20,
		Keccak800,
		Pbkdf,
		encrypt,
		decrypt,
		hash
	}

})(), "Uluru"));
