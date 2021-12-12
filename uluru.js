/*
LICENSED UNDER THE MIT LICENSE: https://github.com/Franatrtur/ulurucrypto/blob/main/LICENSE
*/

;((function(pkg, pkgname){

	let globthis = typeof window == "object" ? window : global

	let package = Object.assign(typeof globthis[pkgname] == "object" ? globthis[pkgname] : (globthis[pkgname] = {}), pkg)

	if (typeof module != 'undefined' && typeof module.exports != "undefined")
		module.exports = package

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
	 * A modified version of the chacha20 stream cipher
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

			if(!this.domac)
				return false

			let pm = this.pmac,
				cm = this.cmac

			let mac = new U32Arr([
				pm[0] ^ cm[0],
				pm[1] ^ cm[1],
				pm[2] ^ cm[2],
				pm[3] ^ cm[3],
			])

			for(let mr = 0; mr < 4; mr++){

				this.QR(mac, 0, 1, 2, 3)
				this.QR(mac, 3, 0, 1, 2)
				this.QR(mac, 2, 3, 0, 1)
				this.QR(mac, 1, 2, 3, 0)
			}

			for(let re = 0; re < 4; re++)
				mac[re] += pm[re] + cm[re]

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

						this.pmac[i & 3] ^= ptw + this.xstate[i] // i & 3 is the same as i % 4
						this.cmac[i & 3] ^= ctw + this.xstate[i]

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
			this.data.set(new U8Arr(data.buffer, data.byteOffset, data.byteLength), this.sigbytes)

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


	const RHOoffets = new U8Arr([
		 0,  1, 62, 28, 27,
		36, 44,  6, 55, 20,
		 3, 10, 43, 25, 39,
		41, 45, 15, 21,  8,
		18,  2, 61, 56, 14
	])

	const RCs = new U32Arr([
		0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009,
		0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
		0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008
	])

	//keccak coordinates precomputation

	//x mod plus 1
	const XMP1 = new U8Arr(25)
	//x mod minus 1
	const XMM1 = new U8Arr(25)
	//x y permutation
	const XYP = new U8Arr(25)
	//x plus 1 - next lane
	const XP1 = new U8Arr(25)
	//x plus 2 - next lane
	const XP2 = new U8Arr(25)

	let nx, ny

	//walk matrix 5x5
	for(let n = 0; n < 25; n++){

		nx = n % 5
		ny = Math.floor(n / 5)

		XMP1[n] = (nx + 1) % 5
		XMM1[n] = (nx + 4) % 5
		XYP[n] = ny*5 + (2*nx + 3*ny) % 5
		XP1[n] = ((nx + 1) % 5) * 5 + ny
		XP2[n] = ((nx + 2) % 5) * 5 + ny
	}

	/*
	 * An implementation of the keccak800 algorithm as accurately as i could (idk about the uint32array endianness, padding etc)
	 * smaller sibling to the keccak1600 used as sha3 (but that requires 64bit words)
	 * built with capacity 64 bytes and 36 private state bytes
	 */
	class Keccak800 {

		reset(){

			this.state = new U32Arr(25)

			this.temp = new U32Arr(25)
			this.theta = new U32Arr(5)

			this.data = new U32Arr(0)
			this.padblock = new U32Arr(16)
			this.padsigbytes = 0
			this.pointer = 0
		}

		constructor(){

			this.reset()
		}

		keccakF(state){

			let temp = this.temp,
				theta = this.theta
			let off, tmp

			for(let round = 0; round < 22; round++){

				theta[0] = state[ 0] ^ state[ 1] ^ state[ 2] ^ state[ 3] ^ state[ 4]
				theta[1] = state[ 5] ^ state[ 6] ^ state[ 7] ^ state[ 8] ^ state[ 9]
				theta[2] = state[10] ^ state[11] ^ state[12] ^ state[13] ^ state[14]
				theta[3] = state[15] ^ state[16] ^ state[17] ^ state[18] ^ state[19]
				theta[4] = state[20] ^ state[21] ^ state[22] ^ state[23] ^ state[24]

				for(let i = 0; i < 25; i++){

					tmp = theta[XMP1[i]]

					state[i] ^= theta[XMM1[i]] ^ (tmp << 1 | tmp >>> 31)

					off = RHOoffets[i]
					tmp = state[i]
					temp[XYP[i]] = tmp << off | tmp >>> (32 - off)
				}

				for(let i = 0; i < 25; i++)
					state[i] = temp[i] ^ (~temp[XP1[i]] & temp[XP2[i]])

				state[0] ^= RCs[round]
			}
		}

		process(flush = false){

			let blocks = (this.data.length - this.pointer) / 16

			for(let b = 0; b < blocks; b++){

				for(let w = 0; w < 16; w++)
					this.state[w] ^= this.data[this.pointer + w]

				this.keccakF(this.state)
				this.pointer += 16
			}

			if(flush){

				for(let w = 0; w < 16; w++)
					this.state[w] ^= this.padblock[w]

				this.keccakF(this.state)
			}
		}

		append(data){

			data = typeof data == "string" ? new Utf8().encode(data) : data
			//shortcuts for the minifier
			let thisdata = this.data
			let padblock = this.padblock
			let padsigbytes = this.padsigbytes

			//incomplete block
			if(data.byteLength + padsigbytes < 64){

				padblock = new U8Arr(padblock.buffer)
				padblock.set(new U8Arr(data.buffer, data.byteOffset, data.byteLength), padsigbytes)

				padblock[padblock.length - 1] = 0x80
				padblock[data.byteLength + padsigbytes] ^= 0x06

				this.padblock = new U32Arr(padblock.buffer)
				this.padsigbytes += data.byteLength
			}
			//new complete block
			else{

				let newlen = (padsigbytes + data.byteLength) >> 6 << 6 // floor(len / 64) * 64
				let overflow = (padsigbytes + data.byteLength) % 64

				//optimization, use existing data buffer we can, useful for repeptitive updating
				thisdata = thisdata.byteLength > newlen ? new U8Arr(thisdata.buffer, 0, newlen) : new U8Arr(newlen)

				thisdata.set(new U8Arr(padblock.buffer, 0, padsigbytes))
				thisdata.set(new U8Arr(data.buffer, data.byteOffset, data.byteLength - overflow), padsigbytes)

				this.data = new U32Arr(thisdata.buffer, 0, newlen >> 2)

				//append the overflow as a new incomplete block

				padblock.fill(0)
				this.padsigbytes = 0

				if(overflow > 0)
					this.append(new U8Arr(data.buffer, data.byteOffset + data.byteLength - overflow, overflow))
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


	/*
	 * Custom password-based key derivation function
	 * uses reseeding of a finalized hasher
	 * simplified because we can have any output length
	 */
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
	//using pbkdf with 1000 iterations to slow down the key generation

	function encrypt(plaintext, password){

		//get random salt, securely if we can ඞ
		let salt = typeof crypto == "object" ? 
					crypto.getRandomValues(new U32Arr(1))[0] :
					Math.floor(Math.random() * 0x100000000)

		let key = new Pbkdf(32, 1000).compute(new Utf8().encode(password), salt)

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

		let key = new Pbkdf(32, 1000).compute(new Utf8().encode(password), salt)

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

	const Bi = BigInt

	const n1 = Bi(1)
	const n0 = Bi(0)

	const mask = bitlen => (n1 << Bi(bitlen)) - n1

	function bitlen(x){
		
		let bits = 0 //means that for 0 the Number of bits is also 0
		let bits32 = Bi(0x100000000)
		let stillbigger = true

		while (x){

			//optimization: go through bigger chunks of 32 bits if possible
			stillbigger &&= x > bits32

			bits += stillbigger ? 32 : 1
			x >>= Bi(stillbigger ? 32 : 1)
		}

		return bits
	}

	function modpow(base, exponent, modulus){

		let result = n1

		while(exponent){

			if((exponent & n1) == n1)
				result = (result * base) % modulus

			exponent >>= n1
			base = (base * base) % modulus
		}

		return result
	}

	function gcd(a, b){
				
		if(b > a)
			[a, b] = [b, a]

		while(true){

			if(b === n0)
				return a

			a %= b

			if(a === n0)
				return b

			b %= a
		}
	}

	function randomBi(bitlength){

		let result = n0
		let rand32 = typeof crypto == "object" ? (() => crypto.getRandomValues(new U32Arr(1))[0]) : Math.random

		for(var w = 0; w * 32 < bitlength; w++)
			result = (result << Bi(32)) | Bi(rand32())

		return result & mask(bitlength)
	}

	//primes smaller than 1024
	let smallprimes = [Bi(2)]

	small: for(let n = 3; n < 1024; n += 2){

		for(let co = 1; co < smallprimes.length; co++)
			if(Bi(n) % smallprimes[co] === BigInt(0))
				continue small

		smallprimes.push(Bi(n))
	}
	

	function fermat(prime, iterations = 6){

		let randsize = Math.min(16, bitlen(prime) - 1)
		let base

		while(iterations--){

			base = randomBi(randsize) + Bi(5)

			if(modpow(base, prime - n1, prime) != n1)
				return false
		}

		return true
	}

	function millerrabin(prime, iterations = 6){

		let s = n0, d = prime - n1
		let randsize = Math.min(16, bitlen(prime) - 1)

		while(!((d & n1) != n1)){

			d >>= n1
			s++
		}

		let a, x
		let cant1 = n1, cant2 = prime - n1

		iter: while(iterations--){

			a = randomBi(randsize) + Bi(5)
			x = modpow(a, d, prime)

			if(x == cant1 || x == cant2)
				continue iter

			for(let i = n0, l = s - n1; i < l; i++){

				x = modpow(x, Bi(2), prime)

				if(x == cant1)
					return false

				if(x == cant2)
					continue iter
			}

			return false
		}

		return true
	}

	function isprime(prime, iterations = 6){

		for(let i = 0, l = smallprimes.length; i < l; i++)
			if(prime % smallprimes[i] == n0)
				return prime == smallprimes[i]

		return millerrabin(prime, iterations) && fermat(prime, iterations)
	}

	function prime(bitlength, iterations = 6, attempts = 100000){

		let candidate

		for(let i = 0; i < attempts; i++){

			candidate = randomBi(bitlength) | n1 | (n1 << Bi(bitlength - 1))

			if(isprime(candidate, iterations))
				return candidate
		}

		throw "Cannot find a prime"
	}

	//code design from: https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/#tablist3-tab7
	function modinv(int, modulus){ //int != 1

		let mod0 = modulus
		let y = n0, x = n1
		let quot, temp
	 
		while(int > 1){

			quot = int / modulus
			temp = modulus

			//as euclids algorigm
			modulus = int % modulus
			int = temp
			temp = y

			y = x - quot * y
			x = temp
		}
	 
		return x < 0 ? x + mod0 : x
	}

	function buffviewtobi(bufferview){

		return Bi("0x" + new Hex().decode(
			new U8Arr(bufferview.buffer, bufferview.byteOffset || 0, bufferview.byteLength || 0)
		))
	}

	function bitobuffview(bigint){

		let stred = bigint.toString(16)
		return new Hex().encode((stred.length % 2 == 1 ? "0" : "") + stred)
	}

	function merge(...bufferviews){

		let len = 0
		for(let i = 0; i < bufferviews.length; i++)
			len += bufferviews[i].byteLength

		let result = new Uint8Array(len)
		let pointer = 0
		for(let i = 0; i < bufferviews.length; i++){

			result.set(new U8Arr(bufferviews[i].buffer, bufferviews[i].byteOffset, bufferviews[i].byteLength), pointer)
			pointer += bufferviews[i].byteLength
		}

		return result
	}

	const SEEDlen = 12
	const HASHlen = 16
	const HDRlen = SEEDlen + HASHlen + 4

	class OAEP {

		pad(data, len){

			let padxdata = new U8Arr(len - HDRlen)
			padxdata.set(data)

			let datalen = new U32Arr([data.byteLength])
			let seed = crypto.getRandomValues(new U8Arr(SEEDlen))
			let hash = new Keccak800().update(padxdata).update(datalen).update(seed).finalize(HASHlen).hash

			let header = merge(datalen, seed, hash)

			let mask = new Keccak800().update(header).finalize(len - HDRlen).hash
			for(let m0 = 0; m0 < len - HDRlen; m0++)
				padxdata[m0] ^= mask[m0]

			mask = new Keccak800().update(padxdata).finalize(HDRlen).hash
			for(let m1 = 0; m1 < HDRlen; m1++)
				header[m1] ^= mask[m1]

			return merge(header, padxdata)
		}

		unpad(data){

			let len = data.byteLength

			let header = new U8Arr(data.buffer, 0, HDRlen).slice()
			let padxdata = new U8Arr(data.buffer, HDRlen).slice()

			let mask = new Keccak800().update(padxdata).finalize(HDRlen).hash
			for(let m1 = 0; m1 < HDRlen; m1++)
				header[m1] ^= mask[m1]

			mask = new Keccak800().update(header).finalize(len - HDRlen).hash
			for(let m0 = 0; m0 < len - HDRlen; m0++)
				padxdata[m0] ^= mask[m0]

			let datalen = new U32Arr(header.buffer, 0, 1)
			let seed = new U8Arr(header.buffer, 4, SEEDlen)
			let hash = new U8Arr(header.buffer, 4 + SEEDlen, HASHlen)

			let rehash = new Keccak800().update(padxdata).update(datalen).update(seed).finalize(HASHlen).hash
			if(rehash.join(",") != hash.join(","))
				throw "OAEP invalid padding hash"

			return new U8Arr(padxdata.buffer, 0, datalen[0])
		}

	}


	class RSAKey {

		static fromBufferViews(bufferview1, bufferview2){

			return new this(buffviewtobi(bufferview1), buffviewtobi(bufferview2))
		}

		static fromString(str){

			let splitted = str.split("<")[1].split(">")[0].split("|")
			return this.fromBufferView(new Base64().encode(splitted[0]), new Base64().encode(splitted[1]))
		}

		constructor(exponent, mod){

			this.E = Bi(exponent) //private/public exponent
			this.M = Bi(mod) //public component
		}

		toString(){

			return "<" + new Base64().decode(bitobuffview(this.E)) + "|" + new Base64().decode(bitobuffview(this.M)) + ">"
		}

		process(data){

			let databi = buffviewtobi(data)

			if(databi >= this.M)
				throw "Data integer too large"

			return bitobuffview(modpow(databi, this.E, this.M))
		}

		encrypt(data){

			data = typeof data == "string" ? new Utf8().encode(data) : data

			let msglen = (bitlen(this.M) >> 3) - 2 - HDRlen

			if(data.byteLength > msglen)
				throw "Message too long"

			return {
				data: this.process(new OAEP().pad(data, msglen))
			}
		}

		decrypt(data){

			return {
				data: new OAEP().unpad(this.process(data))
			}
		}

	}

	//public exponent - fermat prime 2**8+1 = 257
	const PUBEXP = Bi(0x101)

	const PUBLICprefix = ["\n==BEGIN ULURU PUBLIC KEY==\n", "\n==END ULURU PUBLIC KEY==\n"]
	const PRIVATEprefix = ["\n==BEGIN ULURU PRIVATE KEY==\n", "\n==END ULURU PRIVATE KEY==\n"]

	class RSAKeyPair {

		static fromString(str){

			return new this(
				RSAKey.fromString(str.split(PUBLICprefix[0])[1].split(PUBLICprefix[1])[0]),
				RSAKey.fromString(str.split(PRIVATEprefix[0])[1].split(PRIVATEprefix[1])[0])
			)
		}

		static generate(bitlength){

			if(!bitlength)
				return

			bitlength >>= 1

			let E = PUBEXP

			let prime1 = prime(bitlength), prime2 = prime(bitlength)

			let N = prime1 * prime2
			let phi = (prime1 - n1) * (prime2 - n1)
			let D = modinv(E, phi)

			return new this(new RSAKey(E, N), new RSAKey(D, N))
		}

		constructor(publickey, privatekey){

			this.public = publickey
			this.private = privatekey
		}

		toString(){

			return PUBLICprefix[0] + this.public.toString() + PUBLICprefix[1] + "\n" +
					PRIVATEprefix[0] + this.private.toString() + PRIVATEprefix[1]
		}

	}

	//export everything
	return {
		version: "2.0",
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
		OAEP,
		RSAKey,
		RSAKeyPair,
		encrypt,
		decrypt,
		hash
	}

})(), "Uluru"));
