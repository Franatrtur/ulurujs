namespace Uluru {
	
	const Bi = BigInt

	const n1 = Bi(1)
	const n0 = Bi(0)

	const mask = bitlen => (n1 << Bi(bitlen)) - n1

	function bitlen(x: bigint){
		
		let bits = 0 //means that for 0 the Number of bits is also 0
		let bits32 = Bi(0x100000000)
		let stillbigger = true

		while (x){

			//optimization: go through bigger chunks of 32 bits if possible
			stillbigger = stillbigger && x > bits32

			bits += stillbigger ? 32 : 1
			x >>= Bi(stillbigger ? 32 : 1)

		}

		return bits

	}

	function modpow(base: bigint, exponent: bigint, modulus: bigint){

		let result = n1

		while(exponent){

			if((exponent & n1) == n1)
				result = (result * base) % modulus

			exponent >>= n1
			base = (base * base) % modulus

		}

		return result

	}

	function gcd(a: bigint, b: bigint): bigint{
				
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

	function randomBi(bitlength: number){

		let result = n0
		let rand32 = typeof crypto == "object" ? (() => crypto.getRandomValues(new Uint32Array(1))[0]) : Math.random

		for(let w = 0; w * 32 < bitlength; w++)
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
	

	function fermat(prime: bigint, iterations = 6){

		let randsize = Math.min(16, bitlen(prime) - 1)
		let base

		while(iterations--){

			base = randomBi(randsize) + Bi(5)

			if(modpow(base, prime - n1, prime) != n1)
				return false

		}

		return true
	}

	function millerrabin(prime: bigint, iterations = 6){

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

	function isprime(prime: bigint, iterations = 6){

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
	function modinv(int: bigint, modulus: bigint): bigint{ //int != 1

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

	function buffviewtobi(bufferview: ArrayBufferView){

		return Bi("0x" + new enc.Hex().decode(
			new Uint8Array(bufferview.buffer, bufferview.byteOffset || 0, bufferview.byteLength || 0)
		))

	}

	function bitobuffview(bigint: bigint){

		let stred = bigint.toString(16)
		return new enc.Hex().encode((stred.length % 2 == 1 ? "0" : "") + stred)

	}
	


	export class RSAKey {

		static fromBufferViews(bufferview1: ArrayBufferView, bufferview2: ArrayBufferView){

			return new this(buffviewtobi(bufferview1), buffviewtobi(bufferview2))

		}

		static fromString(str: string){

			let splitted = str.split("<")[1].split(">")[0].split("|")
			return this.fromBufferViews(new enc.Base64().encode(splitted[0]), new enc.Base64().encode(splitted[1]))

		}

		private E: bigint
		public M: bigint

		constructor(exponent: bigint | number, mod: bigint | number){

			this.E = Bi(exponent) //private/public exponent
			this.M = Bi(mod) //public component

		}

		toString(){

			return "<" + 
				new enc.Base64().decode(bitobuffview(this.E)) + 
				"|" + 
				new enc.Base64().decode(bitobuffview(this.M)) + 
				">"

		}

		protected process(data: ArrayBufferView){

			let databi = buffviewtobi(data)

			if(databi >= this.M)
				throw "Data integer too large"

			return bitobuffview(modpow(databi, this.E, this.M))

		}

		encrypt(data: ArrayBufferView | string){

			data = typeof data == "string" ? new enc.Utf8().encode(data as string) : data

			let msglen = (bitlen(this.M) >> 3) - 2 - OAEP.hdrlen

			if(data.byteLength > msglen)
				throw "Message too long"

			return {
				data: this.process(new OAEP().pad(data, msglen).data)
			}

		}

		decrypt(data: ArrayBufferView){

			return {
				data: new OAEP().unpad(this.process(data)).data
			}

		}

		sign(data: ArrayBufferView | string){

			data = typeof data == "string" ? new enc.Utf8().encode(data as string) : data

			let hash = new Keccak800().update(data).finalize(64).hash

			return {
				data,
				signature: this.encrypt(data).data
			}

		}

		verify(data: ArrayBufferView | string, signature: ArrayBufferView){

			data = typeof data == "string" ? new enc.Utf8().encode(data as string) : data

			let hash = new Keccak800().update(data).finalize(64).hash
			let authcode = this.decrypt(signature).data

			return hash.join(",") == authcode.join(",")

		}

	}

	//public exponent - fermat prime 2**8+1 = 257
	const PUBEXP = Bi(0x101)

	const PUBLICprefix = ["\n==BEGIN ULURU PUBLIC KEY==\n", "\n==END ULURU PUBLIC KEY==\n"]
	const PRIVATEprefix = ["\n==BEGIN ULURU PRIVATE KEY==\n", "\n==END ULURU PRIVATE KEY==\n"]

	export class RSAKeyPair {

		static pubexp = PUBEXP
		static publicprefix = PUBLICprefix
		static privateprefix = PRIVATEprefix

		static fromString(str: string){

			return new this(
				RSAKey.fromString(str.split(PUBLICprefix[0])[1].split(PUBLICprefix[1])[0]),
				RSAKey.fromString(str.split(PRIVATEprefix[0])[1].split(PRIVATEprefix[1])[0])
			)

		}

		static generate(bitlength: number){

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

		public public: RSAKey
		private private: RSAKey

		constructor(publickey: RSAKey, privatekey: RSAKey){

			this.public = publickey
			this.private = privatekey

		}

		toString(){

			return PUBLICprefix[0] + this.public.toString() + PUBLICprefix[1] + "\n" +
				PRIVATEprefix[0] + this.private.toString() + PRIVATEprefix[1]

		}

	}

}