import Hex from "../../enc/hex"
import Random from "../random"

export const Bi = BigInt

const n1 = Bi(1)
const n0 = Bi(0)

export function mask(bitlen: number): bigint{
	
	return (n1 << Bi(bitlen)) - n1

}

export function bitLength(x: bigint): number{
	
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

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint{

	let result = n1

	while(exponent){

		if((exponent & n1) == n1)
			result = (result * base) % modulus

		exponent >>= n1
		base = (base * base) % modulus

	}

	return result

}

export function randomBi(bitlength: number): bigint{

	let result = n0
	let rand = new Random()

	for(let w = 0; w * 32 < bitlength; w++)
		result = (result << Bi(32)) | Bi(rand.word())

	return result & mask(bitlength)

}

//primes smaller than 1024
let smallprimes = [Bi(2)]

small: for(let n = 3; n < 1024; n += 2){

	for(let co = 1; co < smallprimes.length; co++)
		if(Bi(n) % smallprimes[co] === n0)
			continue small

	smallprimes.push(Bi(n))

}


export function fermatTest(prime: bigint, iterations: number = 6): boolean{

	let randsize = Math.min(16, bitLength(prime) - 1)
	let base

	while(iterations--){

		base = randomBi(randsize) + Bi(5)

		if(modPow(base, prime - n1, prime) != n1)
			return false

	}

	return true
}

export function millerRabinTest(prime: bigint, iterations: number = 6): boolean{

	let s = n0, d = prime - n1
	let randsize = Math.min(16, bitLength(prime) - 1)

	while(!((d & n1) != n1)){

		d >>= n1
		s++

	}

	let a, x
	let cant1 = n1, cant2 = prime - n1

	iter: while(iterations--){

		a = randomBi(randsize) + Bi(5)
		x = modPow(a, d, prime)

		if(x == cant1 || x == cant2)
			continue iter

		for(let i = n0, l = s - n1; i < l; i++){

			x = modPow(x, Bi(2), prime)

			if(x == cant1)
				return false

			if(x == cant2)
				continue iter

		}

		return false

	}

	return true

}

export function isPrime(prime: bigint, iterations: number = 6): boolean{

	for(let i = 0, l = smallprimes.length; i < l; i++)
		if(prime % smallprimes[i] == n0)
			return prime == smallprimes[i]

	return millerRabinTest(prime, iterations) && fermatTest(prime, iterations)

}

export function getPrime(bitlength: number, iterations: number = 6, attempts: number = 100000): bigint{

	let candidate

	for(let i = 0; i < attempts; i++){

		candidate = randomBi(bitlength) | n1 | (n1 << Bi(bitlength - 1))

		if(isPrime(candidate, iterations))
			return candidate

	}

	throw `Couldn't find a prime in ${attempts} attempts`

}

//code design from: https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/#tablist3-tab7
export function modInv(int: bigint, modulus: bigint): bigint{ //int != 1

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

export function buffviewToBi(bufferview: ArrayBufferView): bigint{

	return Bi("0x" + new Hex().decode(
		new Uint8Array(bufferview.buffer, bufferview.byteOffset || 0, bufferview.byteLength || 0)
	))

}

export function biToBuffview(bigint: bigint): Uint8Array{

	let stred = bigint.toString(16)
	return new Hex().encode((stred.length % 2 == 1 ? "0" : "") + stred)

}