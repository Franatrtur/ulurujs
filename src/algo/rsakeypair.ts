import RSAKey from "./rsakey"
import { Bi, modInv, getPrime } from "./utils/bigint"

//public exponent - fermat prime 257 (=2**8+1)
const PUBEXP = Bi(0x101)

const PUBLICprefix = ["\n==BEGIN ULURU PUBLIC KEY==\n", "\n==END ULURU PUBLIC KEY==\n"]
const PRIVATEprefix = ["\n==BEGIN ULURU PRIVATE KEY==\n", "\n==END ULURU PRIVATE KEY==\n"]

export default class RSAKeyPair {

	public static publicExponent = PUBEXP

	public static publicPrefix = PUBLICprefix
	public static privatePrefix = PRIVATEprefix

	static fromString(str: string): RSAKeyPair{

		return new this(
			RSAKey.fromString(str.split(PUBLICprefix[0])[1].split(PUBLICprefix[1])[0]),
			RSAKey.fromString(str.split(PRIVATEprefix[0])[1].split(PRIVATEprefix[1])[0])
		)

	}

	static generate(bitlength: number = 3072): RSAKeyPair{

		if(!bitlength)
			return

		bitlength >>= 1 //primes are two times shorter than the bitlength of n
		let closeShift = Bi(bitlength - 8) //for comparing first 8 bits of the primes

		let E = PUBEXP

		let prime1: bigint, prime2: bigint

		do
			prime1 = getPrime(bitlength)
		while(prime1 % E == Bi(1)) //assert modular invertibility under phi(n)

		do
			prime2 = getPrime(bitlength)
		while(prime2 % E == Bi(1) || (prime2 >> closeShift) == (prime1 >> closeShift)) //p and q must not be close

		let N = prime1 * prime2
		let phi = (prime1 - Bi(1)) * (prime2 - Bi(1))
		let D = modInv(E, phi)

		return new this(new RSAKey(E, N), new RSAKey(D, N))

	}

	public public: RSAKey
	public private: RSAKey

	constructor(publickey: RSAKey, privatekey: RSAKey){

		this.public = publickey
		this.private = privatekey

	}

	toString(){

		return PUBLICprefix[0] + this.public.toString() + PUBLICprefix[1] + "\n!\n" +
			PRIVATEprefix[0] + this.private.toString() + PRIVATEprefix[1]

	}

}

