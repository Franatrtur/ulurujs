import RSAKey from "./rsakey.js"
import { Bi, modInv, getPrime } from "./utils/bigint.js"

//public exponent - fermat prime 257 (=2**8+1)
const PUBEXP = Bi(0x101)

const PUBLICprefix = ["\n==BEGIN ULURU PUBLIC KEY==\n", "\n==END ULURU PUBLIC KEY==\n"]
const PRIVATEprefix = ["\n==BEGIN ULURU PRIVATE KEY==\n", "\n==END ULURU PRIVATE KEY==\n"]

export default class RSAKeyPair {

	public static publicExponent = PUBEXP

	public static publicPrefix = PUBLICprefix
	public static privatePrefix = PRIVATEprefix

	static fromString(str: string){

		return new this(
			RSAKey.fromString(str.split(PUBLICprefix[0])[1].split(PUBLICprefix[1])[0]),
			RSAKey.fromString(str.split(PRIVATEprefix[0])[1].split(PRIVATEprefix[1])[0])
		)

	}

	static generate(bitlength: number = 3072){

		if(!bitlength)
			return

		bitlength >>= 1

		let E = PUBEXP

		let prime1 = getPrime(bitlength), prime2 = getPrime(bitlength)

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

