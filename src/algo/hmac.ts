import algorithm from "./algorithm"
import Keccak800 from "./keccak800"

const OKpad = 0x5c
const IKpad = 0x36

/*
 * Hash message authentication code
 * Follows the traditional HMAC construction with forced key hash
 * Optionally, salt can added to the key
 * Hashing function used is keccak800
 */
export default class HMAC implements algorithm {

	private hasher: Keccak800
	private outerkey: ArrayBufferView

	constructor(key: ArrayBufferView, salt: ArrayBufferView = new Uint8Array(0)){

		let innerkey = new Keccak800().update(key).update(salt).finalize(Keccak800.blockbytes)
		this.outerkey = innerkey.slice()

		for(let i = 0, l = innerkey.length; i < l; i++){

			innerkey[i] ^= IKpad
			this.outerkey[i] ^= OKpad

		}

		this.hasher = new Keccak800().update(innerkey)

	}

	public update(data: string | ArrayBufferView){

		this.hasher.update(data)

		return this

	}

	public finalize(outputbytes?: number){

		return new Keccak800().update(this.outerkey).update(
			this.hasher.finalize(Keccak800.blockbytes)
		).finalize(outputbytes)

	}

}