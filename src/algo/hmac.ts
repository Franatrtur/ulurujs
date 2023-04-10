import algorithm from "./algorithm"
import Keccak800 from "./keccak800"

const OKpad = 0x5c
const IKpad = 0x36

/**
 * Hash message authentication code.  
 * Follows the traditional HMAC construction with forced key hash.
 * Optionally, salt can added to the key.
 * Hashing function used is keccak800.
 */
export default class HMAC implements algorithm {

	private hasher: Keccak800
	private outerKey: ArrayBufferView

	constructor(key: ArrayBufferView, salt: ArrayBufferView = new Uint8Array(0)){

		let innerKey = new Keccak800().update(key).update(salt).finalize(64)
		this.outerKey = innerKey.slice()

		for(let i = 0, l = innerKey.length; i < l; i++){

			innerKey[i] ^= IKpad
			this.outerKey[i] ^= OKpad

		}

		this.hasher = new Keccak800().update(innerKey)

	}

	public update(data: string | ArrayBufferView): this{

		this.hasher.update(data)

		return this

	}

	public finalize(outputbytes?: number): Uint8Array{

		return new Keccak800().update(this.outerKey).update(
			this.hasher.finalize(64)
		).finalize(outputbytes)

	}

}