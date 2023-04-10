import Keccak800 from "./keccak800"

/**
 * Custom key derivation function.
 * Design follows the PBKDF2 construction.  
 * Allows exctraction of a secret of any length from a key/soure of entropy/password, using an optional salt.
 * Can be used as PBKDF or KBKDF.
 */
export default class KDF {

	public outputBytes: number
	public iterations: number

	constructor(outputbytes: number = 32, iterations: number = 1000){

		this.outputBytes = outputbytes
		this.iterations = iterations
		
	}

	public compute(password: ArrayBufferView | string, salt: ArrayBufferView = new Uint32Array(0)): Uint8Array{

		let result = new Uint8Array(this.outputBytes)
		let block
		let hasher = new Keccak800()
		let counter = new Uint32Array(1)

		for(let t = 0, lent = result.length; t < lent; t += 64){

			hasher.reset()
			hasher.update(salt).update(counter).finalize()

			for(let r = 0; r < this.iterations; r++){

				block = hasher.update(password).finalize(64)

				for(let b = 0, l = result.length; (b < 64) && (t + b < l); b++)
					result[t + b] ^= block[b]
				
			}

			counter[0]++

		}

		return result

	}

}