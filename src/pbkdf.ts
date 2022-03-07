namespace Uluru {

	/*
	 * Custom password-based key derivation function
	 * design follows the PBKDF2 construction
	 * allows exctraction of a secret of any length from a source/password, using an optional salt
	 */
	export class PBKDF {

		public outputbytes: number
		public iterations: number

		constructor(outputbytes = 32, iterations = 1000){

			this.outputbytes = outputbytes
			this.iterations = iterations
			
		}

		public compute(password: ArrayBufferView | string, salt: ArrayBufferView = new Uint32Array(0)){

			let result = new Uint8Array(this.outputbytes)
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

}