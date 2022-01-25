namespace Uluru {

	/*
	 * Custom password-based key derivation function
	 * uses reseeding of a finalized hasher
	 * simplified because we can have any output length
	 */
	export class Pbkdf {

		public outputbytes: number
		public iterations: number

		constructor(outputbytes = 32, iterations = 1000){

			this.outputbytes = outputbytes
			this.iterations = iterations
			
		}

		public compute(password: ArrayBufferView | string, salt: ArrayBufferView = new Uint32Array()){

			let result = new Uint8Array(this.outputbytes)
			let block
			let hasher = new Keccak800()

			for(let t = 0, lent = result.length; t < lent; t += 64){

				hasher.reset()
				hasher.update(salt).update(new Uint32Array([t >>> 6]))

				for(let r = 0; r < this.iterations; r++){

					block = hasher.update(password).finalize(64).hash

					for(let b = 0, l = result.length; (b < 64) && (t + b < l); b++)
						result[t + b] ^= block[b]
					
				}

			}

			return { result }

		}

	}

}