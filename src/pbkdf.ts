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

			hasher.update(salt)
			hasher.finalize(0)
			
			for(let i = 0; i < this.iterations; i++){

				hasher.update(password)
				block = hasher.finalize(this.outputbytes).hash

				for(let b = 0; b < result.length; b++)
					result[b] ^= block[b]

			}

			return { result }

		}

	}

}