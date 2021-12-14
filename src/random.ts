namespace Uluru {

	export class Random {

		static capacity = 16300 //max is 65536 bytes -> 16thousand 32bit words

		private static pool: Uint32Array = new Uint32Array(this.capacity)
		private static pointer: number = 0

		static get secure(){

			return typeof crypto == "object"

		}
	
		static reset(){

			this.pointer = 0

			if(Random.secure)
				crypto.getRandomValues(this.pool)

			else 
				for(let i = 0, l = this.pool.length; i < l; i++)
					this.pool[i] = Math.floor(Math.random() * 0x100000000)

		}

		word(){

			if(Random.pointer >= Random.pool.length)
				Random.reset()

			return Random.pool[Random.pointer++]

		}

		fill(arr: Uint32Array | Uint8Array | Uint16Array){

			let rand = Random

			if(ArrayBuffer.isView(arr)){

				rand.reset()

				let wrds = new Uint32Array(arr.buffer, arr.byteOffset, arr.byteLength >> 2)

				for(let i = 0, l = wrds.length; i < l; i += rand.pool.length){

					wrds.set(new Uint32Array(rand.pool.buffer, 0, Math.min((l - i), rand.pool.length)), i)

					rand.reset()

				}

				let bytes = new Uint8Array(arr.buffer, arr.byteLength >> 2 << 2, arr.byteLength - (arr.byteLength >> 2 << 2))

				for(let i = 0, l = bytes.length; i < l; i++)
				//@ts-ignore
					bytes[i] = this.word()

			}
			else{
			//@ts-ignore
				for(let i = 0, l = arr.length; i < l; i++)
				//@ts-ignore
					arr[i] = this.word()
			}

			return arr

		}

	}

}