namespace Uluru {

	export class Random {

		static capacity = 16300 //max is 65536 bytes -> 16thousand 32bit words

		private pool: Uint32Array = new Uint32Array(Random.capacity)
		private pointer: number = 0

		constructor(){

			this.reset()
		
		}

		static get secure(){

			return typeof crypto == "object"

		}
	
		reset(){

			this.pointer = 0

			if(Random.secure)
				crypto.getRandomValues(this.pool)

			else 
				for(let i = 0, l = this.pool.length; i < l; i++)
					this.pool[i] = Math.floor(Math.random() * 0x100000000)

		}

		word(){

			if(this.pointer >= this.pool.length)
				this.reset()

			return this.pool[this.pointer++]

		}

		fill(arr: Uint32Array | Uint8Array | Uint16Array){

			if(ArrayBuffer.isView(arr)){

				this.reset()

				let wrds = new Uint32Array(arr.buffer, arr.byteOffset, arr.byteLength >> 2)

				for(let i = 0, l = wrds.length; i < l; i += this.pool.length){

					wrds.set(new Uint32Array(this.pool.buffer, 0, Math.min((l - i), this.pool.length)), i)

					this.reset()

				}

				let bytes = new Uint8Array(arr.buffer, arr.byteLength >> 2 << 2, arr.byteLength - (arr.byteLength >> 2 << 2))

				for(let i = 0, l = bytes.length; i < l; i++)
				//@ts-ignore
					bytes[i] = this.word()

			}
			else
			//@ts-ignore
				for(let i = 0, l = arr.length; i < l; i++)
				//@ts-ignore
					arr[i] = this.word()

			return arr

		}

	}

}