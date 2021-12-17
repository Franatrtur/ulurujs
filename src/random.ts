namespace Uluru {

	const CAPACITY = 16300 //max is 65536 bytes -> 16thousand 32bit words

	let Pool = new Uint32Array(CAPACITY)
	let Pointer = 0

	function reset(){

		Pointer = 0

		if(Random.secure)
			crypto.getRandomValues(Pool)

		else 
			for(let i = 0, l = CAPACITY; i < l; i++)
				Pool[i] = Math.floor(Math.random() * 0x100000000)

	}

	export class Random {

		static capacity = CAPACITY

		static get secure(){

			return typeof crypto == "object" && typeof crypto["getRandomValues"] == "function"

		}

		public word(){

			if(Pointer >= CAPACITY)
				reset()

			return Pool[Pointer++]

		}

		public fill(arr: Uint32Array | Uint8Array | Uint16Array){

			if(ArrayBuffer.isView(arr)){

				reset()

				let wrds = new Uint32Array(arr.buffer, arr.byteOffset, arr.byteLength >> 2)

				for(let i = 0, l = wrds.length; i < l; i += CAPACITY){

					wrds.set(new Uint32Array(Pool.buffer, 0, Math.min((l - i), CAPACITY)), i)

					reset()

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

	reset()

}