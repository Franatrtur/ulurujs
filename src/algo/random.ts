import { fillRandom } from "./utils/securerandom"

const CAPACITY = 16300 //max is 65536 bytes -> 16thousand 32bit words
const SECURE = typeof fillRandom == "function"

const Pool = new Uint32Array(CAPACITY)
let Pointer = 0


function RESET(){

	Pointer = 0

	if(SECURE)
		fillRandom(Pool)

	else
		for(let i = 0, l = CAPACITY; i < l; i++)
			Pool[i] = Math.floor(Math.random() * 0x100000000)

}

export default class Random {

	static capacity = CAPACITY
	static secure = SECURE

	public word(){

		if(Pointer >= CAPACITY)
			RESET()

		return Pool[Pointer++]

	}

	public fill(data: ArrayBufferView): ArrayBufferView{

		if(SECURE && data.byteLength <= CAPACITY)
			return fillRandom(data)

		RESET()

		let wrds = new Uint32Array(data.buffer, data.byteOffset, data.byteLength >> 2)

		for(let i = 0, l = wrds.length; i < l; i += CAPACITY){

			wrds.set(new Uint32Array(Pool.buffer, 0, Math.min((l - i), CAPACITY)), i)

			RESET()

		}

		let roundedbytes = data.byteLength >> 2 << 2

		let bytes = new Uint8Array(data.buffer, roundedbytes, data.byteLength - roundedbytes)

		for(let i = 0, l = bytes.length; i < l; i++)
			bytes[i] = this.word()

		return data

	}

	public bytes(byteAmount: number){

		return this.fill(new Uint8Array(byteAmount))

	}

}

RESET()

if(!SECURE)
	console.warn("Couldn't find a secure source of randomness. Make sure you are using a modern browser or node v6+")