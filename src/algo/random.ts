import { fillRandom } from "./utils/securerandom"

const CAPACITY = 16300 //max is 65536 bytes -> 16thousand 32bit words
const SECURE = typeof fillRandom == "function" //prefer safe randomness from crypto/webcrypto

/**
 * Private buffer filled with random 32bit words.  
 * Remains hidden in the module scope.
 */
const Pool = new Uint32Array(CAPACITY)
let Pointer: number = 0

/**
 * Once all the words in `Pool` (the random buffer) are used,
 * they are discarded and rewritten with new random data.
 */
function RESET(){

	Pointer = 0

	if(SECURE)
		fillRandom(Pool)

	else
		for(let i = 0, l = CAPACITY; i < l; i++)
			Pool[i] = Math.floor(Math.random() * 0x100000000)

}

/**
 * An exposed class for extracting randomness from a private random buffer.  
 * Allows to fill/create typed arrays with random data or generate random 32bit integer words.
 */
export default class Random {

	public static capacity = CAPACITY
	public static secure = SECURE

	public word(): number{

		if(Pointer >= CAPACITY)
			RESET()

		return Pool[Pointer++]

	}

	public fill(data: ArrayBufferView): ArrayBufferView{

		if(SECURE && data.byteLength <= CAPACITY)
			return fillRandom(data)

		if(Pointer > 0)
			RESET()

		//copy over whole 32bit random words

		let dataWords = new Uint32Array(data.buffer, data.byteOffset, data.byteLength >> 2)

		for(let i = 0, l = dataWords.length; i < l; i += CAPACITY){

			dataWords.set(new Uint32Array(Pool.buffer, 0, Math.min((l - i), CAPACITY)), i)

			RESET()

		}

		let bytesDone = data.byteLength >> 2 << 2

		let overflowBytes = new Uint8Array(data.buffer, bytesDone, data.byteLength - bytesDone)
		let randomWord = this.word()

		for(let i = 0, l = overflowBytes.length; i < l; i++)
			overflowBytes[i] = randomWord >>> (i * 8) & 0xff //extract the next byte from the word

		return data

	}

	public bytes(byteAmount: number){

		return this.fill(new Uint8Array(byteAmount))

	}

}

RESET()

//warn if we have to use math.random
if(!SECURE)
	console.warn("Couldn't find a secure source of randomness. Make sure you are using a modern browser or node v6+")