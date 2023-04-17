import algorithm from "./algorithm"
import Utf8 from "../enc/utf8"

/**nothing-up-my-sleeve constants "expand 32-byte k"*/
const CONSTS = new Uint32Array(
	[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
)

/**
 * A modified version of the chacha20 stream cipher
 * the cipher uses the original chacha function and rounds
 * except that we diffuse the entropy of the key with 20 column/row rounds
 * to create a mask that we add to the permuted state instead of the original
 * nonce is a 96bit (3-word) bufferview and counter is one 32bit word (number)
 * 
 * it uses my custom MACing system that is *symmetrical*
 * so the cipher can still be used in both ways, encrypting will produce the same mac as decrypting
 * this is done by computing two 4-word checksums, one for the plaintext, other one for the ciphertext
 * then we combine them and permute, resulting in a 128bit mac
 * It is important that the combination and permutation together form a compression function 256->128 bits
 */
export default class ChaCha20 implements algorithm {
	
	private state: Uint32Array = new Uint32Array(16)
	private xstate: Uint32Array = new Uint32Array(16)
	private mask: Uint32Array = new Uint32Array(16)
	
	public doMac: boolean
	private Cmac: Uint32Array
	private Pmac: Uint32Array
	
	private data: Uint32Array | Uint8Array
	public pointer: number
	public sigBytes: number

	public reset(){

		this.xstate.fill(0)

		this.Pmac = new Uint32Array(4)

		//add in the spreaded entropy to initialize the mac states
		if(this.doMac)
			for(let i = 0; i < 16; i++)
				this.Pmac[i & 3] ^= this.mask[i]

		this.Cmac = this.Pmac.slice()

		this.data = new Uint32Array(0)
		this.pointer = 0
		this.sigBytes = 0

	}

	constructor(key: ArrayBufferView, mac: boolean = true, nonce: ArrayBufferView = new Uint32Array(3), counter: number = 0){

		this.state.set(CONSTS)
		this.state.set(new Uint32Array(key.buffer, key.byteOffset, key.byteLength >> 2), 4)
		this.state.set(new Uint32Array(nonce.buffer, nonce.byteOffset, nonce.byteLength >> 2), 12)
		this.state[15] = counter

		this.mask.set(this.state)
		this.mask[15] = 0 //erase the counter

		//spread entropy
		for(let init = 0; init < 10; init++){

			for(let ev = 0; ev < 4; ev++) //cols
				this.QR(this.mask, ev, ev + 4, ev + 8, ev + 12)

			for(let od = 0; od < 16; od += 4) //rows
				this.QR(this.mask, od, od + 1, od + 2, od + 3)

		}

		this.doMac = !!mac

		this.reset()

	}

	public get counter(): number{

		return this.state[15]

	}

	public set counter(ctr){

		this.state[15] = ctr

	}

	//ChaCha mixing Quarter-round
	private QR(state: Uint32Array, A: number, B: number, C: number, D: number){

		state[A] += state[B]
		state[D] ^= state[A]
		state[D] = state[D] << 16 | state[D] >>> 16
		
		state[C] += state[D]
		state[B] ^= state[C]
		state[B] = state[B] << 12 | state[B] >>> 20

		state[A] += state[B]
		state[D] ^= state[A]
		state[D] = state[D] << 8 | state[D] >>> 24
		
		state[C] += state[D]
		state[B] ^= state[C]
		state[B] = state[B] << 7 | state[B] >>> 25

	}

	public getMac(){

		if(!this.doMac)
			return false

		let mac = new Uint32Array([
			this.Pmac[0] + this.Cmac[0],
			this.Pmac[1] + this.Cmac[1],
			this.Pmac[2] + this.Cmac[2],
			this.Pmac[3] + this.Cmac[3],
		])

		//20 quarter rounds
		for(let mr = 0; mr < 5; mr++){

			this.QR(mac, 0, 1, 2, 3)
			this.QR(mac, 3, 0, 1, 2)
			this.QR(mac, 2, 3, 0, 1)
			this.QR(mac, 1, 2, 3, 0)

		}

		for(let re = 0; re < 4; re++)
			mac[re] ^= this.Pmac[re] ^ this.Cmac[re]

		return new Uint8Array(mac.buffer)

	}

	private process(flush: boolean = false){

		let blocks = (flush ? Math.ceil : Math.floor)((this.sigBytes - this.pointer) / 16)

		let ptw: number, ctw: number

		let end = Math.ceil(this.sigBytes / 4) - 1
		let erase = 4 - this.sigBytes % 4

		let xState = this.xstate

		for(let b = 0; b < blocks; b++){

			xState.set(this.state)

			//permute
			for(let drnd = 0; drnd < 20; drnd += 2){

				//even round - columns
				this.QR(xState, 0, 4,  8, 12)
				this.QR(xState, 1, 5,  9, 13)
				this.QR(xState, 2, 6, 10, 14)
				this.QR(xState, 3, 7, 11, 15)

				//odd round - diagonals
				this.QR(xState, 0, 5, 10, 15)
				this.QR(xState, 1, 6, 11, 12)
				this.QR(xState, 2, 7,  8, 13)
				this.QR(xState, 3, 4,  9, 14)

			}

			//combine the keystream with the data
			for(let i = 0; i < 16 && this.pointer + i <= end; i++){

				ptw = this.data[this.pointer + i]
				ctw = ptw ^ (xState[i] + this.mask[i])

				if(this.pointer + i == end)
					ctw = ctw << erase * 8 >>> erase * 8 //erase the needless bytes (+uint32array is little-endian!)

				this.data[this.pointer + i] = ctw

				if(this.doMac){

					this.Pmac[i & 3] ^= ptw // i & 3 = i % 4
					this.Cmac[i & 3] ^= ctw

					this.QR(this.Pmac as Uint32Array, (i + 3) & 3, i & 3, (i + 1) & 3, (i + 2) & 3)
					this.QR(this.Cmac as Uint32Array, (i + 3) & 3, i & 3, (i + 1) & 3, (i + 2) & 3)
					
				}
				
			}

			this.pointer += 16

			this.state[15]++

		}

	}

	private append(data: string | ArrayBufferView){

		data = typeof data == "string" ? new Utf8().encode(data as string) : data

		let old = this.data

		this.data = new Uint8Array(
			Math.ceil((this.sigBytes + data.byteLength) / 64) * 64
		)

		this.data.set(new Uint8Array(old.buffer, 0, this.sigBytes))
		this.data.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength), this.sigBytes)

		this.data = new Uint32Array(this.data.buffer)
		this.sigBytes += data.byteLength

	}

	public verify(mac: ArrayBufferView): boolean{

		if(!this.doMac)
			return

		return (this.getMac() as Uint8Array).join(",") === new Uint8Array(mac.buffer, mac.byteOffset, mac.byteLength).join(",")

	}

	public update(data: string | ArrayBufferView): this{

		this.append(data)
		this.process(false)

		return this

	}

	public finalize(): Uint8Array{

		this.process(true)

		let result = new Uint8Array(this.data.buffer, 0, this.sigBytes)

		this.data = new Uint32Array(0)
		this.pointer = 0
		this.sigBytes = 0

		return result

	}

}