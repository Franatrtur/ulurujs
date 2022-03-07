namespace Uluru {
	
	const RHOoffsets = new Uint8Array([
		 0,  1, 30, 28, 27,
		 4, 12,  6, 23, 20,
		 3, 10, 11, 25,  7,
		 9, 13, 15, 21,  8,
		18,  2, 29, 24, 14
	])

	const RCs = new Uint32Array([
		0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009,
		0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
		0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008
	])

	//keccak coordinates precomputation

	//x mod plus 1
	const XMP1 = new Uint8Array(25)

	//x mod minus 1
	const XMM1 = new Uint8Array(25)

	//x y permutation - shuffling
	const XYP = new Uint8Array(25)

	//x plus 1 - next lane
	const XP1 = new Uint8Array(25)

	//x plus 2 - next lane
	const XP2 = new Uint8Array(25)

	let nx: number, ny: number

	//walk matrix 5x5
	for(let n = 0; n < 25; n++){

		nx = n % 5
		ny = Math.floor(n / 5)

		XMP1[n] = (nx + 1) % 5
		XMM1[n] = (nx + 4) % 5
		XYP[n] = ny * 5 + (2 * nx + 3 * ny) % 5
		XP1[n] = ((nx + 1) % 5) * 5 + ny
		XP2[n] = ((nx + 2) % 5) * 5 + ny

	}

	/*
	 * An implementation of the eccak800 algorithm as accurately as i could (idk about the uint32array endianness, padding etc)
	 * smaller sibling to the keccak1600 used as sha3 (but that requires 64bit words)
	 * built with capacity 64 bytes and 36 private state bytes
	 */
	export class Keccak800 implements algorithm {

		public static blockbytes = 64

		private state: Uint32Array = new Uint32Array(25)
		private temp: Uint32Array = new Uint32Array(25)
		private theta: Uint32Array = new Uint32Array(5)

		public data: Uint32Array | Uint8Array
		public pointer: number

		private padblock: Uint32Array = new Uint32Array(16)
		private padsigbytes: number

		public reset(){

			this.state.fill(0)

			this.temp.fill(0)
			this.theta.fill(0)

			this.data = new Uint32Array(0)
			this.pointer = 0

			this.padblock.fill(0)
			this.padsigbytes = 0

		}

		constructor(){

			this.reset()

		}

		private keccakF(state){

			let temp = this.temp,
				theta = this.theta
			let off, tmp

			for(let round = 0; round < 22; round++){

				theta[0] = state[ 0] ^ state[ 1] ^ state[ 2] ^ state[ 3] ^ state[ 4]
				theta[1] = state[ 5] ^ state[ 6] ^ state[ 7] ^ state[ 8] ^ state[ 9]
				theta[2] = state[10] ^ state[11] ^ state[12] ^ state[13] ^ state[14]
				theta[3] = state[15] ^ state[16] ^ state[17] ^ state[18] ^ state[19]
				theta[4] = state[20] ^ state[21] ^ state[22] ^ state[23] ^ state[24]

				for(let i = 0; i < 25; i++){

					tmp = theta[XMP1[i]]

					state[i] ^= theta[XMM1[i]] ^ (tmp << 1 | tmp >>> 31)

					off = RHOoffsets[i]
					tmp = state[i]
					temp[XYP[i]] = tmp << off | tmp >>> (32 - off)

				}

				for(let i = 0; i < 25; i++)
					state[i] = temp[i] ^ (~temp[XP1[i]] & temp[XP2[i]])

				state[0] ^= RCs[round]

			}

		}

		private process(flush = false){

			let blocks = (this.data.length - this.pointer) / 16

			for(let b = 0; b < blocks; b++){

				for(let w = 0; w < 16; w++)
					this.state[w] ^= this.data[this.pointer + w]

				this.keccakF(this.state)
				this.pointer += 16

			}

			if(flush){ //will run even if this.padsigbytes == 0, which is what we want

				for(let w = 0; w < 16; w++)
					this.state[w] ^= this.padblock[w]

				this.keccakF(this.state)

			}

		}

		private append(data: string | ArrayBufferView){

			data = typeof data == "string" ? new enc.Utf8().encode(data as string) : data

			//shortcuts for the minifier
			let padblock: any = this.padblock
			let padsigbytes = this.padsigbytes

			//incomplete block
			if(data.byteLength + padsigbytes < 64){

				padblock = new Uint8Array(padblock.buffer)
				padblock.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength), padsigbytes)

				padblock[padblock.length - 1] = 0x80
				padblock[data.byteLength + padsigbytes] ^= 0x06

				this.padblock = new Uint32Array(padblock.buffer)
				this.padsigbytes += data.byteLength

			}
			//new complete block
			else{

				let newlen = (padsigbytes + data.byteLength) >> 6 << 6 // floor(len / 64) * 64
				let overflow = (padsigbytes + data.byteLength) % 64

				//optimization, use existing data buffer we can, useful for repeptitive updating
				this.data = this.data.byteLength > newlen ? new Uint8Array(this.data.buffer, 0, newlen) : new Uint8Array(newlen)

				this.data.set(new Uint8Array(padblock.buffer, 0, padsigbytes))
				this.data.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength - overflow), padsigbytes)

				this.data = new Uint32Array(this.data.buffer, 0, newlen >> 2)

				//append the overflow as a new incomplete block

				padblock.fill(0)
				this.padsigbytes = 0

				this.append(new Uint8Array(data.buffer, data.byteOffset + data.byteLength - overflow, overflow))

			}

		}

		public update(data: string | ArrayBufferView){

			this.append(data)
			this.process(false)

			return this

		}

		public finalize(outputbytes = 32){

			this.process(true)

			let len = Math.ceil(outputbytes / 64) * 16
			let words = new Uint32Array(len)

			for(let i = 0; i < len; i += 16){

				words.set(new Uint32Array(this.state.buffer, 0, 16), i)
				this.keccakF(this.state)

			}

			this.data = new Uint32Array(0)
			this.pointer = 0

			this.padblock.fill(0)
			this.padsigbytes = 0

			let result = new Uint8Array(words.buffer, 0, outputbytes)

			result.toString = function(encoder: enc.encoding = new enc.Hex){

				return encoder.decode(this)

			}

			return result
			
		}

	}

}