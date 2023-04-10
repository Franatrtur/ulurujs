import Keccak800 from "./keccak800"
import Random from "./random"
import { mergeBuffers } from "./utils/buffers"

const SEEDlen = 12
const HASHlen = 16
const HDRlen = SEEDlen + HASHlen + 4

/**
 * OAEP (optimal asymmetric encryption padding) for RSA.
 * Used internally by the `RSAKey` by default.
 */
export default class OAEP {

	public static seedLength = SEEDlen
	public static hashLength = HASHlen
	public static headerLength = HDRlen

	pad(data: ArrayBufferView, len: number = 128): Uint8Array{

		if(len <= HDRlen)
			throw new Error("OAEP message length too small")

		let padxdata = new Uint8Array(len - HDRlen)
		padxdata.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength))

		let datalen = new Uint32Array([data.byteLength])
		let seed = new Random().bytes(SEEDlen)
		let hash = new Keccak800().update(padxdata).update(datalen).update(seed).finalize(HASHlen)

		let header = mergeBuffers(datalen, seed, hash)

		let mask = new Keccak800().update(header).finalize(len - HDRlen)
		for(let m0 = 0; m0 < len - HDRlen; m0++)
			padxdata[m0] ^= mask[m0]

		mask = new Keccak800().update(padxdata).finalize(HDRlen)
		for(let m1 = 0; m1 < HDRlen; m1++)
			header[m1] ^= mask[m1]

		return mergeBuffers(header, padxdata)

	}

	unpad(data: ArrayBufferView): Uint8Array{

		let len = data.byteLength

		let header = new Uint8Array(data.buffer, 0, HDRlen).slice()
		let padxdata = new Uint8Array(data.buffer, HDRlen).slice()

		let mask = new Keccak800().update(padxdata).finalize(HDRlen)
		for(let m1 = 0; m1 < HDRlen; m1++)
			header[m1] ^= mask[m1]

		mask = new Keccak800().update(header).finalize(len - HDRlen)
		for(let m0 = 0; m0 < len - HDRlen; m0++)
			padxdata[m0] ^= mask[m0]

		let datalen = new Uint32Array(header.buffer, 0, 1)
		let seed = new Uint8Array(header.buffer, 4, SEEDlen)
		let hash = new Uint8Array(header.buffer, 4 + SEEDlen, HASHlen)

		let rehash = new Keccak800().update(padxdata).update(datalen).update(seed).finalize(HASHlen)
		if(rehash.join(",") != hash.join(","))
			throw new Error("OAEP invalid padding hash")

		return new Uint8Array(padxdata.buffer, 0, datalen[0])
		
	}

}