import Keccak800 from "./keccak800"
import Random from "./random"

const SEEDlen = 12
const HASHlen = 16
const HDRlen = SEEDlen + HASHlen + 4

function merge(...bufferviews: ArrayBufferView[]){

	let len = 0
	for(let i = 0; i < bufferviews.length; i++)
		len += bufferviews[i].byteLength

	let result = new Uint8Array(len)
	let pointer = 0
	for(let i = 0; i < bufferviews.length; i++){

		result.set(new Uint8Array(bufferviews[i].buffer, bufferviews[i].byteOffset, bufferviews[i].byteLength), pointer)
		pointer += bufferviews[i].byteLength
	}

	return result
}

export default class OAEP {

	static seedlen = SEEDlen
	static hashlen = HASHlen
	static hdrlen = HDRlen

	pad(data: ArrayBufferView, len: number = 128){

		if(len <= HDRlen)
			throw "OAEP message length too small"

		let padxdata = new Uint8Array(len - HDRlen)
		padxdata.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength))

		let datalen = new Uint32Array([data.byteLength])
		let seed = new Random().fill(new Uint8Array(SEEDlen))
		let hash = new Keccak800().update(padxdata).update(datalen).update(seed).finalize(HASHlen)

		let header = merge(datalen, seed, hash)

		let mask = new Keccak800().update(header).finalize(len - HDRlen)
		for(let m0 = 0; m0 < len - HDRlen; m0++)
			padxdata[m0] ^= mask[m0]

		mask = new Keccak800().update(padxdata).finalize(HDRlen)
		for(let m1 = 0; m1 < HDRlen; m1++)
			header[m1] ^= mask[m1]

		return merge(header, padxdata)

	}

	unpad(data: ArrayBufferView){

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
			throw "OAEP invalid padding hash"

		return new Uint8Array(padxdata.buffer, 0, datalen[0])
		
	}

}