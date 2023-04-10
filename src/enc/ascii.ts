import encoding from "./encoding"

export default class Ascii implements encoding {

	encode(str: string): Uint8Array{

		let bytes = new Uint8Array(str.length)

		for(let i = 0, l = str.length; i < l; i++)
			bytes[i] = str.charCodeAt(i)

		return bytes

	}

	decode(bytes: ArrayBufferView): string{

		let bytearr = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)

		let str: string[] = Array(bytearr.length)

		for(let i = 0, l = bytearr.length; i < l; i++)
			str[i] = String.fromCharCode(bytearr[i])

		return str.join("")
		
	}

}