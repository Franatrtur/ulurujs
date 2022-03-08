import encoding from "./encoding"

export default class Ascii implements encoding {

	encode(str: string){

		let u8array = new Uint8Array(str.length)

		for(let i = 0, l = str.length; i < l; i++)
			u8array[i] = str.charCodeAt(i)

		return u8array

	}

	decode(bytes: ArrayBufferView){

		let bytearr = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)

		let str: string[] = Array(bytearr.length)

		for(let i = 0, l = bytearr.length; i < l; i++)
			str[i] = String.fromCharCode(bytearr[i])

		return str.join("")
		
	}

}