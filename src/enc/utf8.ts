import encoding from "./encoding"

export default class Utf8 implements encoding {

	encode(str: string): Uint8Array{

		if(typeof TextEncoder == "function")
			return new TextEncoder().encode(str)
		
		let bytes = new Uint8Array(str.length * 4)
		let pos = 0

		//utf16 surrogate pairs
		let code

		for(let i = 0, l = str.length; i < l; i++){

			code = str.codePointAt(i)

			if(code > 0x1000)
				i++

			//one UTF-8 byte (0xxxxxxx)
			if(code <= 0x7f)
				bytes[pos++] = code

			//two UTF-8 bytes (110xxxxx 10xxxxxx)
			else if(code <= 0x7ff){
				bytes[pos++] = 0xc0 | ((code >>> 6) & 0x1f)
				bytes[pos++] = 0x80 | (code & 0x3f)
			}

			//three UTF-8 bytes (1110xxxx 10xxxxxx 10xxxxxx)
			else if(code <= 0xffff){
				bytes[pos++] = 0xe0 | ((code >>> 12) & 0x0f)
				bytes[pos++] = 0x80 | ((code >>> 6) & 0x3f)
				bytes[pos++] = 0x80 | (code & 0x3f)
			}

			//four UTF-8 bytes (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
			else{
				bytes[pos++] = 0xf0 | ((code >>> 18) & 0x07)
				bytes[pos++] = 0x80 | ((code >>> 12) & 0x3f)
				bytes[pos++] = 0x80 | ((code >>> 6) & 0x3f)
				bytes[pos++] = 0x80 | (code & 0x3f)
			}

		}

	}

	decode(bytes: ArrayBufferView): string{

		let byteArr = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)

		if(typeof TextDecoder == "function")
			return new TextDecoder().decode(byteArr)

		let str: string[] = []
		let unicodePoint: number

		for(let i = 0, l = byteArr.length; i < l;){

			//one UTF-8 byte (0xxxxxxx)
			if(byteArr[i] < 0x80)
				str.push(String.fromCharCode(byteArr[i++]))
				
			//two UTF-8 bytes (110xxxxx 10xxxxxx)
			else if(byteArr[i] >= 0xc0 && byteArr[i] < 0xe0)
				str.push(String.fromCharCode(((byteArr[i++] & 0x1f) << 6) | (byteArr[i++] & 0x3f)))

			//three UTF-8 bytes (1110xxxx 10xxxxxx 10xxxxxx)
			else if(byteArr[i] >= 0xe0 && byteArr[i] < 0xf0)
				str.push(String.fromCharCode(((byteArr[i++] & 0x0f) << 12) | ((byteArr[i++] & 0x3f) << 6) | (byteArr[i++] & 0x3f)))

			//four UTF-8 bytes (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
			else if(byteArr[i] >= 0xf0 && byteArr[i] < 0xf7){

				unicodePoint = ((byteArr[i++] & 0x07) << 18) | ((byteArr[i++] & 0x3f) << 12) | ((byteArr[i++] & 0x3f) << 6) | (byteArr[i++] & 0x3f)
				
				str.push(String.fromCodePoint(unicodePoint))
			
			}
				
			else
				i++

		}

		return str.join("")
		
	}

}