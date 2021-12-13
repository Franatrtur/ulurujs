namespace Uluru {

	export namespace enc {

		export class Utf8 implements encoding {

			encode(str){

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
	
			decode(bytes){

				if(typeof TextDecoder == "function")
					return new TextDecoder().decode(bytes)

				let str = []
				let ucpoint

				for(let i = 0, l = bytes.length; i < l;){

					//one UTF-8 byte (0xxxxxxx)
					if(bytes[i] < 0x80)
						str.push(String.fromCharCode(bytes[i++]))
						
					//two UTF-8 bytes (110xxxxx 10xxxxxx)
					else if(bytes[i] >= 0xc0 && bytes[i] < 0xe0)
						str.push(String.fromCharCode(((bytes[i++] & 0x1f) << 6) | (bytes[i++] & 0x3f)))

					//three UTF-8 bytes (1110xxxx 10xxxxxx 10xxxxxx)
					else if(bytes[i] >= 0xe0 && bytes[i] < 0xf0)
						str.push(String.fromCharCode(((bytes[i++] & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f)))

					//four UTF-8 bytes (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
					else if(bytes[i] >= 0xf0 && bytes[i] < 0xf7){

						ucpoint = ((bytes[i++] & 0x07) << 18) | ((bytes[i++] & 0x3f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f)
						
						str.push(String.fromCodePoint(ucpoint))
					
					}
						
					else
						i++

				}

				return str.join("")
				
			}

		}

	}
	
}