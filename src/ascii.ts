namespace Uluru {

	export namespace enc {

		export class Ascii implements encoding {

			encode(str){
	
				let u8array = new Uint8Array(str.length)
	
				for(let i = 0, l = str.length; i < l; i++)
					u8array[i] = str.charCodeAt(i)
	
				return u8array

			}
	
			decode(bytes){

				bytes = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
	
				let str: string[] = Array(bytes.length)

				for(let i = 0, l = bytes.length; i < l; i++)
					str[i] = String.fromCharCode(bytes[i])

				return str.join("")
				
			}

		}

	}
	
}