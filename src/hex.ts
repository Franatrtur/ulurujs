namespace Uluru {

	export namespace enc {
		
		//hex lookup tables

		let hexcodes = Array(256)
		let hexmap = {}

		for(let h = 0; h < 256; h++){

			hexcodes[h] = ("00" + h.toString(16)).slice(-2)
			hexmap[hexcodes[h]] = h
		
		}

		export class Hex implements encoding {

			encode(str){

				let bytes = new Uint8Array(str.length >> 1)
		
				for(let hxcode = 0; hxcode < str.length; hxcode += 2)
					bytes[hxcode >> 1] = hexmap[str.slice(hxcode, hxcode + 2)]

				return bytes

			}
	
			decode(bytes){

				bytes = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)

				let str = Array(bytes.length)

				for(let byte = 0; byte < bytes.length; byte++)
					str[byte] = hexcodes[bytes[byte]]

				return str.join("")

			}

		}

	}
	
}