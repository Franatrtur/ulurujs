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
	
				return String.fromCharCode(...bytes)
				
			}

		}

	}
	
}