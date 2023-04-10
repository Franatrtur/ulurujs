import encoding from "./encoding"
import Ascii from "./ascii"

//base 64 lookup tables

let b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
let b64paddings = ["", "=", "=="]
let b64codes = new Uint8Array(256)

for(let c = 0; c < 64; c++)
	b64codes[b64chars.charCodeAt(c)] = c

export default class Base64 implements encoding {

	encode(str: string): Uint8Array{

		if(typeof atob == "function")
			return new Ascii().encode(atob(str))
			
		//remove padding
		str = str.replace(/[^A-Za-z0-9\+\/]/g, "")

		//design based on the example at
		//https://developer.mozilla.org/en-US/docs/Glossary/Base64#appendix_decode_a_base64_string_to_uint8array_or_arraybuffer
		
		let outlen = str.length * 3 + 1 >>> 2
		let bytes = new Uint8Array(outlen)

		let mod3, mod4, out24 = 0, outidx = 0

		for(let i = 0, l = str.length; i < l; i++){

			mod4 = i & 3
			out24 |= b64codes[str.charCodeAt(i)] << 6 * (3 - mod4)

			if(mod4 == 3 || str.length - i == 1){

				for(mod3 = 0; mod3 < 3 && outidx < outlen; mod3++, outidx++)
					bytes[outidx] = out24 >>> (16 >>> mod3 & 24) & 0xff

				out24 = 0

			}

		}

		return bytes
		
	}

	decode(bytes: ArrayBufferView): string{

		let byteArr = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)

		if(typeof btoa == "function")
			return btoa(new Ascii().decode(byteArr))

		let str: string[] | string = []
		let mod3 = 2, u24 = 0

		for(let i = 0, l = byteArr.length; i < l; i++){

			/* not support ancient line wrapping

			if(i > 0 && (i * 4 / 3) % 76 === 0)
				str.push("\r\n")
			amogus*/

			mod3 = i % 3
			u24 |= byteArr[i] << (16 >>> mod3 & 24)

			if(mod3 == 2 || byteArr.length - i == 1){

				str.push(
					b64chars.charAt(u24 >>> 18 & 0x3f) +
					b64chars.charAt(u24 >>> 12 & 0x3f) +
					b64chars.charAt(u24 >>> 6 & 0x3f) +
					b64chars.charAt(u24 & 0x3f)
				)

				u24 = 0

			}

		}

		str = str.join("")

		return str.slice(0, str.length - 2 + mod3) + b64paddings[2 - mod3]

	}

}