import encoding from "./encoding"

//hex lookup tables
let hexcodes = Array(256)
let hexmap = {}

for(let h = 0; h < 256; h++){

	hexcodes[h] = ("00" + h.toString(16)).slice(-2)
	hexmap[hexcodes[h]] = h

}

export default class Hex implements encoding {

	encode(str: string): Uint8Array{

		str = str.replace(/[^A-Fa-f0-9\+\/]/g, "").toLowerCase()

		let bytes = new Uint8Array(str.length >> 1)

		for(let hxcode = 0; hxcode < str.length; hxcode += 2)
			bytes[hxcode >> 1] = hexmap[str.slice(hxcode, hxcode + 2)]

		return bytes

	}

	decode(bytes: ArrayBufferView): string{

		let byteArr = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)

		let str = Array(byteArr.length)

		for(let byte = 0; byte < byteArr.length; byte++)
			str[byte] = hexcodes[byteArr[byte]]

		return str.join("")

	}

}