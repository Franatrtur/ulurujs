import Base64 from "../enc/base64"
import Utf8 from "../enc/utf8"
import Keccak800 from "./keccak800"
import OAEP from "./oaep"
import { Bi, buffviewToBi, biToBuffview, bitLength, modPow } from "./utils/bigint"

export default class RSAKey {

	static fromBufferViews(bufferview1: ArrayBufferView, bufferview2: ArrayBufferView): RSAKey{

		return new this(buffviewToBi(bufferview1), buffviewToBi(bufferview2))

	}

	static fromString(str: string): RSAKey{

		let splitted = str.split("<")[1].split(">")[0].split("|")

		return this.fromBufferViews(new Base64().encode(splitted[0]), new Base64().encode(splitted[1]))

	}

	private E: bigint
	public M: bigint

	constructor(exponent: bigint | number, mod: bigint | number){

		this.E = Bi(exponent) //private/public exponent
		this.M = Bi(mod) //public component

	}

	toString(){

		return "<" + 
			new Base64().decode(biToBuffview(this.E)) + 
			"|" + 
			new Base64().decode(biToBuffview(this.M)) + 
			">"

	}

	private process(data: ArrayBufferView): Uint8Array{

		let dataBi = buffviewToBi(data)

		if(dataBi >= this.M)
			throw new Error("Data integer too large")

		return biToBuffview(modPow(dataBi, this.E, this.M))

	}

	public encrypt(data: ArrayBufferView | string): Uint8Array{

		data = typeof data == "string" ? new Utf8().encode(data as string) : data

		let msglen = (bitLength(this.M) >> 3) - 2 - OAEP.headerLength

		if(data.byteLength > msglen)
			throw new Error("Message too long")

		return this.process(new OAEP().pad(data, msglen))

	}

	public decrypt(data: ArrayBufferView): Uint8Array{

		return new OAEP().unpad(this.process(data))

	}

	public sign(data: ArrayBufferView | string): Uint8Array{

		let hash = new Keccak800().update(data).finalize(64)

		return this.encrypt(hash)

	}

	public verify(data: ArrayBufferView | string, signature: ArrayBufferView): boolean{

		try{

			data = typeof data == "string" ? new Utf8().encode(data as string) : data

			let hash = new Keccak800().update(data).finalize(64)
			let authCode = this.decrypt(signature)

			return hash.join(",") == authCode.join(",")

		}
		catch(e){
			return false
		}

	}

}