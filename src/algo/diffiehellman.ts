import Base64 from "../enc/base64"
import KDF from "./kdf"
import { Bi, buffviewToBi, biToBuffview, modPow, randomBi } from "./utils/bigint"

/**
 * 4096bit diffie-hellman group constant from
 * @see https://www.rfc-editor.org/rfc/rfc3526
 */
const MODPgroup = buffviewToBi(new Base64().encode(
	"///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxObIlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjftawv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXTmmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhghfDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYMfbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshqZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEIARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBIHNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0BjGZ//////////8="
))

const GENERATOR = Bi(2)

/**
 * A basic diffie-hellman protocol.
 * An instance of the class acts as one party in the key exchange.  
 * 
 * Parties can be for example client(browser)-server(node).
 * Both parties exchange the send() parts and derive a shared secret, usually used as a key for symmetric encryption
 */
export default class DiffieHellman {

	static generator = GENERATOR
	static group = MODPgroup

	E: bigint
	secret: bigint

	constructor(ebits = 384){

		this.E = randomBi(ebits) | (Bi(1) << Bi(ebits - 1))
		
	}

	public send(): Uint8Array{

		return biToBuffview(modPow(GENERATOR, this.E, MODPgroup))

	}

	public receive(data: ArrayBufferView){

		this.secret = modPow(buffviewToBi(data), this.E, MODPgroup)

	}

	public finalize(length: number = 32): Uint8Array{

		if(typeof this.secret != "bigint")
			throw new Error("Key exchange cannot finalize without receiving")

		return new KDF(length, 1).compute(biToBuffview(this.secret))

	}

}