import { ChaCha20, Keccak800, KDF, HMAC, Random, RSAKey, RSAKeyPair } from "./algo/algo"
import { Hex, Utf8, Base64 } from "./enc/enc"

//functions for simplified user interface

const SALTsize = 8

export function encrypt(plaintext: string, password: string): string{

	let salt = new Random().bytes(SALTsize)

	let key = new KDF(32, 1000).compute(new Utf8().encode(password), salt)

	let encryptor = new ChaCha20(key, true, salt)

	encryptor.update(new Utf8().encode(plaintext))

	let encrypted = encryptor.finalize(),
		mac = encryptor.getMac()

	return  new Hex().decode(salt) +
			new Base64().decode(encrypted) +
			new Hex().decode(mac as Uint8Array)
			
}

export function decrypt(ciphertext: string, password: string): string{

	let salt, cdata, mac

	try{

		salt = new Hex().encode(ciphertext.slice(0, SALTsize * 2))
		cdata = new Base64().encode(ciphertext.slice(SALTsize * 2, -32))
		mac = new Hex().encode(ciphertext.slice(-32))
		
	}
	catch(e){
		throw "Incorrectly formated ciphertext"
	}

	let key = new KDF(32, 1000).compute(new Utf8().encode(password), salt)

	let decryptor = new ChaCha20(key, true, salt)

	decryptor.update(cdata)

	let decrypted = decryptor.finalize()

	if(!decryptor.verify(mac))
		throw "Invalid authentication"

	return new Utf8().decode(decrypted)

}

export function hash(text: string): string{

	return new Hex().decode(
		new Keccak800().update(
			new Utf8().encode(text)
		).finalize()
	)

}

export function rsaGenerate(): string{

	return RSAKeyPair.generate(3072).toString()

}

export function rsaSign(message: string, privkeystr: string): string{

	return new Base64().decode(
		RSAKey.fromString(privkeystr).sign(
			new Utf8().encode(message)
		)
	)

}

export function rsaVerify(message: string, signature: string, pubkeystr: string): boolean{

	return RSAKey.fromString(pubkeystr).verify(
		new Utf8().encode(message),
		new Base64().encode(signature)
	)

}

export function rsaEncrypt(message: string, pubkeystr: string): string{

	let key = RSAKey.fromString(pubkeystr)

	let symkey = new Random().bytes(32)

	let encsymkey = new Base64().decode(
		key.encrypt(symkey)
	)

	let encryptor = new ChaCha20(symkey, true)

	encryptor.update(new Utf8().encode(message))

	let encptx = encryptor.finalize(),
		encmac = encryptor.getMac()

	return encsymkey + "|" + new Base64().decode(encptx) + new Hex().decode(encmac as Uint8Array)

}

export function rsaDecrypt(message: string, privkeystr: string): string{

	let key: RSAKey, symkey, encptx, mac, splitted

	try{

		key = RSAKey.fromString(privkeystr)

		splitted = message.split("|")
		symkey = new Base64().encode(splitted[0])

		encptx = new Base64().encode(splitted[1].slice(0, -32))
		mac = new Hex().encode(splitted[1].slice(-32))

	}
	catch(e){
		throw "Incorrectly formatted RSA ciphertext"
	}

	symkey = key.decrypt(symkey)
	let decryptor = new ChaCha20(symkey, true)
	
	let decptx = decryptor.update(encptx).finalize()

	if(!decryptor.verify(mac))
		throw "Invalid RSA message authentication code"

	return new Utf8().decode(decptx)

}

export function hmac(message: string, password: string): string{

	return new Hex().decode(
		new HMAC(
			new KDF().compute(password)
		).update(message).finalize(16)
	)

}