namespace Uluru {

	//functions for simplified user interaction
	//using pbkdf with 1000 iterations to slow down the key generation

	export function encrypt(plaintext, password){

		let salt = new Random().word()

		let key = new Pbkdf(32, 1000).compute(new enc.Utf8().encode(password), salt).result

		let encryptor = new ChaCha20(key, true, salt)

		encryptor.update(new enc.Utf8().encode(plaintext))

		let encrypted = encryptor.finalize()

		return  new enc.Hex().decode(new Uint8Array(new Uint32Array([salt]).buffer)) +
				new enc.Base64().decode(encrypted.data) +
				new enc.Hex().decode(encrypted.mac)
	}

	export function decrypt(ciphertext, password){

		let salt, cdata, macstr

		try{

			salt = new Uint32Array(new enc.Hex().encode(ciphertext.slice(0, 8)).buffer)[0]
			cdata = new enc.Base64().encode(ciphertext.slice(8, -32))
			macstr = ciphertext.slice(-32)
		}
		catch(e){
			throw "Incorrectly formated ciphertext"
		}

		let key = new Pbkdf(32, 1000).compute(new enc.Utf8().encode(password), salt).result

		let decryptor = new ChaCha20(key, true, salt)

		decryptor.update(cdata)

		let decrypted = decryptor.finalize()

		if(new enc.Hex().decode(decrypted.mac) != macstr)
			throw "Invalid authentication"

		return new enc.Utf8().decode(decrypted.data)
	}

	export function hash(text){

		return new Keccak800().update(new enc.Utf8().encode(text)).finalize().toString(new enc.Hex)

	}

	export function rsaGenerate(){

		return RSAKeyPair.generate(3072).toString()

	}

	export function rsaSign(message, privkeystr){

		return new enc.Base64().decode(
			RSAKey.fromString(privkeystr).sign(
				new enc.Utf8().encode(message)
			).signature
		)

	}

	export function rsaVerify(message, signature, pubkeystr){

		return RSAKey.fromString(pubkeystr).verify(
			new enc.Utf8().encode(message),
			new enc.Base64().encode(signature)
		)

	}

	export function rsaEncrypt(message, pubkeystr){

		let key = RSAKey.fromString(pubkeystr)

		let symkey = new Random().fill(new Uint32Array(8))

		let encsymkey = new enc.Base64().decode(
			key.encrypt(symkey).data
		)

		let encptx = new ChaCha20(symkey, true).update(
			new enc.Utf8().encode(message)
		).finalize()

		return encsymkey + "|" + new enc.Base64().decode(encptx.data) + new enc.Hex().decode(encptx.mac)

	}

	export function rsaDecrypt(message, privkeystr){

		let key, symkey, encptx, mac, splitted

		try{

			key = RSAKey.fromString(privkeystr)
			splitted = message.split("|")
			symkey = new enc.Base64().encode(splitted[0])
			encptx = new enc.Base64().encode(splitted[1].slice(0, -32))
			mac = new enc.Hex().encode(splitted[1].slice(32))
		}
		catch(e){
			throw "Incorrectly formatted RSA ciphertext"
		}

		symkey = key.decrypt(symkey).data
		encptx = new ChaCha20(symkey, true).update(
			encptx
		).finalize()

		if(encptx.mac.join(",") != mac.join(","))
			throw "Invalid RSA message authentication code"

		return new enc.Utf8().decode(encptx.data)

	}

}