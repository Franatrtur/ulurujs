namespace Uluru {

	//functions for simplified user interaction
	//using pbkdf with 1000 iterations to slow down the key generation

	const SALTsize = 8

	export function encrypt(plaintext: any, password: string){

		let salt = new Random().fill(new Uint8Array(SALTsize))

		let key = new PBKDF(32, 1000).compute(new enc.Utf8().encode(password), salt)

		let encryptor = new ChaCha20(key, true, salt)

		encryptor.update(new enc.Utf8().encode(plaintext))

		let encrypted = encryptor.finalize()

		return  new enc.Hex().decode(salt) +
				new enc.Base64().decode(encrypted.data) +
				new enc.Hex().decode(encrypted.mac as Uint8Array)
	}

	export function decrypt(ciphertext: string, password: string): any{

		let salt, cdata, mac

		try{

			salt = new enc.Hex().encode(ciphertext.slice(0, SALTsize * 2))
			cdata = new enc.Base64().encode(ciphertext.slice(SALTsize * 2, -32))
			mac = new enc.Hex().encode(ciphertext.slice(-32))
			
		}
		catch(e){
			throw "Incorrectly formated ciphertext"
		}

		let key = new PBKDF(32, 1000).compute(new enc.Utf8().encode(password), salt)

		let decryptor = new ChaCha20(key, true, salt)

		decryptor.update(cdata)

		let decrypted = decryptor.finalize()

		if(!decryptor.verify(mac))
			throw "Invalid authentication"

		return new enc.Utf8().decode(decrypted.data)

	}

	export function hash(text){

		return new enc.Hex().decode(new Keccak800().update(new enc.Utf8().encode(text)).finalize())

	}

	export function rsaGenerate(){

		return RSAKeyPair.generate(3072).toString()

	}

	export function rsaSign(message, privkeystr){

		return new enc.Base64().decode(
			RSAKey.fromString(privkeystr).sign(
				new enc.Utf8().encode(message)
			)
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

		let symkey = new Random().fill(new Uint8Array(32))

		let encsymkey = new enc.Base64().decode(
			key.encrypt(symkey)
		)

		let encryptor = new ChaCha20(symkey, true)

		encryptor.update(new enc.Utf8().encode(message))

		let encptx = encryptor.finalize()

		return encsymkey + "|" + new enc.Base64().decode(encptx.data) + new enc.Hex().decode(encptx.mac as Uint8Array)

	}

	export function rsaDecrypt(message, privkeystr){

		let key: RSAKey, symkey, encptx, mac, splitted

		try{

			key = RSAKey.fromString(privkeystr)

			splitted = message.split("|")
			symkey = new enc.Base64().encode(splitted[0])

			encptx = new enc.Base64().encode(splitted[1].slice(0, -32))
			mac = new enc.Hex().encode(splitted[1].slice(-32))

		}
		catch(e){
			throw "Incorrectly formatted RSA ciphertext"
		}

		symkey = key.decrypt(symkey)
		let decryptor = new ChaCha20(symkey, true)
		
		encptx = decryptor.update(encptx).finalize()

		if(!decryptor.verify(mac))
			throw "Invalid RSA message authentication code"

		return new enc.Utf8().decode(encptx.data)

	}

	export function hmac(message, password){

		return new Uluru.enc.Hex().decode(
			new Uluru.HMAC(
				new PBKDF().compute(password)
			).update(message).finalize(32)
		)

	}

}