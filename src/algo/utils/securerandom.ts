
declare const crypto

export let fillRandom: (data: ArrayBufferView) => ArrayBufferView

if(typeof crypto == "object")
	fillRandom = data => crypto.getRandomValues(data)

else if(typeof global != "object" && typeof window == "object")
	fillRandom = undefined

else{

	let nodecrypto = require("crypto")

	fillRandom = data => nodecrypto.randomFillSync(data)

}