
declare const crypto

export let fillRandom: (data: ArrayBufferView) => ArrayBufferView

if(typeof crypto == "object"){

	fillRandom = crypto.getRandomValues

}
else if(typeof global != "object" && typeof window == "object"){

	fillRandom = undefined

}
else{

	let nodecrypto = require("crypto")

	fillRandom = function(data: ArrayBufferView){

		nodecrypto.randomFillSync(data)
		return data

	}

}