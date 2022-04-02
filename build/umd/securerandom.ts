export let fillRandom = typeof crypto == "object" ? function fillRandom(data: ArrayBufferView): ArrayBufferView{

	return crypto.getRandomValues(data)
	
} : typeof module == "object" && typeof require == "function" ? function(){

	//when the browser umd is used in node by require-ing

	const nodecrypto = require("crypto")

	return function fillRandom(data: ArrayBufferView): ArrayBufferView{

		return nodecrypto.randomFillSync(data)
		
	}
	
}() : undefined