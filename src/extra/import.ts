//@ts-ignore
var crypto = typeof crypto == "object" ? crypto : typeof global == "object" ? function(){
	//@ts-ignore
	var cryp = require("crypto")
	return {
		getRandomValues(data: ArrayBufferView){
			cryp.randomFillSync(data)
			return data
		}
	}
}() : undefined