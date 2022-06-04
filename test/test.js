
var Uluru = Uluru || require("../dist/uluru-umd")
if(typeof performance != "object")
	var {performance} = require("perf_hooks")


let ERRORS = []

;(function(){

let Nrun = 0

const Colors = {
	red: "\x1b[31m",
	green: "\x1b[32m",
	end: "\x1b[0m"
}

function Run(name, trial, ...args){

	Nrun++

	let t0 = performance.now()
	let success = true
	let err

	try{

		if(!trial(...args))
			throw "Test failed with a falsy return value"

	}
	catch(e){

		success = false
		err = e

		ERRORS[Nrun] = err

	}

	let t1 = performance.now()

	console.log(
		`${Nrun}) ${success ? Colors.green : Colors.red}${name}${Colors.end} ${success ? "✓" : "✗"} (${(t1 - t0).toFixed(2)}ms)`
		+ (success ? "" : `\n${err.toString()}`)
	)

}


function encodingTester(encoder, streams){

	for(let i in streams){

		if(encoder.encode(streams[i].string).join(",") != streams[i].bytes.join(","))
			throw `Cannot encode stream #${i}`

		if(encoder.decode(new Uint8Array(streams[i].bytes)) != streams[i].string)
			throw `Cannot decode stream #${i}`

	}

	return true

}


Run("Ascii encoding", () => {

	let streams = [
		{
			string: "Aa Zz",
			bytes: [65,97,32,90,122]
		},
		{
			string: '\x00\x01\v\f\r\x0E !"1ÆæúdÄ\x8Dð\x9F\x98\x8D',
			bytes: [0,1,11,12,13,14,32,33,34,49,198,230,250,100,196,141,240,159,152,141]
		}
	]

	return encodingTester(new Uluru.Ascii(), streams)

})

Run("Base64 encoding", () => {

	let streams = [
		{
			string: "9dr2AnGW6y3aghaC",
			bytes: [245,218,246,2,113,150,235,45,218,130,22,130]
		}
	]

	return encodingTester(new Uluru.Base64(), streams)

})

Run("Hex encoding", () => {

	let streams = [
		{
			string: "1019deadbeef",
			bytes: [16,25,222,173,190,239]
		}
	]

	return encodingTester(new Uluru.Hex(), streams)

})

Run("Utf8 encoding", () => {

	let streams = [
		{
			string: "Aa Zz",
			bytes: [65,97,32,90,122]
		},
		{
			string: `\x10Aa ?“
”„†•…‰™œŠŸž€ ΑΒΓΔΩαβγδω АБВГДабвгдማይሰᚳᚹ‾⍎'´\`
  ∀∂∈ℝ∧∪≡∞ ↑↗↨↻⇣ ┐┼╔╘░►☺♀ ﬁ�⑀₂ἠḂӥẄɐː⍎אԱა⠜⠇⠑コンニ有有 個	个🧨🤐
`,
			bytes: [16,65,97,32,63,226,128,156,10,226,128,157,226,128,158,226,128,160,226,128,162,226,128,166,226,128,176,226,132,162,197,147,197,160,197,184,197,190,226,130,172,32,206,145,206,146,206,147,206,148,206,169,206,177,206,178,206,179,206,180,207,137,32,208,144,208,145,208,146,208,147,208,148,208,176,208,177,208,178,208,179,208,180,225,136,155,225,139,173,225,136,176,225,154,179,225,154,185,226,128,190,226,141,142,39,194,180,96,10,32,32,226,136,128,226,136,130,226,136,136,226,132,157,226,136,167,226,136,170,226,137,161,226,136,158,32,226,134,145,226,134,151,226,134,168,226,134,187,226,135,163,32,226,148,144,226,148,188,226,149,148,226,149,152,226,150,145,226,150,186,226,152,186,226,153,128,32,239,172,129,239,191,189,226,145,128,226,130,130,225,188,160,225,184,130,211,165,225,186,132,201,144,203,144,226,141,142,215,144,212,177,225,131,144,226,160,156,226,160,135,226,160,145,227,130,179,227,131,179,227,131,139,230,156,137,230,156,137,32,229,128,139,9,228,184,170,240,159,167,168,240,159,164,144,10]
		}
	]

	return encodingTester(new Uluru.Utf8(), streams)

})


Run("Ez Hash checksums (old)", () => {

	return Uluru.hash("").startsWith("f47a2c3a") && Uluru.hash("A").startsWith("ad54ca3f") && Uluru.hash("_fillč".repeat(690)).startsWith("ad282344")

})
Run("Keccak squeezing (old)", () => {

	return new Uluru.Keccak800().update("TOOTH").finalize(256).toString().startsWith(new Uluru.Keccak800().update("TOOTH").finalize(32).toString())

})
Run("Backwards compatible decryption (old)", () => {

	return "ahoj" == Uluru.decrypt("12381b81274b8c9dMZIzcQ==27637d76eedac4201a37571c917273f8", "k")

})


console.log("\n===" + (ERRORS.length ? `${Colors.red}TEST DIDN'T PASS` : `${Colors.green}TEST PASSED`) + Colors.end + "===")

})();
