var Uluru = Uluru || require("../uluru")

function assert(label, condition){

	if(!!condition)
		console.log("\x1b[32m%s\x1b[0m✔️", label,)

	else{
		console.log("\x1b[31m%s\x1b[0m❌", label)
		throw "Assertion failed"
	}
}

assert("uluru is loaded", typeof Uluru == "object")

assert("ascii encode works", new Uluru.enc.Ascii().encode("ABabč ?😍").join(",") == "65,66,97,98,13,32,63,61,13")
assert("ascii decode works",
	new Uluru.enc.Ascii().decode(new Uint8Array([
		0,1,11,12,13,14,32,33,34,49,198,230,250,100,196,141,240,159,152,141
	])) == '\x00\x01\v\f\r\x0E !"1ÆæúdÄ\x8Dð\x9F\x98\x8D'
)

assert("hex encode works", new Uluru.enc.Hex().encode("1019deadbeefe").join(",") == "16,25,222,173,190,239")
assert("hex decode works",
	new Uluru.enc.Hex().decode(new Uint8Array([
		16,25,222,173,190,239
	])) == '1019deadbeef'
)
