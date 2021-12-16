var Uluru = Uluru || require("../uluru")
var {performance} = typeof performance == "object" ? {performance} : require('perf_hooks')

let ctr = 0

function time(label, callback, iterations = 1, ...args){

	let started
	let times = []

	let total = performance.now()

	for(let i = 0; i < iterations; i++){

		started = performance.now()

		callback(...args)

		times.push(performance.now() - started)

	}

	total = performance.now() - total

	let average = times.reduce((a, b) => a + b, 0) / times.length

	console.log(
		`>${ctr}> ${iterations} iterations of ${label} finished in ${total.toFixed(2)}ms` +
		`, average: ${average.toFixed(2)}ms` +
		`, iters/sec: ${(times.length / average).toFixed(2)}`
	)

	times.sort((a, b) => a - b)

	ctr++

	return times

}
function headline(str){
	console.log(`\n==${str.toUpperCase()}==`)
}

headline(`Random generation (${!Uluru.Random.secure ? "in" : ""}secure)`)
time("random 1kB", (rand, target) => rand.fill(target), 20, new Uluru.Random(), new Uint8Array(1000))
time("random 1MB", (rand, target) => rand.fill(target), 10, new Uluru.Random(), new Uint8Array(1000000))
time("random 10MB", (rand, target) => rand.fill(target), 3, new Uluru.Random(), new Uint8Array(10000000))

let randdata = new Uluru.Random().fill(new Uint8Array(1000000))

headline("hashing")
time("hash 1MB", () => new Uluru.Keccak800().update(randdata).finalize(), 20)