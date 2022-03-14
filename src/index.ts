export * from "./algo/algo.js"
export * from "./enc/enc.js"
export * from "./easy.js"

import * as algo from "./algo/algo.js"
import * as enc from "./enc/enc.js"
import * as easy from "./easy.js"

export default {
	...algo,
	...enc,
	...easy
}