export * from "./algo/algo"
export * from "./enc/enc"
export * from "./easy"

import * as algo from "./algo/algo"
import * as enc from "./enc/enc"
import * as easy from "./easy"

export default {
	...algo,
	...enc,
	...easy
}