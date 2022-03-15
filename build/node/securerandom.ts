import { randomFillSync } from "crypto"

export function fillRandom(data: ArrayBufferView): ArrayBufferView{

	//@ts-ignore
	return randomFillSync(data)
	
}