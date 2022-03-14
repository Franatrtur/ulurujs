export let fillRandom = typeof crypto == "object" ? function fillRandom(data: ArrayBufferView): ArrayBufferView{

	return crypto.getRandomValues(data)
	
} : undefined