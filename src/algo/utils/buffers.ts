
export function mergeBuffers(...bufferViews: ArrayBufferView[]): Uint8Array{

	let len = 0
	for(let i = 0; i < bufferViews.length; i++)
		len += bufferViews[i].byteLength

	let result = new Uint8Array(len)
	let pointer = 0

	for(let i = 0; i < bufferViews.length; i++){

		result.set(new Uint8Array(bufferViews[i].buffer, bufferViews[i].byteOffset, bufferViews[i].byteLength), pointer)
		pointer += bufferViews[i].byteLength

	}

	return result

}