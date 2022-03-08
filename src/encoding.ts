export default interface encoding {

	encode: (str: string) => Uint8Array

	decode: (bytes: ArrayBufferView) => string

}