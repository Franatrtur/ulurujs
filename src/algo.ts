namespace Uluru {

	export interface algorithm {

		update: (data: ArrayBufferView | string) => algorithm

		finalize: (...args: any) => object

		[key: string]: any

	}

}