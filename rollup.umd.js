import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json'
import resolve from '@rollup/plugin-node-resolve'
import typescript from '@rollup/plugin-typescript'
import { terser } from 'rollup-plugin-terser'

const name = 'Uluru'
const extensions = ['.mjs', '.js', '.json', '.node', '.ts']

export default {
		
	input: './src/index-umd.ts',

	plugins: [

		// Allows node_modules resolution
		resolve({
			preferBuiltins: true,
			browser: true,
			extensions,
		}),

		// allow json importing
		json(),

		// Allow bundling cjs modules. Rollup doesn't understand cjs
		commonjs(),

		// Compile TypeScript/JavaScript files
		typescript()

	],

	output: [
		{
			file: 'dist/uluru-umd.js',
			format: 'umd',
			name,
		},
		{
			file: 'dist/uluru-umd.min.js',
			format: 'umd',
			name,
			plugins: [
				//minify
				terser(),
			]
		}
	]
}