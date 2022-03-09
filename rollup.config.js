import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json'
import resolve from '@rollup/plugin-node-resolve'
import typescript from '@rollup/plugin-typescript'
import { terser } from 'rollup-plugin-terser'

const name = 'Uluru'
const extensions = ['.mjs', '.js', '.json', '.node', '.ts']

export default [
	{
		
		input: './src/index-browser.ts',

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
			typescript({
				tsconfig: "tsconfig-browser.json"
			})

		],

		output: [
			{
				file: 'dist/uluru-browser.js',
				format: 'umd',
				name,
				sourcemap: true,
			},
			{
				file: 'dist/uluru-browser.min.js',
				format: 'umd',
				name,
				sourcemap: true,
				plugins: [
					//minify
					terser(),
				]
			}
		]
	},

	//For mjs we need the regular index input
	{
	
		input: './src/index.ts',
	
		plugins: [
			resolve({
				preferBuiltins: true,
				browser: true,
				extensions,
			}),
			json(),
			commonjs(),
			typescript({
				tsconfig: "tsconfig.json",
				outDir: "./",
				exclude: []
			})
		],
	
		output: [
			{
				file: 'dist/uluru-browser.mjs',
				format: 'es',
				sourcemap: true,
			}
		]
	}
]