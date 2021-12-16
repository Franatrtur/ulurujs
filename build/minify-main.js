const { minify } = require('terser');

// Import fs so we can read/write files
const fs = require('fs');

async function work(){
const config = {
	compress: {
		dead_code: true,
		drop_console: false,
		drop_debugger: true,
		keep_classnames: false,
		keep_fargs: true,
		keep_fnames: false,
		keep_infinity: false
	},
	mangle: {
		eval: false,
		keep_classnames: false,
		keep_fnames: false,
		toplevel: false,
		safari10: false
	},
	module: false,
	sourceMap: false,
	output: {
		comments: 'some'
	}
};

let mylicense =
`/**
 * **LICENSED UNDER THE MIT LICENSE:**
 * @license https://github.com/Franatrtur/ulurucrypto/blob/main/LICENSE
 */
`

// Load in your code to minify
const code = fs.readFileSync(__dirname + '/../uluru.js', 'utf8');

// Minify the code with Terser
const minified = await minify(code, config);

// Save the code!
fs.writeFileSync(__dirname + '/../uluru.min.js', mylicense + minified.code);
}

work()