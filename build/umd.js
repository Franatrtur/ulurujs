const fs = require("fs")


let fileContents = fs.readFileSync(__dirname + '\\files.json')
let fileList = JSON.parse(fileContents)

const fixSlashes = pth => pth.split("/").join("\\")

const warningNotice = "//UMD VERSION, see build/"
const destDir = __dirname + "\\..\\src\\"

const buildDir = __dirname + "\\umd\\"

for(let file of fileList){

	fs.writeFileSync(destDir + fixSlashes(file.destination),
		warningNotice + file.buildName + "\n\n" + fs.readFileSync(buildDir + fixSlashes(file.buildName))
	)

}

console.log("written umd build placeholders")

/*

import fs from "fs"
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename) + "\\"


let fileContents = fs.readFileSync(__dirname + '\\files.json')
let fileList = JSON.parse(fileContents)

const fixSlashes = pth => pth.split("/").join("\\")

const warningNotice = "//BROWSER VERSION, see build/"
const destDir = __dirname + "..\\src\\"

const buildDir = __dirname + ".\\browser\\"

for(let file of fileList){

	fs.writeFileSync(destDir + fixSlashes(file.destination),
		warningNotice + file.buildName + "\n\n" + fs.readFileSync(buildDir + fixSlashes(file.buildName))
	)

}

console.log("written browser build placeholders")

*/