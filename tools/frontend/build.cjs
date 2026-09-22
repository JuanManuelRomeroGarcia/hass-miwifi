const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const output = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve(__dirname, '../../custom_components/miwifi/www/vendor');
fs.mkdirSync(output, { recursive: true });
const result = esbuild.buildSync({
  stdin: {
    contents: 'export {html, css, LitElement} from "lit"; export {until} from "lit/directives/until.js";',
    resolveDir: __dirname,
    sourcefile: 'miwifi-lit.js',
  },
  bundle: true, format: 'esm', platform: 'browser', target: 'es2020',
  minify: true, legalComments: 'eof', metafile: true,
  outfile: path.join(output, 'lit.js'),
});
const packages = new Map();
for (const input of Object.keys(result.metafile.inputs)) {
  if (input === 'miwifi-lit.js') continue;
  let folder = path.dirname(path.resolve(input));
  while (folder !== path.dirname(folder)) {
    if (fs.existsSync(path.join(folder, 'package.json'))) {
      const info = JSON.parse(fs.readFileSync(path.join(folder, 'package.json'), 'utf8'));
      const license = ['LICENSE', 'LICENSE.txt', 'LICENSE.md'].map(n => path.join(folder, n)).find(p => fs.existsSync(p));
      if (license) packages.set(info.name, {version: info.version, text: fs.readFileSync(license, 'utf8')});
      break;
    }
    folder = path.dirname(folder);
  }
}
if (!packages.has('lit') || !packages.has('lit-html')) throw Error('Missing runtime license information');
fs.writeFileSync(path.join(output, 'LICENSES.txt'), [...packages].map(([name, p]) => `${name} ${p.version}\n${p.text}`).join('\n\n'));
fs.writeFileSync(path.join(output, 'versions.json'), JSON.stringify(Object.fromEntries([...packages].map(([name,p]) => [name,p.version])), null, 2)+'\n');
console.log(`Bundled Lit and ${packages.size} runtime licenses into ${output}`);
