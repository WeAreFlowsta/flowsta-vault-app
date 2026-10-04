// The built app loads no style or font from another host: everything the
// window shows ships inside it. Run after a build; fails on any outside URL
// in the built stylesheets or an outside stylesheet/font link in the pages.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('../dist/', import.meta.url).pathname;
const files = [];
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path);
    else if (/\.(css|html)$/.test(name)) files.push(path);
  }
})(root);

const found = [];
for (const file of files) {
  const text = readFileSync(file, 'utf8');
  const patterns = file.endsWith('.css')
    ? [/url\(\s*["']?(https?:)?\/\/[^)]+\)/g, /@import\s+["'](https?:)?\/\/[^"']+["']/g]
    : [/<link[^>]+rel=["']?(stylesheet|preconnect|preload)["']?[^>]*href=["']?(https?:)?\/\/[^"'\s>]+/g];
  for (const pattern of patterns) {
    for (const match of text.match(pattern) || []) found.push(`${file.slice(root.length)}: ${match.slice(0, 120)}`);
  }
}
if (found.length) {
  console.error('Styles or fonts loaded from another host:\n' + found.join('\n'));
  process.exit(1);
}
console.log(`no outside styles or fonts (${files.length} files checked)`);
