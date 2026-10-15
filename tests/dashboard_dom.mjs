// Execute the rendered dashboard script against a small DOM. No browser,
// network, installed packages or test containers are needed for mode switching.
import vm from 'node:vm';
let raw = '';
for await (const chunk of process.stdin) raw += chunk;
const input = JSON.parse(raw);
function element() {
  return {hidden: false, textContent: '', children: [],
    addEventListener() {}, append(...nodes) { this.children.push(...nodes); },
    replaceChildren() { this.children = []; }};
}
const tiles = input.tiles.map(attrs => {
  const tile = element();
  const classes = new Set();
  const label = element(), endpoints = element();
  tile.dataset = {port: attrs['data-port'], apiEndpoints: attrs['data-api-endpoints']};
  tile.getAttribute = name => attrs[name];
  tile.querySelector = selector => ({'.tile-url': label, '.api-endpoints': endpoints})[selector] ?? null;
  tile.classList = {toggle(name, active) { active ? classes.add(name) : classes.delete(name); }};
  tile.classes = classes;
  tile.endpoints = endpoints;
  return tile;
});
const selection = {...element(), options: input.modes.map(value => ({value}))};
const controls = {'route-mode-sel': selection, 'services-title': element(),
  'api-empty': element(), 'other-ports': element()};
const document = {body: {dataset: {defaultMode: input.defaultMode}},
  getElementById: id => controls[id] ?? null,
  querySelectorAll: selector => selector === '.tile' ? tiles : [],
  createElement: () => element(), createTextNode: text => ({textContent: text})};
const context = vm.createContext({document,
  localStorage: {getItem: () => null}, window: {open() {}}, console});
vm.runInContext(input.script, context, {timeout: 1000});
const results = {};
for (const mode of [...input.modes, input.defaultMode]) {
  vm.runInContext(`applyMode(${JSON.stringify(mode)})`, context, {timeout: 1000});
  results[mode] = {title: controls['services-title'].textContent,
    otherHidden: controls['other-ports'].hidden, empty: !controls['api-empty'].hidden,
    visible: tiles.filter(tile => !tile.hidden).map(tile => ({
      port: Number(tile.dataset.port), grey: tile.classes.has('no-link'),
      url: tile.dataset.activeUrl,
      details: tile.endpoints.children.map(row => row.textContent),
      links: tile.endpoints.children.flatMap(row => row.children ?? []).filter(node => node?.href).map(node => node.href),
    }))};
}
process.stdout.write(JSON.stringify(results));
