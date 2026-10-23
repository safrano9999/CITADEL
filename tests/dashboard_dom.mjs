// Execute the rendered dashboard script against a small DOM. No browser,
// network, installed packages or test containers are needed for mode switching.
import vm from 'node:vm';
let raw = '';
for await (const chunk of process.stdin) raw += chunk;
const input = JSON.parse(raw);
function element() {
  return {hidden: false, textContent: '', children: [], dataset: {}, attributes: {}, handlers: {},
    addEventListener(name, handler) { this.handlers[name] = handler; },
    setAttribute(name, value) { this.attributes[name] = value; },
    append(...nodes) { this.children.push(...nodes); },
    replaceChildren() { this.children = []; }};
}
const tiles = input.tiles.map(attrs => {
  const tile = element();
  const classes = new Set();
  const label = element(), endpoints = element(), cardLink = element();
  tile.dataset = {port: attrs['data-port'], apiEndpoints: attrs['data-api-endpoints'], interfaceLinks: attrs['data-interface-links'], browserHttp: attrs['data-browser-http'], serviceReachable: attrs['data-service-reachable'], accessConfigured: attrs['data-access-configured'], protocolFilters: attrs['data-protocol-filters'], serviceName: attrs['data-service-name'], process: attrs['data-process']};
  tile.dataset.apiOnly = attrs['data-api-only'];
  tile.getAttribute = name => attrs[name];
  tile.querySelector = selector => ({'.tile-url': label, '.api-endpoints': endpoints, '.tile-link': cardLink})[selector] ?? null;
  tile.classList = {toggle(name, active) { active ? classes.add(name) : classes.delete(name); }};
  tile.classes = classes;
  tile.endpoints = endpoints;
  tile.cardLink = cardLink;
  return tile;
});
const selection = {...element(), options: input.modes.map(value => ({value}))};
const controls = {'route-mode-sel': selection, 'services-title': element(),
  'api-empty': element(), 'other-ports': element(), 'filtered-services': element(), 'protocol-filters': element()};
const filterButtons = ['mcp', 'api'].map(protocolFilter => ({...element(), dataset: {protocolFilter}}));
controls['other-ports'].dataset.hasPorts = input.hasPorts ? '1' : '0';
const document = {body: {dataset: {defaultMode: input.defaultMode}},
  getElementById: id => controls[id] ?? null,
  querySelectorAll: selector => selector === '.tile' ? tiles : selector === '[data-protocol-filter]' ? filterButtons : [],
  createElement: () => element(), createTextNode: text => ({textContent: text})};
const context = vm.createContext({document,
  localStorage: {getItem: () => null}, window: {open() {}}, console});
vm.runInContext(input.script, context, {timeout: 1000});
function descendants(node) { return [node, ...(node.children ?? []).flatMap(descendants)]; }
function text(node) { return descendants(node).map(child => child.textContent || '').join(' '); }
const results = {};
function snapshot() {
  return {title: controls['services-title'].textContent,
    otherHidden: controls['other-ports'].hidden, empty: !controls['api-empty'].hidden,
    filtersHidden: controls['protocol-filters'].hidden,
    filters: filterButtons.map(button => ({category: button.dataset.protocolFilter, hidden: button.hidden,
      pressed: button.attributes['aria-pressed'], text: button.textContent})),
    filtered: controls['filtered-services'].children.map(row => ({text: text(row),
      links: descendants(row).filter(node => node.href).map(node => node.href)})),
    visible: tiles.filter(tile => !tile.hidden).map(tile => ({
      port: Number(tile.dataset.port), grey: tile.classes.has('no-link'),
      url: tile.dataset.activeUrl,
      cardHref: tile.cardLink.hidden ? null : tile.cardLink.href,
      details: tile.endpoints.children.map(text),
      statusLines: tile.endpoints.children.flatMap(descendants).filter(node => node.className === 'api-statuses').flatMap(node => node.children.map(child => child.textContent)),
      links: tile.endpoints.children.flatMap(descendants).filter(node => node?.href).map(node => node.href),
      linkLabels: tile.endpoints.children.flatMap(descendants).filter(node => node?.href).map(node => node.textContent),
      protocolLabels: tile.endpoints.children.flatMap(descendants).filter(node => node.className === 'api-endpoint-protocol').map(node => node.textContent),
    }))};
}
for (const mode of [...input.modes, input.defaultMode]) {
  selection.value = mode;
  vm.runInContext(`applyMode(${JSON.stringify(mode)})`, context, {timeout: 1000});
  results[mode] = snapshot();
}
if (input.actions?.length) {
  results.actions = [];
  for (const action of input.actions) {
    selection.value = action.mode;
    vm.runInContext(`applyMode(${JSON.stringify(action.mode)})`, context, {timeout: 1000});
    if (action.toggle) filterButtons.find(button => button.dataset.protocolFilter === action.toggle).handlers.click();
    results.actions.push(snapshot());
  }
}
process.stdout.write(JSON.stringify(results));
