// tests/fixtures/clean/app.js - true-negative (safe equivalent) fixture for
// modules/sast/rules/javascript.rules (tests/suites/sast.sh), one snippet per
// rule id in tests/fixtures/vuln/app.js, in the same order.  This file is
// also walked by the whole-tree gate test (scan.sh sast --fail-on high
// --fail-on-new against tests/fixtures/clean), so nothing below may trip any
// shipped rule, JS-specific or language-agnostic, at any severity a linked
// pack assigns.

function runDynamic(userInput) {
  return JSON.parse(userInput);
}

function Comment({ body }) {
  return React.createElement('div', null, body);
}

function renderLegacyBanner(markup) {
  const el = document.createElement('div');
  el.className = 'banner';
  el.textContent = markup;
  document.body.appendChild(el);
}

function findUser(db, id) {
  return db.query('SELECT * FROM users WHERE id = ?', [id]);
}

function loadPlugin(pluginName) {
  switch (pluginName) {
    case 'audit':
      return require('./plugins/audit');
    case 'report':
      return require('./plugins/report');
    default:
      throw new Error('unknown plugin');
  }
}

function setProto(obj, payload) {
  return Object.assign({}, obj, payload);
}

function merge(target, source) {
  return Object.assign({}, target, source);
}
