// tests/fixtures/vuln/app.js - true-positive fixture for
// modules/sast/rules/javascript.rules (tests/suites/sast.sh), one snippet per
// rule id.  Mirrors tests/fixtures/vuln/app.py, which already carries the
// Python side of the shared vuln/clean gate-test tree.

function runDynamic(userInput) {
  return eval(userInput);
}

function Comment({ body }) {
  return React.createElement('div', { dangerouslySetInnerHTML: { __html: body } });
}

function renderLegacyBanner(markup) {
  document.write('<div class="banner">' + markup + '</div>');
}

function findUser(db, id) {
  const q = `SELECT * FROM users WHERE id = ${id}`;
  return db.query(q);
}

function loadPlugin(pluginName) {
  return require(pluginName);
}

function setProto(obj, payload) {
  obj.__proto__ = payload;
}

function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}
