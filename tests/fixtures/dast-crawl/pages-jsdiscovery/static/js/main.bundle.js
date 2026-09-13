// fixture bundle for tests/suites/dast-crawl.sh's JS endpoint discovery cases
// A realistic mix: in-scope relative paths (the main prize), an in-scope
// absolute URL, several third-party absolute URLs that must NEVER be
// requested, and a handful of URL-shaped strings that are not endpoints -
// including the two shapes measured against a real Angular/Juice Shop
// bundle that a real production run mined as bogus endpoints (`/(` and
// `/g,`) before crawl_engine.sh's extraction rules closed them: a plain
// string literal that is a parenthesised code fragment (isAuxRoute below),
// and a bare regex literal whose own pattern matches a quote character,
// which the walker has no concept of and can misread as a string opener
// (escapeHtml below).
var API_ROOT = "https://crawl.fixture.invalid/api/v1/widgets";
function loadOrders() { return fetch("/api/v1/orders").then(function (r) { return r.json(); }); }
function loadItems() { return axios.get("./v2/items"); }
function loadSearch() { return fetch("/search?q=hello&page=2"); }
var stripeCharge = "https://api.stripe.com/v1/charges";
var sentryDsn = "https://o123.ingest.sentry.io/456/envelope";
var contentType = "application/json";
var slugPattern = "/^[a-z0-9_-]+$/";
var logo = "/static/img/logo.png";
var buildComment = "/* build: 2026-09-12 */";
var trackingPixel = "data:text/plain,x";
var anchor = "#section";
function isAuxRoute(seg) { return seg.peekStartsWith("/(") && seg.length > 0; }
function escapeHtml(s) { return String(s).replace(/"/g,"&quot;"); }
