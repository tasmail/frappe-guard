"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { create, HOSTS } = require("../../frappe_guard/public/js/guard.js");

// A fake browser: scripts are appended and settled by the test, timers are run by the test.
function browser(options) {
	options = options || {};
	const scripts = [];
	const timers = [];
	const listeners = {};
	const calls = [];
	const win = {};
	const doc = {
		head: { appendChild: (script) => scripts.push(script) },
		createElement: () => ({}),
		addEventListener: (name, fn) => ((listeners[name] = listeners[name] || []).push(fn)),
		removeEventListener: (name, fn) => {
			listeners[name] = (listeners[name] || []).filter((item) => item !== fn);
		},
	};
	const clock = { t: 1000 };
	const env = {
		window: win,
		document: doc,
		now: () => clock.t,
		Headers: options.Headers,
		fetch: (url, settings) => {
			calls.push({ url, settings });
			return Promise.resolve({ status: options.status || 200 });
		},
		setTimeout: (fn, ms) => timers.push({ fn, ms }) && timers.length,
		clearTimeout: (id) => {
			timers[id - 1] = null;
		},
	};
	win.grecaptcha = undefined;
	const install = (execute) => {
		win.grecaptcha = {
			ready: (cb) => cb(),
			execute: execute || ((key, opts) => Promise.resolve("token-for-" + opts.action)),
		};
	};
	return { env, scripts, timers, listeners, calls, win, install, clock };
}
const tick = () => new Promise((resolve) => setImmediate(resolve));

test("the script is loaded from google first with the site key, and a token is made per call", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "KEY 1" });
	const pending = client.token("contact");
	await tick();
	assert.equal(b.scripts.length, 1);
	assert.equal(b.scripts[0].src, "https://www.google.com/recaptcha/api.js?render=KEY%201");
	b.install();
	b.scripts[0].onload();
	assert.equal(await pending, "token-for-contact");
	assert.equal(await client.token("download"), "token-for-download"); // loaded once, a new token each time
	assert.equal(b.scripts.length, 1);
});

test("when google does not load the script comes from recaptcha.net", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	const pending = client.token("contact");
	await tick();
	b.scripts[0].onerror();
	await tick();
	assert.equal(b.scripts.length, 2);
	assert.match(b.scripts[1].src, /^https:\/\/www\.recaptcha\.net\/recaptcha\/api\.js\?render=K$/);
	b.install();
	b.scripts[1].onload();
	assert.equal(await pending, "token-for-contact");
});

test("a host that hangs is abandoned after the timeout", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	const pending = client.token("contact");
	await tick();
	assert.deepEqual(b.timers.map((timer) => timer.ms), [8000, 4000]); // the deadline of the step, the host
	b.timers[1].fn(); // the first host never answers
	await tick();
	assert.equal(b.scripts.length, 2);
	b.install();
	b.scripts[1].onload();
	assert.equal(await pending, "token-for-contact");
});

test("no token is made and nothing throws when every host fails, and a later call tries again", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	const first = client.token("contact");
	await tick();
	b.scripts[0].onerror();
	await tick();
	b.scripts[1].onerror();
	assert.equal(await first, "");
	assert.equal(await client.token("contact"), ""); // not waited for again at once
	assert.equal(b.scripts.length, 2);
	b.clock.t += 15001;
	const second = client.token("contact");
	await tick();
	assert.equal(b.scripts.length, 3); // loading starts again
	b.install();
	b.scripts[2].onload();
	assert.equal(await second, "token-for-contact");
});

test("without a site key nothing is loaded and the token is empty", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({});
	assert.equal(await client.token("contact"), "");
	assert.equal(b.scripts.length, 0);
});

test("a failing or hanging execute gives an empty token", async () => {
	const b = browser();
	b.install(() => Promise.reject(new Error("blocked")));
	const client = create(b.env);
	client.init({ siteKey: "K" });
	assert.equal(await client.token("contact"), "");
	b.install(() => new Promise(() => {}));
	const hanging = client.token("contact");
	await tick();
	b.timers[b.timers.length - 1].fn(); // the deadline of the step
	assert.equal(await hanging, "");
	b.install(() => Promise.resolve(42));
	assert.equal(await client.token("contact"), "");
});

test("a request carries the token, asks for JSON and keeps the options", async () => {
	const b = browser();
	b.install();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	const response = await client.request("/api/method/x", {
		action: "contact",
		method: "POST",
		body: "b",
		headers: { "X-Custom": "1" },
	});
	assert.equal(response.status, 200);
	const call = b.calls[0];
	assert.equal(call.url, "/api/method/x");
	assert.equal(call.settings.method, "POST");
	assert.equal(call.settings.body, "b");
	assert.equal("action" in call.settings, false);
	assert.deepEqual(call.settings.headers, {
		"X-Custom": "1",
		Accept: "application/json",
		"X-Requested-With": "XMLHttpRequest",
		"X-Guard-Token": "token-for-contact",
	});
});

test("a request without a token still goes out, without the header", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({});
	await client.request("/x", { action: "contact" });
	const headers = b.calls[0].settings.headers;
	assert.equal("X-Guard-Token" in headers, false);
	assert.equal(headers.Accept, "application/json");
});

test("the script is loaded on the first interaction with a protected form only, once", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	assert.equal(b.scripts.length, 0); // not at page load
	const inside = { target: { closest: (selector) => (selector === "form[data-guard-action]" ? {} : null) } };
	const outside = { target: { closest: () => null } };
	b.listeners.focusin[0](outside);
	await tick();
	assert.equal(b.scripts.length, 0);
	b.listeners.pointerdown[0](inside);
	await tick();
	assert.equal(b.scripts.length, 1);
	assert.equal((b.listeners.pointerdown || []).length, 0); // the listeners are gone
});

test("a custom selector and hosts are honoured", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "K", selector: ".protected", hosts: ["example.test"] });
	b.listeners.keydown[0]({ target: { closest: (selector) => (selector === ".protected" ? {} : null) } });
	await tick();
	assert.match(b.scripts[0].src, /^https:\/\/example\.test\/recaptcha\/api\.js/);
});

test("an event without a target is ignored", () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	b.listeners.focusin[0]({});
	b.listeners.focusin[0](undefined);
	assert.equal(b.scripts.length, 0);
});

test("the defaults are the two hosts of the provider", () => {
	assert.deepEqual(HOSTS, ["www.google.com", "www.recaptcha.net"]);
});

test("an already loaded provider is not loaded again", async () => {
	const b = browser();
	b.install();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	await client.warm();
	assert.equal(b.scripts.length, 0);
});

test("warm never throws", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({});
	assert.equal(await client.warm(), null);
});

test("a whole step that exceeds the deadline gives an empty token and is not repeated for 15 seconds", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	const slow = client.token("contact");
	await tick();
	b.timers[0].fn(); // the deadline of the whole step: 8 seconds, not the sum of the hosts and the token
	assert.equal(await slow, "");
	assert.equal(await client.token("contact"), "");
	assert.equal(b.scripts.length, 1);
});

test("a failing execute does not make the provider unreachable", async () => {
	const b = browser();
	b.install(() => Promise.reject(new Error("invalid key")));
	const client = create(b.env);
	client.init({ siteKey: "K" });
	assert.equal(await client.token("contact"), "");
	b.install();
	assert.equal(await client.token("contact"), "token-for-contact"); // no waiting period after an error of execute
});

test("a script that loads without grecaptcha is removed and the next host is tried", async () => {
	const b = browser();
	const removed = [];
	b.env.document.head.appendChild = (script) => {
		script.parentNode = { removeChild: (item) => removed.push(item) };
		b.scripts.push(script);
	};
	const client = create(b.env);
	client.init({ siteKey: "K" });
	const pending = client.token("contact");
	await tick();
	b.scripts[0].onload(); // loaded, but nothing usable
	await tick();
	assert.equal(removed.length, 1);
	assert.equal(b.scripts.length, 2);
	b.install();
	b.scripts[1].onload();
	assert.equal(await pending, "token-for-contact");
	b.scripts[0].onerror();
	assert.equal(removed.length, 2);
});

test("a Headers instance, an array of pairs and a plain object of the caller are kept and merged without duplicates", async () => {
	const b = browser({ Headers });
	b.install();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	for (const base of [
		new Headers({ "X-Frappe-CSRF-Token": "csrf", accept: "text/html" }),
		[["X-Frappe-CSRF-Token", "csrf"], ["accept", "text/html"]],
		{ "X-Frappe-CSRF-Token": "csrf", accept: "text/html" },
	]) {
		await client.request("/x", { action: "contact", headers: base });
		const sent = b.calls[b.calls.length - 1].settings.headers;
		const get = (name) => (sent instanceof Headers ? sent.get(name) : sent[name]);
		assert.equal(get("X-Frappe-CSRF-Token"), "csrf");
		assert.equal(get("Accept"), "application/json");
		assert.equal(get("X-Guard-Token"), "token-for-contact");
	}
});

test("the plain-object merge replaces a differently cased header instead of duplicating it", async () => {
	const b = browser();
	b.install();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	await client.request("/x", { action: "contact", headers: { accept: "text/html", "x-requested-with": "x" } });
	const sent = b.calls[0].settings.headers;
	assert.deepEqual(Object.keys(sent).map((name) => name.toLowerCase()).sort(), [
		"accept",
		"x-guard-token",
		"x-requested-with",
	]);
});

test("hosts that are not plain host names are ignored, and a bad selector does not break the page", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "K", hosts: ["evil.com/x?", "a.com@b.com", 5], selector: "((" });
	const throwing = { target: { closest: () => { throw new SyntaxError("bad selector"); } } };
	b.listeners.focusin[0](throwing); // does not throw
	const pending = client.token("contact");
	await tick();
	assert.match(b.scripts[0].src, /^https:\/\/www\.google\.com\//); // the defaults, not the bad hosts
	client.init({ siteKey: "K", hosts: ["good.example", "evil.com/x?"] });
	assert.ok(pending);
});

test("a repeated init with the same settings does not restart a load in flight", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	client.warm();
	await tick();
	client.init({ siteKey: "K" });
	client.warm();
	await tick();
	assert.equal(b.scripts.length, 1);
});

test("the file as a browser loads it: it defines window.FrappeGuard once and initialises from FRAPPE_GUARD", () => {
	const vm = require("node:vm");
	const fs = require("node:fs");
	const source = fs.readFileSync(require.resolve("../../frappe_guard/public/js/guard.js"), "utf8");
	const listeners = [];
	const sandbox = {
		document: { head: { appendChild() {} }, createElement: () => ({}), addEventListener: (n) => listeners.push(n) },
		Date,
		Promise,
		setTimeout,
		clearTimeout,
		FRAPPE_GUARD: { siteKey: "K" },
	};
	sandbox.window = sandbox;
	vm.runInNewContext(source, sandbox);
	const first = sandbox.FrappeGuard;
	assert.equal(typeof first.request, "function");
	assert.deepEqual(listeners.sort(), ["focusin", "keydown", "pointerdown"]); // init watched the page
	vm.runInNewContext(source, sandbox); // a second copy of the file must not replace the first client
	assert.equal(sandbox.FrappeGuard, first);
});

test("a host that hangs is removed, so its late onload cannot load api.js twice", async () => {
	const b = browser();
	const removed = [];
	b.env.document.head.appendChild = (script) => {
		script.parentNode = { removeChild: (item) => removed.push(item) };
		b.scripts.push(script);
	};
	const client = create(b.env);
	client.init({ siteKey: "K" });
	client.token("contact");
	await tick();
	b.timers[1].fn();
	await tick();
	assert.equal(removed.length, 1);
	assert.equal(b.scripts.length, 2); // the fallback host is tried inside the same request's deadline
});

test("a load chain that failed after init started another one does not clobber the new load", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	client.warm();
	await tick();
	client.init({ siteKey: "OTHER" }); // a new load will start on the next call
	client.warm();
	await tick();
	const before = b.scripts.length;
	b.scripts[0].onerror(); // the old chain fails now
	await tick();
	client.warm();
	await tick();
	assert.ok(b.scripts.length >= before); // no extra duplicate load of the new key
});

test("a provider that became ready after the deadline is used again at once", async () => {
	const b = browser();
	const client = create(b.env);
	client.init({ siteKey: "K" });
	const slow = client.token("contact");
	await tick();
	b.timers[0].fn(); // the deadline
	assert.equal(await slow, "");
	b.install(); // the abandoned load finished meanwhile
	assert.equal(await client.token("contact"), "token-for-contact");
});
