/*
 * frappe_guard: the browser side of the CAPTCHA check (reCAPTCHA v3) for the public forms.
 *
 *   FrappeGuard.init({ siteKey: "..." });
 *   const response = await FrappeGuard.request("/api/method/frappe.www.contact.send_message", {
 *     action: "contact", method: "POST", body: formData });
 *
 * - The script of the provider is loaded on the first interaction with a protected form (`warm`),
 *   not at page load, and not behind the analytics banner: it is named in the privacy text as
 *   anti-abuse (plan G6). It is tried on www.google.com and, when that does not load, on
 *   www.recaptcha.net.
 * - A token is single use and lives two minutes: one is made for every request, never reused. The
 *   whole step is capped at 8 seconds; when the provider cannot be reached the next requests do
 *   not wait for it again for 15 seconds.
 * - The token travels in the header `X-Guard-Token`. The request asks for JSON (`Accept` and
 *   `X-Requested-With`).
 * - No failure of the browser side is thrown: when no token can be made the request goes without
 *   one and the server decides (in `monitor` it passes, in `enforce` it answers that the check
 *   failed and asks to reload).
 * - The site key is public; put it in the page (`init`), never fetch it from an endpoint (a fetch
 *   counts against the edge limit).
 * - Another `api.js?render=OTHER` on the same page makes `execute` fail with an invalid key: load
 *   only one.
 */
(function (root, factory) {
	"use strict";
	var api = factory(root);
	if (typeof module === "object" && module.exports) {
		module.exports = api;
	}
	if (typeof window !== "undefined" && root === window && !root.FrappeGuard) {
		// a second copy of this file (inlined and served) must not replace the first client and its listeners
		root.FrappeGuard = api.defaultClient;
		if (root.FRAPPE_GUARD && root.FRAPPE_GUARD.siteKey) {
			api.defaultClient.init(root.FRAPPE_GUARD);
		}
	}
})(typeof window !== "undefined" ? window : globalThis, function (root) {
	"use strict";

	var HOSTS = ["www.google.com", "www.recaptcha.net"];
	var HOST_PATTERN = /^[a-z0-9.-]+$/i; // a host name only: no path, no credentials
	var LOAD_TIMEOUT = 4000; // per host: two hosts fit in the deadline of one request
	var TOKEN_DEADLINE = 8000; // for the whole token step of a request
	var UNREACHABLE_FOR = 15000;
	var EVENTS = ["focusin", "pointerdown", "keydown"];

	function create(env) {
		var win = env.window;
		var doc = env.document;
		var setTimer = env.setTimeout;
		var clearTimer = env.clearTimeout;
		var now = env.now || Date.now;
		var siteKey = "";
		var hosts = HOSTS.slice();
		var selector = "form[data-guard-action]";
		var loading = null;
		var watching = false;
		var unreachableUntil = 0;

		function withTimeout(promise, ms) {
			return new Promise(function (resolve, reject) {
				var timer = setTimer(function () {
					reject(new Error("timeout"));
				}, ms);
				promise.then(
					function (value) {
						clearTimer(timer);
						resolve(value);
					},
					function (error) {
						clearTimer(timer);
						reject(error);
					}
				);
			});
		}

		function providerReady() {
			return !!(win.grecaptcha && typeof win.grecaptcha.ready === "function");
		}

		function remove(script) {
			if (script && script.parentNode && typeof script.parentNode.removeChild === "function") {
				script.parentNode.removeChild(script);
			}
		}

		function loadFrom(host) {
			return new Promise(function (resolve, reject) {
				var script = doc.createElement("script");
				script.guardTimer = setTimer(function () {
					// a host that hangs is abandoned: its late onload must not load api.js a second time
					remove(script);
					reject(new Error("timeout"));
				}, LOAD_TIMEOUT);
				script.async = true;
				script.src = "https://" + host + "/recaptcha/api.js?render=" + encodeURIComponent(siteKey);
				script.onload = function () {
					clearTimer(script.guardTimer);
					if (providerReady()) {
						resolve();
					} else {
						remove(script);
						reject(new Error("load " + host + ": no grecaptcha"));
					}
				};
				script.onerror = function () {
					clearTimer(script.guardTimer);
					remove(script);
					reject(new Error("load " + host));
				};
				(doc.head || doc.documentElement).appendChild(script);
			});
		}

		function load() {
			if (!siteKey) {
				return Promise.reject(new Error("no site key"));
			}
			if (providerReady()) {
				return Promise.resolve();
			}
			if (!loading) {
				var attempt = Promise.reject(new Error("start"));
				hosts.forEach(function (host) {
					attempt = attempt.catch(function () {
						return loadFrom(host);
					});
				});
				var mine = attempt.catch(function (error) {
					if (loading === mine) {
						// a later call tries again (not when init started another load meanwhile)
						loading = null;
					}
					throw error;
				});
				loading = mine;
			}
			return loading;
		}

		function execute(action) {
			return new Promise(function (resolve, reject) {
				win.grecaptcha.ready(function () {
					win.grecaptcha.execute(siteKey, { action: action }).then(resolve, reject);
				});
			});
		}

		function token(action) {
			if (now() < unreachableUntil && !providerReady()) {
				return Promise.resolve("");
			}
			return withTimeout(
				load().then(function () {
					return execute(action);
				}),
				TOKEN_DEADLINE
			)
				.then(function (value) {
					return typeof value === "string" ? value : "";
				})
				.catch(function (error) {
					if (error && /^(timeout|load)/.test(error.message)) {
						// the provider cannot be reached: do not wait for it again
						unreachableUntil = now() + UNREACHABLE_FOR;
					}
					return ""; // never thrown: the server decides what a request without a token is
				});
		}

		function merge(base, extra) {
			if (typeof env.Headers === "function") {
				var merged = new env.Headers(base || undefined);
				Object.keys(extra).forEach(function (name) {
					merged.set(name, extra[name]);
				});
				return merged;
			}
			var result = {};
			Object.keys(base || {}).forEach(function (name) {
				result[name] = base[name];
			});
			Object.keys(extra).forEach(function (name) {
				Object.keys(result).forEach(function (existing) {
					if (existing.toLowerCase() === name.toLowerCase()) {
						delete result[existing];
					}
				});
				result[name] = extra[name];
			});
			return result;
		}

		function headers(action, base) {
			return token(action).then(function (value) {
				var extra = { Accept: "application/json", "X-Requested-With": "XMLHttpRequest" };
				if (value) {
					extra["X-Guard-Token"] = value;
				}
				return merge(base, extra);
			});
		}

		function request(url, options) {
			var settings = {};
			Object.keys(options || {}).forEach(function (name) {
				settings[name] = options[name];
			});
			var action = settings.action;
			delete settings.action;
			return headers(action, settings.headers).then(function (merged) {
				settings.headers = merged;
				return env.fetch(url, settings);
			});
		}

		function warm() {
			return load().catch(function () {
				return null;
			});
		}

		function inside(target) {
			try {
				return !!(target && typeof target.closest === "function" && target.closest(selector));
			} catch (error) {
				return false; // an invalid selector must not break every interaction of the page
			}
		}

		function interacted(event) {
			if (inside(event && event.target)) {
				EVENTS.forEach(function (name) {
					doc.removeEventListener(name, interacted, true);
				});
				watching = false;
				warm();
			}
		}

		function watch() {
			if (watching || !doc.addEventListener) {
				return;
			}
			watching = true;
			EVENTS.forEach(function (name) {
				doc.addEventListener(name, interacted, true);
			});
		}

		function init(settings) {
			settings = settings || {};
			var key = typeof settings.siteKey === "string" ? settings.siteKey : "";
			var wanted = hosts;
			if (Array.isArray(settings.hosts)) {
				var valid = settings.hosts.filter(function (host) {
					return typeof host === "string" && HOST_PATTERN.test(host);
				});
				wanted = valid.length ? valid : HOSTS.slice();
			}
			if (typeof settings.selector === "string") {
				selector = settings.selector;
			}
			if (key !== siteKey || wanted.join() !== hosts.join()) {
				loading = null; // a load in flight is not restarted by a repeated init with the same settings
			}
			siteKey = key;
			hosts = wanted;
			if (siteKey) {
				watch();
			}
		}

		return { init: init, load: load, warm: warm, token: token, headers: headers, request: request };
	}

	var defaultClient = create({
		window: root,
		document: typeof document !== "undefined" ? document : {},
		Headers: typeof Headers === "function" ? Headers : undefined,
		now: function () {
			return Date.now();
		},
		fetch: function () {
			return root.fetch.apply(root, arguments);
		},
		setTimeout: function (callback, ms) {
			return root.setTimeout(callback, ms);
		},
		clearTimeout: function (timer) {
			return root.clearTimeout(timer);
		},
	});
	return { create: create, defaultClient: defaultClient, HOSTS: HOSTS };
});
