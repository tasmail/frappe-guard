/*
 * frappe_guard: the browser side of the CAPTCHA check (reCAPTCHA v3) for the public forms.
 *
 *   FrappeGuard.init({ siteKey: "..." });
 *   const response = await FrappeGuard.request("/api/method/frappe.www.contact.send_message", {
 *     action: "contact", method: "POST", body: formData });
 *
 * - The script of the provider is loaded on the first interaction with a protected form (`warm`), not at page load, and not
 *   behind the analytics banner: it is named in the privacy text as anti-abuse (plan G6). It is tried on www.google.com and,
 *   when that does not load, on www.recaptcha.net.
 * - A token is single use and lives two minutes: one is made for every request, never reused.
 * - The token travels in the header `X-Guard-Token`. The request asks for JSON (`Accept` and `X-Requested-With`): Frappe
 *   answers any other client with an HTML error page (status 417) on a refusal.
 * - No failure of the browser side is thrown: when no token can be made the request goes without one and the server decides
 *   (in `monitor` it passes, in `enforce` it answers that the check failed and asks to reload).
 * - The site key is public; put it in the page (`init`), never fetch it from an endpoint (a fetch counts against the edge limit).
 */
(function (root, factory) {
	"use strict";
	var api = factory(root);
	if (typeof module === "object" && module.exports) {
		module.exports = api;
	}
	if (root && typeof root === "object") {
		root.FrappeGuard = api.defaultClient;
		if (root.FRAPPE_GUARD && root.FRAPPE_GUARD.siteKey) {
			api.defaultClient.init(root.FRAPPE_GUARD);
		}
	}
})(typeof window !== "undefined" ? window : globalThis, function (root) {
	"use strict";

	var HOSTS = ["www.google.com", "www.recaptcha.net"];
	var LOAD_TIMEOUT = 8000;
	var TOKEN_TIMEOUT = 10000;
	var EVENTS = ["focusin", "pointerdown", "keydown"];

	function create(env) {
		var win = env.window;
		var doc = env.document;
		var setTimer = env.setTimeout;
		var clearTimer = env.clearTimeout;
		var siteKey = "";
		var hosts = HOSTS.slice();
		var selector = "form[data-guard-action]";
		var loading = null;
		var watching = false;

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

		function loadFrom(host) {
			return new Promise(function (resolve, reject) {
				var script = doc.createElement("script");
				script.async = true;
				script.src = "https://" + host + "/recaptcha/api.js?render=" + encodeURIComponent(siteKey);
				script.onload = function () {
					resolve();
				};
				script.onerror = function () {
					reject(new Error("load " + host));
				};
				(doc.head || doc.documentElement).appendChild(script);
			});
		}

		function load() {
			if (!siteKey) {
				return Promise.reject(new Error("no site key"));
			}
			if (win.grecaptcha && typeof win.grecaptcha.ready === "function") {
				return Promise.resolve();
			}
			if (!loading) {
				var attempt = Promise.reject(new Error("start"));
				hosts.forEach(function (host) {
					attempt = attempt.catch(function () {
						return withTimeout(loadFrom(host), LOAD_TIMEOUT);
					});
				});
				loading = attempt.catch(function (error) {
					loading = null; // a later call tries again
					throw error;
				});
			}
			return loading;
		}

		function token(action) {
			return load()
				.then(function () {
					return withTimeout(
						new Promise(function (resolve, reject) {
							win.grecaptcha.ready(function () {
								win.grecaptcha.execute(siteKey, { action: action }).then(resolve, reject);
							});
						}),
						TOKEN_TIMEOUT
					);
				})
				.then(function (value) {
					return typeof value === "string" ? value : "";
				})
				.catch(function () {
					return ""; // never thrown: the server decides what a request without a token is
				});
		}

		function headers(action, base) {
			return token(action).then(function (value) {
				var result = {};
				Object.keys(base || {}).forEach(function (name) {
					result[name] = base[name];
				});
				result["Accept"] = "application/json";
				result["X-Requested-With"] = "XMLHttpRequest";
				if (value) {
					result["X-Guard-Token"] = value;
				}
				return result;
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

		function interacted(event) {
			var target = event && event.target;
			if (target && typeof target.closest === "function" && target.closest(selector)) {
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
			siteKey = typeof settings.siteKey === "string" ? settings.siteKey : "";
			if (Array.isArray(settings.hosts) && settings.hosts.length) {
				hosts = settings.hosts.slice();
			}
			if (typeof settings.selector === "string") {
				selector = settings.selector;
			}
			loading = null;
			if (siteKey) {
				watch();
			}
		}

		return { init: init, load: load, warm: warm, token: token, headers: headers, request: request };
	}

	var defaultClient = create({
		window: root,
		document: typeof document !== "undefined" ? document : {},
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
