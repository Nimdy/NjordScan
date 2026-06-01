# NjordScan rules

NjordScan ships **121 rules**. Every one is explained in plain English — why it matters and how to fix it — both here and inline when a scan finds it.

> Auto-generated from the knowledge base by `scripts/gen_docs.py`. Don't edit by hand.

Run `njordscan explain <rule-id>` for any of these in your terminal.

## Contents

- [Secrets & credentials](#secrets--credentials) (4)
- [Cross-site scripting (XSS)](#cross-site-scripting-xss) (2)
- [DOM-based XSS](#dom-based-xss) (5)
- [React](#react) (6)
- [Next.js](#nextjs) (10)
- [Vite](#vite) (9)
- [Injection (eval / command / SSTI)](#injection-eval--command--ssti) (5)
- [SQL injection](#sql-injection) (2)
- [NoSQL injection](#nosql-injection) (2)
- [Path traversal](#path-traversal) (2)
- [Server-side request forgery](#server-side-request-forgery) (1)
- [Open redirect](#open-redirect) (1)
- [Cryptography](#cryptography) (9)
- [JSON Web Tokens](#json-web-tokens) (3)
- [Authentication & credentials](#authentication--credentials) (4)
- [Sessions](#sessions) (1)
- [Cookies](#cookies) (5)
- [CORS](#cors) (4)
- [Content-Security-Policy](#content-security-policy) (4)
- [CSRF](#csrf) (3)
- [Security headers (live)](#security-headers-live) (6)
- [Configuration](#configuration) (2)
- [Supply chain](#supply-chain) (2)
- [Dependencies](#dependencies) (2)
- [AI / LLM application security](#ai--llm-application-security) (10)
- [AI endpoints (dynamic)](#ai-endpoints-dynamic) (1)
- [Dynamic scan (DAST)](#dynamic-scan-dast) (3)
- [Hardening & info-leak](#hardening--info-leak) (8)
- [Information leakage](#information-leakage) (5)

## Secrets & credentials

### `secret.aws-access-key` — AWS access key committed to the repository

Severity: 🔴 **critical**  ·  [CWE-798](https://cwe.mitre.org/data/definitions/798.html)  ·  A07:2021-Identification and Authentication Failures

**Why this matters.** An AWS access key pair grants programmatic access to your cloud account. Committed AWS keys are scraped automatically and can be used to spin up servers (huge bills) or read your data within minutes of being pushed.

**How to fix it.** Deactivate and delete this key in the AWS IAM console immediately, then issue a new one and store it in your host's secret manager / environment — never in code.

```js
// load from process.env at runtime; configure via AWS IAM roles where possible
```

### `secret.private-key` — Private key committed to the repository

Severity: 🔴 **critical**  ·  [CWE-798](https://cwe.mitre.org/data/definitions/798.html)  ·  A07:2021-Identification and Authentication Failures

**Why this matters.** A private key (RSA/EC/SSH/PGP) is the master credential for whatever it protects — TLS, signing, server access. If it is in your repo, anyone with the code can impersonate your service or decrypt traffic.

**How to fix it.** Remove the key, rotate it, and store it in a secret manager. Purge it from git history.

### `secret.generic` — Hard-coded secret or credential

Severity: 🟠 **high**  ·  [CWE-798](https://cwe.mitre.org/data/definitions/798.html)  ·  A07:2021-Identification and Authentication Failures

**Why this matters.** A secret committed to your code (API key, password, token) is visible to anyone who can see the repository — and stays in git history forever, even if you delete the line later. Leaked keys are routinely scraped from public repos within minutes and used to run up bills or steal data.

**How to fix it.** Move the value to an environment variable, add the env file to .gitignore, and ROTATE the exposed secret now (assume it is already compromised). On Next.js, only expose values to the browser via the NEXT_PUBLIC_ prefix when you intend them to be public.

```js
const apiKey = process.env.API_KEY; // set in your host's env / .env.local (gitignored)
```

### `secret.public-env-exposure` — Secret exposed to the browser via NEXT_PUBLIC_ / VITE_

Severity: 🟠 **high**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A01:2021-Broken Access Control

**Why this matters.** Variables prefixed with NEXT_PUBLIC_ (Next.js) or VITE_ (Vite) are inlined into the JavaScript bundle that ships to every visitor. Putting a real secret (private API key, DB password) behind that prefix publishes it to the whole world.

**How to fix it.** Only use the public prefix for values that are safe to be public. Keep real secrets unprefixed and read them only in server code (Route Handlers, Server Actions, getServerSideProps).

```js
// server only:
const key = process.env.STRIPE_SECRET_KEY; // NOT NEXT_PUBLIC_
```

## Cross-site scripting (XSS)

### `xss.dangerously-set-inner-html` — Untrusted data rendered with dangerouslySetInnerHTML

Severity: 🟠 **high**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** React normally escapes everything you render, which protects your users automatically. `dangerouslySetInnerHTML` turns that protection OFF and injects raw HTML. If any part of that HTML comes from a user (a form field, a URL, an API response, the database), an attacker can smuggle in a <script> tag and run their own JavaScript in your users' browsers — stealing logins, cookies, or making requests as the victim. This is called cross-site scripting (XSS).

**How to fix it.** Prefer rendering text as `{value}` and let React escape it. If you truly need to render HTML (e.g. rich text from a CMS), sanitize it first with a library like DOMPurify and only then pass the cleaned string to dangerouslySetInnerHTML.

```js
import DOMPurify from 'isomorphic-dompurify';
const clean = DOMPurify.sanitize(userHtml);
return <div dangerouslySetInnerHTML={{ __html: clean }} />;
```

### `xss.inner-html` — User input assigned to innerHTML / outerHTML

Severity: 🟠 **high**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** Assigning a string to `element.innerHTML` parses it as HTML. When the string contains data an attacker controls, they can inject markup that runs JavaScript in your users' browsers (cross-site scripting), letting them hijack accounts or steal data.

**How to fix it.** Use `element.textContent` to insert text safely, or build DOM nodes explicitly. In React, render `{value}` instead of touching innerHTML. If raw HTML is unavoidable, sanitize with DOMPurify first.

```js
element.textContent = userInput; // rendered as text, never executed
```

## DOM-based XSS

### `dom.document-write` — document.write() called with non-literal content

Severity: 🟠 **high**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** `document.write()` / `document.writeln()` drops a string straight into the
page and parses it as HTML. If the string contains anything a user controls,
an attacker can inject a `<script>` (or an `onerror` handler) and run code in
your visitors' browsers — stealing sessions or acting as them (cross-site
scripting). It also blocks rendering and can wipe the whole page if called
after load, so it's discouraged even with trusted input.

**How to fix it.** Stop using `document.write`. Build the page with React/JSX, or create DOM
nodes and set their `textContent` (which is inserted as text, never executed).
If you must inject HTML you do not fully control, sanitize it with DOMPurify
first.

```js
// instead of document.write(userInput)
const el = document.createElement('p');
el.textContent = userInput;   // inserted as text, never run as code
container.appendChild(el);
```

### `dom.insert-adjacent-html` — insertAdjacentHTML() / outerHTML assigned non-literal content

Severity: 🟠 **high**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** `element.insertAdjacentHTML(...)` and assigning to `element.outerHTML` parse
their argument as HTML and splice it into the page. When that argument holds
data an attacker can influence, they can inject markup that runs JavaScript in
your visitors' browsers (cross-site scripting), letting them hijack accounts
or steal data — the same risk as `innerHTML`.

**How to fix it.** Insert text with `textContent`, or build elements with
`document.createElement` and `append`. In React, render `{value}` and let
React escape it. If you genuinely need to insert HTML from an untrusted
source, sanitize it with DOMPurify first.

```js
// instead of el.insertAdjacentHTML('beforeend', userHtml)
const node = document.createElement('span');
node.textContent = userText;
el.append(node);
```

### `dom.jquery-html` — jQuery .html() / .append() called with a non-literal value

Severity: 🟠 **high**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** jQuery's `$(...).html(value)` (and `.append(value)`) treats the value as HTML
and inserts it into the page. If the value contains user-controlled data, an
attacker can smuggle in a `<script>` or event handler that runs JavaScript in
your visitors' browsers (cross-site scripting). jQuery does NOT sanitize for
you.

**How to fix it.** Use `.text(value)` to insert text safely (it escapes everything). If you must
render HTML from an untrusted source, sanitize it with DOMPurify first and
only then pass it to `.html()`.

```js
// instead of $('#out').html(userInput)
$('#out').text(userInput);              // inserted as text, never executed
// or, if HTML is required:
$('#out').html(DOMPurify.sanitize(userHtml));
```

### `dom.location-from-fragment` — Page navigation built from location.hash / location.search (DOM-XSS)

Severity: 🟠 **high**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** The part of the URL after `#` (`location.hash`) and after `?`
(`location.search`) is fully attacker-controlled — anyone can craft a link
with whatever they want there. Feeding it straight into `location`,
`location.href`, or `location.assign(...)` can navigate to a
`javascript:` URL and run code in your visitor's browser, or redirect them to
a phishing site. This is a classic DOM-based cross-site scripting / open
redirect bug.

**How to fix it.** Never trust the hash or query string as a destination. Decode it, then check
it against an allowlist of known paths, or require it to start with a single
`/` (and not `//`, which means another site). Reject anything containing a
scheme like `javascript:`.

```js
const next = decodeURIComponent(location.hash.slice(1));
// only allow same-site paths
if (/^\/(?!\/)/.test(next)) location.assign(next);
```

### `dom.postmessage-no-origin-check` — window message handler does not verify event.origin

Severity: 🟠 **high**  ·  [CWE-345](https://cwe.mitre.org/data/definitions/345.html)  ·  A08:2021-Software and Data Integrity Failures

**Why this matters.** A `message` event listener (`window.addEventListener('message', ...)`) can be
triggered by ANY other page or iframe — including a malicious site that
embeds yours or that you embed. If your handler trusts `event.data` without
first checking `event.origin`, an attacker can send forged messages to
control your app: navigate it, inject content, or steal data the handler has
access to.

**How to fix it.** At the very top of the handler, verify the message came from an origin you
trust and ignore everything else. Compare `event.origin` against an exact
expected origin (not a substring match).

```js
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://trusted.example.com') return; // reject others
  handle(event.data);
});
```

## React

### `react.javascript-url` — Link/script URL set to a "javascript:" string

Severity: 🟠 **high**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** A URL that starts with `javascript:` is not a real address — the browser
runs whatever comes after it as code the moment the link is clicked (or the
element loads). If any part of that URL can be influenced by a user, an
attacker can run their own JavaScript in your visitors' browsers, steal their
login session, or act as them. This is cross-site scripting (XSS). Even a
hard-coded `javascript:` URL is a bad habit that trains the codebase to treat
URLs as a place to put code.

**How to fix it.** Point links and image/script sources at real `http(s):` or relative URLs.
For a button that runs code, use an actual `<button onClick={...}>` instead of
a `javascript:` link. If a URL comes from user data, validate that it begins
with `http://`, `https://`, or `/` before using it.

```js
// a real action, not a javascript: URL
<button type="button" onClick={handleClick}>Run</button>
// for a user-supplied link, allow only safe schemes:
const safe = /^(https?:|\/)/.test(url) ? url : '#';
<a href={safe}>Open</a>
```

### `react.ref-inner-html` — innerHTML assigned via a React ref (ref.current.innerHTML)

Severity: 🟠 **high**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** React escapes everything you render through JSX, which keeps your users safe
automatically. Reaching around React with a ref and writing
`ref.current.innerHTML = value` throws that protection away and parses the
value as HTML. If the value contains user data, an attacker can inject a
`<script>` or event handler and run JavaScript in your visitors' browsers
(cross-site scripting).

**How to fix it.** Render the value as `{value}` in JSX and let React handle it, or set
`ref.current.textContent` to insert it as plain text. If you truly need raw
HTML, sanitize it with DOMPurify and use `dangerouslySetInnerHTML` so the
intent is explicit.

```js
// render through React, which escapes for you
return <div>{value}</div>;
// if you must touch the node directly, use textContent:
ref.current.textContent = value;
```

### `react.unsanitized-markdown` — Rendered Markdown passed to dangerouslySetInnerHTML without sanitizing

Severity: 🟠 **high**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** Markdown-to-HTML libraries like `marked` and `markdown-it` deliberately let
raw HTML pass through by default — `<script>alert(1)</script>` in the Markdown
becomes a real script tag in the output. If you then hand that HTML to
`dangerouslySetInnerHTML`, an attacker who can write Markdown (a comment, a
bio, a wiki page) can run JavaScript in your visitors' browsers (cross-site
scripting).

**How to fix it.** Sanitize the generated HTML with DOMPurify before rendering it, every time.
Don't rely on the Markdown library's own options alone — sanitize the final
HTML string.

```js
import { marked } from 'marked';
import DOMPurify from 'isomorphic-dompurify';
const html = DOMPurify.sanitize(marked.parse(userMarkdown));
return <div dangerouslySetInnerHTML={{ __html: html }} />;
```

### `react.href-user-value` — Link href set directly from a user-controlled value

Severity: 🟡 **medium**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** Putting a raw user value straight into an `href` (or image `src`) is risky:
if the value is something like `javascript:stealCookies()`, clicking the link
runs that code in your visitor's browser (cross-site scripting). It can also
be used to send users to a phishing page from a link that looks like it lives
on your trusted site. "User-controlled" means it came from a form field, the
URL, an API response, or your database.

**How to fix it.** Validate the value before using it as a URL. Allow only links that start with
`http://`, `https://`, or `/` (a path on your own site). Reject `javascript:`,
`data:`, and `vbscript:` schemes. The `URL` constructor is a handy way to
parse and check the protocol.

```js
function safeHref(value) {
  try {
    const u = new URL(value, window.location.origin);
    return ['http:', 'https:'].includes(u.protocol) ? u.href : '#';
  } catch { return '#'; }
}
<a href={safeHref(userUrl)}>Visit</a>
```

### `react.token-in-web-storage` — Auth token or secret stored in localStorage / sessionStorage

Severity: 🟡 **medium**  ·  [CWE-922](https://cwe.mitre.org/data/definitions/922.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** `localStorage` and `sessionStorage` are readable by any JavaScript running on
your page. If your site ever has a cross-site scripting (XSS) bug — even in a
third-party script you include — the attacker's code can read a token or
secret you stored there and use it to impersonate the user. Unlike a cookie,
web storage cannot be marked HttpOnly, so there is no way to hide it from
JavaScript.

**How to fix it.** Keep session tokens in a cookie set by the server with the `HttpOnly`,
`Secure`, and `SameSite` flags, so page JavaScript can never read them. If you
must hold something client-side, keep it in memory for the session and never
persist long-lived credentials in web storage.

```js
// server response sets the cookie; the browser sends it automatically:
// Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Path=/
// client code never touches the token at all
```

### `react.unsafe-target-blank` — Link opens with target="_blank" but no rel="noopener"

Severity: 🔵 **low**  ·  [CWE-1022](https://cwe.mitre.org/data/definitions/1022.html)  ·  A01:2021-Broken Access Control

**Why this matters.** When a link opens a new tab with target="_blank", the page it opens gets a reference back to your page via window.opener. A malicious destination can use that to silently redirect your tab to a phishing page ("tabnabbing"). Modern browsers mitigate this, but older ones and webviews do not.

**How to fix it.** Add rel="noopener noreferrer" to any link that uses target="_blank".

```js
<a href={url} target="_blank" rel="noopener noreferrer">Open</a>
```

## Next.js

### `nextjs.api-env-exposure` — API route sends process.env (or its config object) back to the browser

Severity: 🟠 **high**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A01:2021-Broken Access Control

**Why this matters.** Code inside an API route (`pages/api/*`) or a Route Handler (`app/**/route.ts`)
runs on the SERVER, so it can see every secret in process.env — database
passwords, Stripe keys, JWT signing secrets, everything. The moment you put
`process.env` (or an object built from it) into the JSON you send back, you
hand all of those secrets to whoever calls the endpoint. Anyone can open the
URL in a browser and read them; there is no login wall on the response body.
This is one of the most common ways a hobby project leaks its entire
credential set in a single fetch.

**How to fix it.** Never serialise process.env to the client. Return only the specific,
non-secret values the page actually needs, and pick them out by name. If the
value is meant to be public, expose it the official way with a NEXT_PUBLIC_
prefix and read it in the component instead of round-tripping it through an
API route.

```js
// app/api/config/route.ts
export async function GET() {
  // hand-pick safe values only — never the whole env
  return Response.json({ region: process.env.AWS_REGION });
}
```

### `nextjs.api-wildcard-cors` — API route allows any website to read its responses (Access-Control-Allow-Origin *)

Severity: 🟠 **high**  ·  [CWE-942](https://cwe.mitre.org/data/definitions/942.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Setting `Access-Control-Allow-Origin: *` tells the browser that ANY website
is allowed to make requests to this endpoint and read the response. For a
public, no-login API that is fine — but if this route returns user data or
relies on cookies/session, a malicious site your user visits can quietly call
your API in their browser and steal whatever it returns. The wildcard removes
the browser's main cross-site protection.

**How to fix it.** Echo back only origins you trust instead of "*". Keep a small allowlist of
your own domains and set Access-Control-Allow-Origin to the request's origin
only when it is in that list. Never combine "*" with
Access-Control-Allow-Credentials: true — browsers reject it, and it would be
dangerous anyway.

```js
const ALLOWED = new Set(['https://app.example.com']);
const origin = req.headers.origin;
if (ALLOWED.has(origin)) res.setHeader('Access-Control-Allow-Origin', origin);
```

### `nextjs.props-secret-leak` — getServerSideProps / getStaticProps leaks a server secret into page props

Severity: 🟠 **high**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A01:2021-Broken Access Control

**Why this matters.** getServerSideProps and getStaticProps run on the server, but whatever you put
in the `props` object is serialised and SHIPPED TO THE BROWSER — it ends up in
the page's HTML and in the client-side JS bundle, visible to anyone who opens
"View Source" or the Network tab. Reading a private value like
`process.env.STRIPE_SECRET_KEY` on the server and then placing it into props
publishes that secret to every visitor. The env var has no NEXT_PUBLIC_
prefix precisely because it was never meant to leave the server.

**How to fix it.** Keep secrets on the server. Use them inside getServerSideProps to do the work
(call the API, query the DB) and return only the RESULT to props — never the
key itself. If a value is genuinely safe to be public, give it a NEXT_PUBLIC_
prefix and read it directly in the component.

```js
export async function getServerSideProps() {
  const data = await fetchWithSecret(process.env.STRIPE_SECRET_KEY); // used, not exposed
  return { props: { data } }; // only the safe result crosses to the browser
}
```

### `nextjs.unsafe-allowed-dev-origins` — Server Actions accept requests from any origin (allowedOrigins includes "*")

Severity: 🟠 **high**  ·  [CWE-352](https://cwe.mitre.org/data/definitions/352.html)  ·  A01:2021-Broken Access Control

**Why this matters.** Next.js protects Server Actions by checking that the request came from your
own site, which stops other websites from triggering them in a logged-in
user's browser (a cross-site request forgery, or CSRF). Adding "*" to
`experimental.serverActions.allowedOrigins` switches that check off for every
origin — so any malicious page a logged-in user visits can fire your Server
Actions as them, changing data or making purchases without their knowledge.

**How to fix it.** List only the exact origins that should be allowed to call your Server Actions
(for example a known proxy or a staging host). Never use "*". If you only run
on your own domain, you usually don't need allowedOrigins at all.

```js
// next.config.js
module.exports = {
  experimental: { serverActions: { allowedOrigins: ['app.example.com'] } },
};
```

### `nextjs.dangerous-config` — Insecure Next.js configuration

Severity: 🟡 **medium**  ·  [CWE-16](https://cwe.mitre.org/data/definitions/16.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Some next.config options loosen safety in ways that are easy to ship by accident — e.g. ignoring build/type errors hides real bugs, and overly broad image `domains`/`remotePatterns` let attackers proxy arbitrary content through your domain.

**How to fix it.** Don't ignore type/lint errors in production builds, and scope image and rewrite patterns to hosts you control.

```js
images: { remotePatterns: [{ protocol: 'https', hostname: 'assets.example.com' }] }
```

### `nextjs.error-stack-leak` — API route / Route Handler sends an error stack trace to the client

Severity: 🟡 **medium**  ·  [CWE-209](https://cwe.mitre.org/data/definitions/209.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** A stack trace (err.stack, or the whole Error object) is a map of your app's
insides: file paths, function names, line numbers, library versions, and
sometimes the exact SQL or the secret that was being used when it crashed.
Returning it in an API response hands attackers a free reconnaissance report
and can leak sensitive values directly. It is also a tell that error handling
was never thought through, which often means other bugs are reachable too.

**How to fix it.** Send the client a short, generic message and a stable error id. Log the full
error (stack included) on the SERVER only, where you can actually read it.
Never put err.stack — or the raw error — into the HTTP response body.

```js
try { /* ... */ } catch (err) {
  console.error(err);                       // full detail stays on the server
  res.status(500).json({ error: 'Something went wrong' }); // generic for the client
}
```

### `nextjs.image-dangerously-allow-svg` — Next.js Image is configured to serve untrusted SVGs (dangerouslyAllowSVG)

Severity: 🟡 **medium**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** SVG files are not just pictures — they can contain <script> and event
handlers, so a browser may run JavaScript when it displays one. The Next.js
image optimizer refuses to serve SVGs by default for exactly this reason.
Turning on `images.dangerouslyAllowSVG: true` re-enables them, and if any of
those SVGs come from users or a remote host you don't fully control, an
attacker can upload one that runs code in your visitors' browsers
(cross-site scripting) — stealing logins and session cookies.

**How to fix it.** Leave dangerouslyAllowSVG off unless you absolutely must serve SVGs. If you
do, also set a strict `contentSecurityPolicy` for images
(e.g. "default-src 'self'; script-src 'none'; sandbox") and only allow SVGs
from hosts you fully trust — never user uploads.

```js
// next.config.js — prefer leaving SVG optimization off
module.exports = {
  images: {
    dangerouslyAllowSVG: false,
    // if you truly must: contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;"
  },
};
```

### `nextjs.middleware-open-redirect` — Middleware redirects/rewrites to a destination taken from the request

Severity: 🟡 **medium**  ·  [CWE-601](https://cwe.mitre.org/data/definitions/601.html)  ·  A01:2021-Broken Access Control

**Why this matters.** Next.js middleware runs on every matching request and can send the user
somewhere else with NextResponse.redirect() or rewrite(). If the destination
is built from something the user controls — a `?next=` query parameter, a
header, a cookie — an attacker can craft a link that starts on your trusted
domain but bounces the visitor to a look-alike phishing site. Because the link
really is on your domain, users (and email filters) trust it.

**How to fix it.** Only redirect to paths you control. Treat any user-supplied destination as a
string to validate, not a URL to trust: require it to start with a single "/"
(not "//" or "https://"), or check it against an allowlist before redirecting.

```js
const next = req.nextUrl.searchParams.get('next') ?? '/';
const safe = next.startsWith('/') && !next.startsWith('//') ? next : '/';
return NextResponse.redirect(new URL(safe, req.url));
```

### `nextjs.powered-by-header` — X-Powered-By header not disabled (poweredByHeader left on)

Severity: 🔵 **low**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** By default Next.js adds an `X-Powered-By: Next.js` header to every response.
On its own this is harmless, but it advertises exactly what you are running.
Attackers and automated scanners use that to immediately try exploits known
to affect that framework, skipping the guesswork. Removing the banner is free
defence-in-depth: it makes your app a slightly quieter target.

**How to fix it.** Turn the header off in next.config.js by setting `poweredByHeader: false`.
This is a one-line change with no downside.

```js
// next.config.js
module.exports = { poweredByHeader: false };
```

### `nextjs.source-maps-exposed` — Production browser source maps are published (productionBrowserSourceMaps)

Severity: 🔵 **low**  ·  [CWE-540](https://cwe.mitre.org/data/definitions/540.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Source maps re-create your original, un-minified source code from the shipped
bundle. Setting `productionBrowserSourceMaps: true` uploads those maps
alongside your public site, so anyone can download them and read your real
code — including comments, internal endpoint names, and the occasional
hard-coded value you forgot was there. It makes finding weaknesses in your app
much easier for an attacker.

**How to fix it.** Leave production browser source maps off (the default). If you need maps for
error monitoring, upload them privately to your error tracker (e.g. Sentry)
instead of serving them to the public.

```js
// next.config.js — omit the flag, or set it false
module.exports = { productionBrowserSourceMaps: false };
```

## Vite

### `vite.define-inlines-secret` — Vite `define` inlines a secret or process.env into the bundle

Severity: 🟠 **high**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** The `define` option in vite.config performs a raw find-and-replace at build
time: whatever value you give it is hard-coded into the public JavaScript
bundle. Feeding a secret token, or a whole `process.env` reference that
resolves to a secret, into `define` publishes that value to every visitor —
they can read it straight out of the shipped JavaScript.

**How to fix it.** Never put secrets in `define`. If you need a build-time constant in the
browser, make sure it is non-sensitive. For anything secret, keep it on the
server and expose only a public API endpoint to the browser. Note that
`define: { 'process.env': process.env }` is especially dangerous because it
can leak every environment variable on the build machine.

```js
// vite.config.ts — only inline NON-secret, public constants
export default defineConfig({
  define: { __APP_VERSION__: JSON.stringify(pkg.version) },
});
```

### `vite.fs-allow-too-broad` — Vite `server.fs.allow` opened to the whole filesystem

Severity: 🟠 **high**  ·  [CWE-22](https://cwe.mitre.org/data/definitions/22.html)  ·  A01:2021-Broken Access Control

**Why this matters.** Vite's dev server only serves files inside an allowed list of directories so
that a crafted URL can't reach the rest of your disk. Adding `'/'` or `'..'`
to `server.fs.allow` removes that fence: a request like
`/@fs/etc/passwd` (or one that climbs out with `..`) can now read arbitrary
files on your machine — including `.env` files, SSH keys, and source outside
the project. This is a path-traversal / arbitrary-file-read hole.

**How to fix it.** Remove `'/'` and `'..'` from `server.fs.allow`. Let Vite use its safe
defaults, or list only the specific extra directories you actually need
(for example a shared packages folder in a monorepo).

```js
// vite.config.ts — allow only a specific sibling package dir
export default defineConfig({
  server: { fs: { allow: ['..\/shared-ui'] } },
});
```

### `vite.import-meta-env-secret` — Secret read from import.meta.env in client code

Severity: 🟠 **high**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A01:2021-Broken Access Control

**Why this matters.** Vite replaces every `import.meta.env.SOMETHING` you write with the literal
value at build time and ships it inside the JavaScript bundle that every
visitor downloads. Vite only ever exposes variables whose name starts with
`VITE_`, so reading a secret-looking var like `import.meta.env.VITE_API_SECRET`
(or a Stripe/AWS/DB token) means you are publishing that secret to the whole
internet — anyone can open the browser dev tools and read it.

**How to fix it.** Real secrets must never reach the browser bundle. Keep secret keys on a
server you control (an API route, a serverless function, your own backend)
and have the browser call that server instead. In Vite, only put values
behind the `VITE_` prefix that are genuinely safe to be public (a public
site URL, a publishable/anon key that is designed to be shared).

```js
// browser code calls YOUR server, which holds the secret:
const res = await fetch('/api/charge', { method: 'POST', body });
// server (not bundled) reads the real secret from process.env.STRIPE_SECRET_KEY
```

### `vite.vite-prefixed-secret` — Secret-looking variable exposed with the VITE_ prefix

Severity: 🟠 **high**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A01:2021-Broken Access Control

**Why this matters.** Any environment variable whose name starts with `VITE_` is inlined into the
public JavaScript bundle and downloaded by every visitor. Defining something
like `VITE_SECRET_KEY`, `VITE_DB_PASSWORD`, or `VITE_STRIPE_SECRET_KEY` in a
`.env` file or in code means that secret is shipped to the browser in
plain text — it is effectively published to the world.

**How to fix it.** Drop the `VITE_` prefix from anything secret so Vite stops exposing it, and
read it only in server-side code. ROTATE any secret that already shipped this
way (assume it is compromised). Reserve `VITE_` for values that are safe to be
public.

```js
# .env  — secret stays server-side (NO VITE_ prefix), public URL may be exposed
STRIPE_SECRET_KEY=sk_live_xxx        # server only
VITE_PUBLIC_API_URL=https://api.example.com   # safe to ship to the browser
```

### `vite.dev-server-cors-wildcard` — Vite dev server CORS opened to any origin

Severity: 🟡 **medium**  ·  [CWE-942](https://cwe.mitre.org/data/definitions/942.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** `server.cors: true` tells the Vite dev server to send an
`Access-Control-Allow-Origin: *` header, which lets any website your browser
visits make requests to your dev server and read the responses. A malicious
page you happen to open in another tab could then probe your dev server,
read your modules, or call dev-only API proxies that sit behind it.

**How to fix it.** Don't enable wildcard CORS on the dev server. If a specific origin needs
access during development, pass an explicit `origin` allowlist to `cors`
instead of `true`.

```js
// vite.config.ts — allow one trusted origin instead of "*"
export default defineConfig({
  server: { cors: { origin: 'http://localhost:3000' } },
});
```

### `vite.dev-server-host-exposed` — Vite dev server bound to all network interfaces

Severity: 🟡 **medium**  ·  [CWE-668](https://cwe.mitre.org/data/definitions/668.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Setting `server.host` to `true` or `'0.0.0.0'` makes the Vite dev server
listen on every network interface, not just your own machine. On a shared
Wi-Fi, an office network, or a coffee shop, anyone on the same network can
reach your dev server — read your source, hit your unprotected dev API
proxies, and sometimes pull local files. The dev server has none of the
hardening of a production deployment.

**How to fix it.** Leave `server.host` unset (Vite defaults to localhost-only). If you truly
need to test from a phone on the same network, enable it temporarily with
the `--host` CLI flag instead of committing it, and never expose the dev
server to an untrusted network.

```js
// vite.config.ts — dev server stays on localhost
export default defineConfig({ server: { /* host left unset */ } });
```

### `vite.fs-strict-disabled` — Vite `server.fs.strict` disabled

Severity: 🟡 **medium**  ·  [CWE-22](https://cwe.mitre.org/data/definitions/22.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** `server.fs.strict` is the guard that stops the dev server from serving files
outside your project root. Setting `server.fs.strict: false` turns that guard
off, so a crafted URL can read files anywhere on your disk — `.env` files,
keys, and other projects — through the dev server. It re-opens the same
arbitrary-file-read risk as a wide-open `fs.allow`.

**How to fix it.** Remove `fs: { strict: false }` — strict mode is on by default and should stay
on. If a specific outside directory is genuinely needed, add it to
`server.fs.allow` instead of disabling strict mode entirely.

```js
// vite.config.ts — keep strict mode (the default) on
export default defineConfig({ server: { fs: { strict: true } } });
```

### `vite.proxy-target-insecure` — Vite dev proxy with TLS verification disabled

Severity: 🟡 **medium**  ·  [CWE-295](https://cwe.mitre.org/data/definitions/295.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** A Vite `server.proxy` entry with `secure: false` tells the dev proxy to
accept the upstream server's TLS certificate without checking it. That means
anyone on the network between you and the upstream can impersonate it and
read or modify the traffic flowing through the proxy (a man-in-the-middle).
Developers often copy this setting into shared config where it can mask a
real certificate problem.

**How to fix it.** Remove `secure: false`. If you are proxying to a development server with a
self-signed certificate, trust that specific certificate locally instead of
turning verification off for everything.

```js
// vite.config.ts — keep TLS verification on for the proxy
export default defineConfig({
  server: { proxy: { '/api': { target: 'https://api.example.com', changeOrigin: true } } },
});
```

### `vite.prod-sourcemap` — Source maps enabled for the production build

Severity: 🔵 **low**  ·  [CWE-540](https://cwe.mitre.org/data/definitions/540.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** `build.sourcemap: true` ships `.map` files alongside your bundle, which let
anyone reconstruct your original, un-minified source code in the browser dev
tools. That makes it easy for an attacker to read your client logic, spot
hidden endpoints, and notice any secret or comment you assumed was hidden by
minification. It is not a critical hole on its own, but it removes a layer of
obscurity and can leak information.

**How to fix it.** Don't enable source maps for production. If you need them for error
monitoring, generate "hidden" source maps and upload them privately to your
error tracker instead of serving them to users (`build.sourcemap: 'hidden'`).

```js
// vite.config.ts — no public source maps in prod
export default defineConfig({ build: { sourcemap: false } });
```

## Injection (eval / command / SSTI)

### `injection.command` — Shell command built from untrusted input

Severity: 🔴 **critical**  ·  [CWE-78](https://cwe.mitre.org/data/definitions/78.html)  ·  A03:2021-Injection

**Why this matters.** Building a shell command by concatenating user input lets an attacker add their own commands (e.g. `; rm -rf /`). Functions like `exec` and `execSync` run through a shell, so injected text is executed on your server.

**How to fix it.** Use `execFile`/`spawn` with an arguments array (no shell), validate inputs against an allowlist, and never interpolate user data into a command string.

```js
execFile('convert', [inputPath, outputPath]); // args are not parsed by a shell
```

### `injection.eval` — eval() / Function() called on dynamic input

Severity: 🔴 **critical**  ·  [CWE-95](https://cwe.mitre.org/data/definitions/95.html)  ·  A03:2021-Injection

**Why this matters.** `eval()` (and `new Function(...)`) runs whatever string you give it as live code. If any part of that string can be influenced by a user, an attacker can execute arbitrary JavaScript — on the server this can mean full takeover of your app and its data.

**How to fix it.** There is almost always a safer alternative. Parse data with `JSON.parse`, look up behavior in an object/map, or use a real expression library. Never pass user-influenced strings to eval/Function.

```js
// instead of eval(userInput)
const actions = { start, stop };
actions[userChoice]?.();
```

### `injection.template-ssti` — User input compiled into a server-side template

Severity: 🔴 **critical**  ·  [CWE-94](https://cwe.mitre.org/data/definitions/94.html)  ·  A03:2021-Injection

**Why this matters.** Template engines like Handlebars, EJS, Pug, and Nunjucks turn a template
STRING into executable code. If you build that template string out of user
input (instead of passing the user input as data to a fixed template),
an attacker can inject template syntax that runs JavaScript on your server —
often leading to full server takeover. This is server-side template
injection (SSTI).

**How to fix it.** Keep templates as fixed files or constant strings, and pass user input only
as DATA in the context object — never concatenate user input into the
template source. Leave the engine's auto-escaping on.

```js
// instead of: ejs.render('Hello ' + req.query.name)
ejs.render('Hello <%= name %>', { name: req.query.name }); // name is data, escaped
```

### `injection.prototype-pollution-merge` — Untrusted object merged into a target (prototype pollution)

Severity: 🟠 **high**  ·  [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)  ·  A08:2021-Software and Data Integrity Failures

**Why this matters.** Deep-merging or assigning an attacker-controlled object (like `req.body`)
into another object lets the attacker smuggle a special `__proto__` key.
That key doesn't just set one object — it changes the prototype that EVERY
object in your app inherits from, letting an attacker plant default values
everywhere. Depending on your code this can flip security flags
(`isAdmin`), break the app, or even lead to code execution.

**How to fix it.** Don't merge raw request data into objects. Validate and pick the exact keys
you expect with a schema (Zod), or use a merge utility that is hardened
against prototype pollution and reject keys named `__proto__`,
`constructor`, or `prototype`.

```js
// instead of: Object.assign(config, req.body) or _.merge({}, req.body)
const { theme, locale } = req.body;            // pick only known keys
const config = { ...defaults, theme, locale }; // __proto__ can't sneak in
```

### `injection.prototype-pollution-bracket` — Object key taken from user input written with bracket assignment

Severity: 🟡 **medium**  ·  [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)  ·  A08:2021-Software and Data Integrity Failures

**Why this matters.** Writing `obj[userKey] = value` where `userKey` comes from the user is risky:
if the user sends the key `__proto__` (or `constructor`), the assignment can
reach into the prototype shared by every object in your program instead of
your own object. This "prototype pollution" can quietly turn on admin flags,
corrupt data, or crash the app.

**How to fix it.** Reject the dangerous keys before assigning (`__proto__`, `constructor`,
`prototype`), or store user-keyed data in a `Map`, which never touches the
prototype chain. Validating the key against an allowlist is best.

```js
const DANGEROUS = new Set(['__proto__', 'constructor', 'prototype']);
if (DANGEROUS.has(userKey)) throw new Error('invalid key');
obj[userKey] = value;
// or: const store = new Map(); store.set(userKey, value);
```

## SQL injection

### `sqli.string-concatenation` — SQL query built by glueing strings together

Severity: 🔴 **critical**  ·  [CWE-89](https://cwe.mitre.org/data/definitions/89.html)  ·  A03:2021-Injection

**Why this matters.** When you build a SQL query by adding (`+`) a variable into the query
string, the database can't tell your query apart from data the user typed.
If that variable came from a form, a URL, or an API request, an attacker can
type SQL of their own — for example ending your query early and adding
`OR 1=1 --` to dump every row, or `; DROP TABLE users; --` to delete data.
This is the classic "SQL injection" bug, and it can leak or destroy your
entire database.

**How to fix it.** Never put user data directly into the query text. Use a parameterized query
(also called a "prepared statement"): write `?` or `$1` placeholders and
pass the values as a separate array. The database driver then treats them as
pure data that can never become SQL. If you use an ORM (Prisma, Drizzle,
Sequelize), use its query builder instead of raw string SQL.

```js
// instead of: db.query('SELECT * FROM users WHERE id = ' + id)
db.query('SELECT * FROM users WHERE id = ?', [id]); // value is sent separately
```

### `sqli.template-literal` — SQL query built with a template literal containing a variable

Severity: 🔴 **critical**  ·  [CWE-89](https://cwe.mitre.org/data/definitions/89.html)  ·  A03:2021-Injection

**Why this matters.** A backtick template literal like `` `SELECT * FROM users WHERE name='${name}'` ``
drops the variable straight into the query text. If `name` comes from a user,
they can break out of the quotes and run their own SQL — reading other
users' data, bypassing a login, or deleting tables. This is SQL injection,
just hidden behind nicer-looking string syntax.

**How to fix it.** Use a parameterized query with placeholders and a values array instead of
interpolating into the string. Note: a tagged template from a library that
escapes for you (e.g. the `sql` tag from `postgres`/`@vercel/postgres`) is
safe — the danger is a plain string passed to `.query()`/`.execute()`.

```js
// safe tagged template (library escapes ${name} for you):
await sql`SELECT * FROM users WHERE name = ${name}`;
// or classic placeholder:
db.query('SELECT * FROM users WHERE name = ?', [name]);
```

## NoSQL injection

### `nosqli.where-operator` — MongoDB $where clause runs server-side JavaScript

Severity: 🔴 **critical**  ·  [CWE-943](https://cwe.mitre.org/data/definitions/943.html)  ·  A03:2021-Injection

**Why this matters.** A MongoDB query that uses `$where` runs a string of JavaScript inside your
database to decide which documents match. If any part of that string is
built from user input, an attacker can inject their own JavaScript — slowing
the database to a crawl (denial of service) or, depending on setup, reading
data they should never see. `$where` is slow and dangerous even with trusted
input.

**How to fix it.** Replace `$where` with normal query operators (`$eq`, `$gt`, `$in`, `$regex`
with care). Almost anything you can express in `$where` has a safe operator
equivalent that the database can also index.

```js
// instead of: collection.find({ $where: `this.age > ${age}` })
collection.find({ age: { $gt: Number(age) } });
```

### `nosqli.untrusted-query-filter` — Request body or query passed straight into a database filter

Severity: 🟠 **high**  ·  [CWE-943](https://cwe.mitre.org/data/definitions/943.html)  ·  A03:2021-Injection

**Why this matters.** Passing `req.body` or `req.query` directly as a MongoDB filter looks
harmless, but the user controls the SHAPE of that object, not just the
values. By sending `{"password": {"$ne": null}}` they turn your equality
check into "any password that isn't null", letting them log in without
knowing the password or pull back records they shouldn't. This is NoSQL
injection through operator smuggling.

**How to fix it.** Pull out the specific fields you expect and coerce them to plain values
(e.g. `String(req.body.email)`), or validate the input with a schema
(Zod, Joi) before it reaches the query. Never spread an untrusted object
into a filter. Many setups also disable operator parsing with
`express-mongo-sanitize`.

```js
// instead of: User.findOne(req.body)
const email = String(req.body.email);
const password = String(req.body.password);
const user = await User.findOne({ email }); // then verify the hash
```

## Path traversal

### `path-traversal.fs-read` — File read with a path built from user input

Severity: 🟠 **high**  ·  [CWE-22](https://cwe.mitre.org/data/definitions/22.html)  ·  A01:2021-Broken Access Control

**Why this matters.** When you open a file using a name or path that came from the user, they can
send `../../../../etc/passwd` (or `..\..\` on Windows) to "walk up" out of
your intended folder and read files anywhere your server can — config files,
other users' uploads, even secrets and SSH keys. This is called path (or
"directory") traversal.

**How to fix it.** Resolve the final path and confirm it still lives inside the directory you
intended before reading it. Strip path separators from the user value, or
better, look the file up by an id in a database and never let the raw name
touch the filesystem.

```js
const base = path.resolve('./uploads');
const target = path.resolve(base, path.basename(userName)); // basename drops ../
if (!target.startsWith(base + path.sep)) throw new Error('invalid path');
fs.readFileSync(target);
```

### `path-traversal.send-file` — File served back to the user with a request-controlled path

Severity: 🟠 **high**  ·  [CWE-22](https://cwe.mitre.org/data/definitions/22.html)  ·  A01:2021-Broken Access Control

**Why this matters.** `res.sendFile()` and `res.download()` stream a file straight to the
visitor's browser. If the path is built from the request (a query string, a
URL parameter), an attacker can request `../../config/.env` and have your
server hand them files outside the public folder — leaking source code,
credentials, or other users' data. This is path traversal in a download
endpoint.

**How to fix it.** Pass an absolute `root` option and a sanitized filename to sendFile, and
reject any name containing `..` or a slash. Express's sendFile blocks `..`
only when you supply the `root` option, so always include it.

```js
const name = path.basename(req.params.name); // removes any ../ segments
res.sendFile(name, { root: path.resolve('./public/files') });
```

## Server-side request forgery

### `ssrf.fetch` — Server-side fetch to a user-controlled URL (SSRF)

Severity: 🟠 **high**  ·  [CWE-918](https://cwe.mitre.org/data/definitions/918.html)  ·  A10:2021-SSRF

**Why this matters.** When your server fetches a URL that the user chose, an attacker can point it at internal services or cloud metadata endpoints (e.g. http://169.254.169.254) that are normally unreachable from the outside — leaking credentials or letting them reach your private network. This is server-side request forgery (SSRF).

**How to fix it.** Validate the destination against an allowlist of hosts you trust, reject private/loopback/link-local IP ranges, and disable automatic redirect-following for user-supplied URLs.

```js
const url = new URL(userUrl);
if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error('host not allowed');
```

## Open redirect

### `open-redirect` — Redirect to a user-controlled URL

Severity: 🟡 **medium**  ·  [CWE-601](https://cwe.mitre.org/data/definitions/601.html)  ·  A01:2021-Broken Access Control

**Why this matters.** Redirecting to a URL taken straight from user input lets attackers send your users to a look-alike phishing site through a link that starts on your trusted domain.

**How to fix it.** Only redirect to relative paths you control, or check the target against an allowlist.

```js
if (!target.startsWith('/')) target = '/'; res.redirect(target);
```

## Cryptography

### `crypto.deprecated-cipher` — Deprecated createCipher / createDecipher used (no IV)

Severity: 🟠 **high**  ·  [CWE-327](https://cwe.mitre.org/data/definitions/327.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** Node's crypto.createCipher() and crypto.createDecipher() are deprecated and
unsafe. They derive the encryption key from your password with a weak,
one-iteration method and — critically — they use NO initialization vector
(IV). An IV is a random value that makes the same plaintext encrypt to a
different ciphertext each time. Without it, encrypting the same data twice
produces identical output, which leaks patterns and lets an attacker learn
things about the data (or detect when two encrypted values are equal). The
"iv" variant, createCipheriv(), exists precisely to fix this.

**How to fix it.** Switch to crypto.createCipheriv() / crypto.createDecipheriv() with a strong
algorithm (aes-256-gcm), a properly derived key, and a fresh random IV per
message. Store/transmit the IV alongside the ciphertext (it is not secret).

```js
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const enc = Buffer.concat([cipher.update(data), cipher.final()]);
const tag = cipher.getAuthTag(); // store iv + tag + enc together
```

### `crypto.hardcoded-cookie-secret` — Cookie / session signing secret hard-coded

Severity: 🟠 **high**  ·  [CWE-798](https://cwe.mitre.org/data/definitions/798.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** Session middleware (express-session, cookie-session, cookie-signature,
iron-session, fastify cookie/secret) signs or encrypts the cookie it gives a
logged-in user so the user can't tamper with it. That protection rests
entirely on the signing secret. When the secret is a literal string in your
code, anyone who reads the repo can forge or modify a valid session cookie —
flipping their own session to another user's, or to an admin — and take over
accounts without a password.

**How to fix it.** Read the secret from an environment variable and make it a long random value.
Rotate it if it was ever committed (which logs everyone out). Provide an array
of secrets if your library supports key rotation.

```js
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
```

### `crypto.hardcoded-key` — Hard-coded encryption key in source code

Severity: 🟠 **high**  ·  [CWE-321](https://cwe.mitre.org/data/definitions/321.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** The whole point of encryption is that only someone with the secret key can
read the data. When that key is written as a literal in your code — a string
or a byte buffer passed straight into createCipheriv / createSecretKey — it
lives in your repository and your git history forever, visible to everyone
with access (and frequently to the public, in shipped bundles). Anyone who
has the key can decrypt every value you ever encrypted with it. A hard-coded
key turns "encrypted" data back into plaintext for the attacker.

**How to fix it.** Generate a random key once, store it in a secrets manager or an environment
variable, and read it at runtime. Never commit key material. If this key was
ever committed, rotate it and re-encrypt the affected data.

```js
const key = Buffer.from(process.env.ENCRYPTION_KEY, 'base64'); // 32 random bytes, from env
const cipher = crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12));
```

### `crypto.insecure-transport-auth` — Auth / token / OAuth endpoint requested over plain http://

Severity: 🟠 **high**  ·  [CWE-319](https://cwe.mitre.org/data/definitions/319.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** A request to a login, token, or OAuth URL that starts with http:// (not
https://) travels across the network unencrypted. Anyone in between — someone
on the same coffee-shop Wi-Fi, a malicious router, your ISP — can read it as
plain text. For an auth endpoint that means they can capture passwords,
one-time codes, OAuth secrets, or the access tokens that are sent back, and
then log in as your user. HTTPS encrypts the connection so eavesdroppers see
only scrambled bytes.

**How to fix it.** Always use https:// for any URL that carries credentials or tokens. Update
the literal URL, and prefer loading base URLs from configuration so a stray
http:// can't sneak back in.

```js
const res = await fetch('https://auth.example.com/oauth/token', { method: 'POST', body });
```

### `crypto.weak-cipher` — Weak or legacy cipher (DES, RC4, 3DES, or AES-ECB)

Severity: 🟠 **high**  ·  [CWE-327](https://cwe.mitre.org/data/definitions/327.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** Some encryption algorithms are simply broken or too weak to use anymore. DES
and RC4 can be cracked with ordinary hardware; 3DES is slow and considered
legacy. The ECB *mode* (as in aes-256-ecb) is dangerous even with a strong
cipher: it encrypts each block independently, so identical chunks of input
produce identical chunks of output. That preserves visible patterns in the
data — the famous "ECB penguin" image stays recognisable after encryption.
Relying on any of these gives you a false sense of safety; the data is not
actually protected.

**How to fix it.** Use AES with an authenticated mode: aes-256-gcm (preferred) or aes-256-cbc
with a separate integrity check. Never use DES, RC4, or any *-ecb mode.

```js
const cipher = crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12));
```

### `crypto.bcrypt-low-rounds` — bcrypt cost factor too low (< 10 rounds)

Severity: 🟡 **medium**  ·  [CWE-916](https://cwe.mitre.org/data/definitions/916.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** bcrypt deliberately makes password hashing SLOW so that if your database
leaks, an attacker can only try a limited number of guesses per second. How
slow is controlled by the "cost" / "rounds" number — each step up doubles the
work. Setting it too low (under 10) makes hashing cheap again, so a stolen
password database can be cracked far faster. The whole point of bcrypt is the
cost factor; a low one throws that protection away.

**How to fix it.** Use a cost factor of at least 10 (12 is a common, comfortable default on
modern hardware). Pick the highest value your login latency budget allows and
revisit it as hardware gets faster.

```js
const hash = await bcrypt.hash(password, 12); // cost factor 12
```

### `crypto.hardcoded-iv` — Hard-coded or static IV / salt

Severity: 🟡 **medium**  ·  [CWE-329](https://cwe.mitre.org/data/definitions/329.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** An initialization vector (IV) for encryption — and a salt for password
hashing or key derivation — must be RANDOM and different every single time.
Their job is to make the same input produce different output, so attackers
can't spot repeats or precompute results. A fixed IV (passed as a literal
string or a constant Buffer.from('1234567890123456')) defeats that: identical
plaintexts encrypt identically, and with GCM/CTR modes a reused IV can even
leak the key stream and let an attacker recover the plaintext. A fixed salt
lets one precomputed table crack many hashes at once.

**How to fix it.** Generate a fresh random IV/salt for every operation with crypto.randomBytes()
and store it next to the ciphertext/hash (it does not need to be secret).

```js
const iv = crypto.randomBytes(12);   // fresh per message, stored with the ciphertext
const salt = crypto.randomBytes(16); // fresh per password
```

### `crypto.insecure-random` — Insecure randomness used for a security value

Severity: 🟡 **medium**  ·  [CWE-338](https://cwe.mitre.org/data/definitions/338.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** Math.random() is fast but predictable — an attacker who sees a few outputs can predict the rest. Using it to generate tokens, session ids, OTPs, or password-reset links lets an attacker guess them.

**How to fix it.** Use a cryptographically secure source: crypto.randomUUID(), crypto.getRandomValues() in the browser, or crypto.randomBytes() in Node.

```js
import { randomUUID } from 'crypto';
const token = randomUUID();
```

### `crypto.weak-hash` — Weak hash algorithm (MD5/SHA-1)

Severity: 🟡 **medium**  ·  [CWE-327](https://cwe.mitre.org/data/definitions/327.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** MD5 and SHA-1 are broken: attackers can find collisions and, for passwords, crack them at billions of guesses per second. Using them to hash passwords or verify integrity gives a false sense of security.

**How to fix it.** For passwords use a slow, salted password hash (bcrypt, scrypt, or argon2). For integrity use SHA-256 or better.

```js
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
```

## JSON Web Tokens

### `jwt.alg-none` — JWT verification accepts the "none" algorithm

Severity: 🔴 **critical**  ·  [CWE-347](https://cwe.mitre.org/data/definitions/347.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** A JWT says, in its own header, which algorithm was used to sign it. The
special algorithm "none" means "this token is not signed at all." If your
verification step accepts "none", an attacker can take any token, strip the
signature, set the algorithm to "none", and your app will treat it as valid.
That lets them rewrite the contents — for example change the user id to an
admin's — and be trusted instantly. This is the classic JWT "alg=none"
authentication bypass: a complete login bypass with no password needed.

**How to fix it.** Never include 'none' in the list of algorithms you accept. Pass an explicit
allowlist of the exact signing algorithm you use (for example ['HS256'] or
['RS256']) to your verify call, so a token claiming any other algorithm is
rejected.

```js
// only accept the algorithm you actually sign with:
const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
```

### `jwt.hardcoded-secret` — JWT signed or verified with a hard-coded secret

Severity: 🟠 **high**  ·  [CWE-798](https://cwe.mitre.org/data/definitions/798.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** A JSON Web Token (JWT) is a signed string your app hands to a logged-in user
so it can trust them on the next request — the signature is what proves the
token wasn't tampered with. That signature is only as strong as the secret
you sign it with. When the secret is written directly in your code (a plain
string like "secret" or "mysupersecretkey"), anyone who can see your
repository — or who finds the value in your shipped JavaScript bundle — can
forge their own valid tokens. With a forged token an attacker can log in as
ANY user, including an admin, without ever knowing a password.

**How to fix it.** Move the secret out of the code into an environment variable, and make it a
long, random value (32+ bytes). Read it from process.env at runtime. If this
secret has ever been committed, treat it as leaked: generate a new one (which
invalidates all existing tokens) and rotate it.

```js
import jwt from 'jsonwebtoken';
// JWT_SECRET set in your host's env / .env.local (gitignored), 32+ random bytes
const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
```

### `jwt.missing-algorithms` — JWT verified without an algorithms allowlist

Severity: 🟠 **high**  ·  [CWE-347](https://cwe.mitre.org/data/definitions/347.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** When you verify a JWT you should tell the library exactly which signing
algorithm to expect. If you don't, the library trusts the algorithm named
inside the token itself — which the attacker controls. The danger is
"algorithm confusion": apps that verify with a public RSA key (RS256) can be
tricked into accepting a token the attacker signed with that same public key
treated as an HMAC password (HS256). Because the public key is, by design,
public, the attacker can forge tokens and impersonate any user. Leaving the
allowlist off also leaves the door open to the "none" algorithm bypass.

**How to fix it.** Always pass the { algorithms: [...] } option to your verify call, listing
only the single algorithm you actually sign with. This pins verification so a
token claiming a different algorithm is rejected before its signature is even
checked.

```js
const payload = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
```

## Authentication & credentials

### `auth.hardcoded-credentials` — Hard-coded admin / login credentials in code

Severity: 🔴 **critical**  ·  [CWE-798](https://cwe.mitre.org/data/definitions/798.html)  ·  A07:2021-Identification and Authentication Failures

**Why this matters.** A username/password (or admin check) written directly into your code is a
permanent backdoor: it's visible to everyone who can read the repository,
it stays in git history even after you delete the line, and you usually
can't change it without a redeploy. Attackers specifically scan code for
patterns like `password === 'admin'` or `password == 'password'` because a
hard-coded credential often unlocks the highest-privilege account in the app.

**How to fix it.** Never compare against a literal password. Look the user up in your data
store and verify a salted password hash (bcrypt/argon2). Keep any
service/admin credentials in environment variables or a secrets manager, and
rotate anything that was committed.

```js
const user = await db.user.findUnique({ where: { email } });
const ok = user && await bcrypt.compare(password, user.passwordHash);
```

### `auth.middleware-bypass` — Auth check disabled or bypassed in middleware / guard

Severity: 🔴 **critical**  ·  [CWE-287](https://cwe.mitre.org/data/definitions/287.html)  ·  A07:2021-Identification and Authentication Failures

**Why this matters.** Middleware, route guards, and `getServerSideProps`-style checks are the
gates that decide who is allowed in. A line like `return true` at the top of
an auth guard, `return NextResponse.next()` before any check, or an
`if (true)` / `// TODO re-enable auth` short-circuit opens the gate for
everyone — every protected page and API becomes public. These bypasses are
usually left in during local development and then accidentally shipped,
handing attackers admin pages and private data with no login at all.

**How to fix it.** Remove the short-circuit and let the real check run. If you need to skip auth
locally, gate it behind an explicit env flag that can never be true in
production, and add a test that protected routes reject anonymous requests.

```js
export function middleware(req) {
  const session = req.cookies.get('session');
  if (!session) return NextResponse.redirect(new URL('/login', req.url));
  return NextResponse.next();
}
```

### `auth.hardcoded-basic-auth` — Hard-coded HTTP Basic / Bearer credentials in an Authorization header

Severity: 🟠 **high**  ·  [CWE-798](https://cwe.mitre.org/data/definitions/798.html)  ·  A07:2021-Identification and Authentication Failures

**Why this matters.** An `Authorization: Basic <base64>` header carries a username and password
that are merely base64-encoded — that is NOT encryption, anyone can decode
it in one line. Hard-coding such a header (or a literal `Bearer <token>`)
bakes a real credential into your source, where it leaks to everyone with
repo access and lives forever in git history. These static API/admin
credentials are a favourite target for automated secret scanners.

**How to fix it.** Build the header at runtime from a secret read out of the environment, and
rotate the exposed credential. Better still, use short-lived tokens issued
by your auth provider instead of static ones.

```js
const auth = 'Basic ' + Buffer.from(`${process.env.API_USER}:${process.env.API_PASS}`).toString('base64');
```

### `auth.jwt-in-localstorage` — Auth token stored in localStorage / sessionStorage

Severity: 🟠 **high**  ·  [CWE-922](https://cwe.mitre.org/data/definitions/922.html)  ·  A07:2021-Identification and Authentication Failures

**Why this matters.** `localStorage` and `sessionStorage` are readable by any JavaScript running
on your page. When you keep a login token (a JWT, an access/refresh token)
there, a single cross-site-scripting (XSS) bug anywhere on the site lets an
attacker read the token and impersonate the user from their own machine —
and unlike a stolen cookie, the token keeps working until it expires. Browser
storage also doesn't get the protections cookies have (httpOnly, Secure,
SameSite). The safer home for a session token is an httpOnly cookie that
scripts cannot read.

**How to fix it.** Store the session/refresh token in an httpOnly, Secure, SameSite cookie set
by the server, and let the browser attach it automatically. If you must keep
something in the browser, keep only non-sensitive data there.

```js
// server sets the token; the browser stores it where JS can't read it
res.cookie('token', jwt, { httpOnly: true, secure: true, sameSite: 'lax' });
```

## Sessions

### `session.hardcoded-secret` — Session signing secret hard-coded (or a well-known default)

Severity: 🟠 **high**  ·  [CWE-798](https://cwe.mitre.org/data/definitions/798.html)  ·  A07:2021-Identification and Authentication Failures

**Why this matters.** `express-session`, `cookie-session`, `cookie-parser`, and similar libraries
sign your session cookies with a secret key so the server can detect if a
user tampered with their cookie. If that secret is written directly in your
source code — and especially if it's a famous placeholder like
'keyboard cat' from the docs — anyone who can read the code (or guesses the
common default) can forge a valid signed cookie and log in as ANY user,
including an admin. The secret is the only thing standing between an attacker
and a forged session, so it must be unguessable and kept out of the codebase.

**How to fix it.** Move the secret into an environment variable, generate a long random value
(e.g. `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`),
and rotate it now since the committed one must be treated as compromised.

```js
app.use(session({ secret: process.env.SESSION_SECRET, /* httpOnly etc. */ }));
```

## Cookies

### `cookie.missing-httponly` — Session cookie set without the httpOnly flag

Severity: 🟠 **high**  ·  [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** A cookie is a small piece of data the browser stores and sends back on
every request — it's how your app remembers who is logged in. The
`httpOnly` flag tells the browser "JavaScript on the page is not allowed to
read this cookie." Without it, any JavaScript that runs on your site can
read the cookie's value with `document.cookie`. So if an attacker ever lands
a single cross-site-scripting (XSS) bug on one page, they can steal your
users' session cookies and log in as them. Marking auth/session cookies
httpOnly removes that entire path — the script can't see the cookie at all.

**How to fix it.** Add `httpOnly: true` whenever you set a cookie that identifies a logged-in
user (a session id, a JWT, a refresh token). The browser will keep sending
it automatically, but page scripts can no longer read it.

```js
// Next.js (app router)
cookies().set('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });
// Express
res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });
```

### `cookie.samesite-none-insecure` — SameSite=None cookie sent without the Secure flag

Severity: 🟠 **high**  ·  [CWE-614](https://cwe.mitre.org/data/definitions/614.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** `sameSite: 'none'` tells the browser to send this cookie on cross-site
requests — exactly the situation where it is most exposed. Modern browsers
REQUIRE such a cookie to also be `secure` (HTTPS-only) and will silently
refuse to store it otherwise, so a None cookie without Secure is both broken
and unsafe: it would travel over plain HTTP where anyone on the network can
read it. If you opt into cross-site cookies you must also opt into HTTPS-only.

**How to fix it.** Whenever you use `sameSite: 'none'`, also set `secure: true`. If you didn't
actually need cross-site cookies, switch to `sameSite: 'lax'` instead.

```js
cookies().set('session', token, { httpOnly: true, secure: true, sameSite: 'none' });
```

### `cookie.insecure-flags-live` — Cookie set without Secure / HttpOnly / SameSite

Severity: 🟡 **medium**  ·  [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** A live response set a cookie missing protective flags. Without HttpOnly, JavaScript (and thus any XSS) can read it; without Secure it can be sent over plain HTTP and intercepted; without SameSite it can be sent on cross-site requests (CSRF). Session cookies need all three.

**How to fix it.** Set HttpOnly, Secure, and SameSite=Lax (or Strict) on session/auth cookies.

```js
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Path=/
```

### `cookie.missing-samesite` — Session cookie set without an explicit SameSite policy

Severity: 🟡 **medium**  ·  [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** `SameSite` controls whether the browser sends your cookie when a request to
your site is triggered by a *different* site. If another website can make
the browser send your logged-in user's session cookie, it can perform
actions as that user without their knowledge — this is cross-site request
forgery (CSRF). Setting `sameSite: 'lax'` (or `'strict'`) tells the browser
not to attach the cookie to cross-site requests, which blocks most CSRF
attacks for free. Leaving it unset is risky to rely on, so set it explicitly.

**How to fix it.** Set `sameSite: 'lax'` for most session cookies (it still works for normal
top-level navigations like clicking a link), or `'strict'` for the most
sensitive ones. Use `'none'` only when you genuinely need cross-site cookies,
and pair it with `secure: true`.

```js
cookies().set('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });
```

### `cookie.missing-secure` — Session cookie set without the Secure flag

Severity: 🟡 **medium**  ·  [CWE-614](https://cwe.mitre.org/data/definitions/614.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** The `secure` flag tells the browser "only send this cookie over an
encrypted HTTPS connection, never plain HTTP." Without it, the cookie can be
sent over an unencrypted connection — and anyone sharing the network (a
coffee-shop Wi-Fi, a compromised router) can read it off the wire and use it
to impersonate the user. Session and auth cookies should always be Secure so
they are never transmitted in the clear.

**How to fix it.** Add `secure: true` to every cookie that carries login/session data. In local
development over http://localhost the browser still accepts Secure cookies,
so you can leave it on everywhere (or gate it on NODE_ENV === 'production').

```js
cookies().set('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });
```

## CORS

### `cors.origin-reflection` — CORS reflects the request Origin back without an allowlist

Severity: 🟠 **high**  ·  [CWE-942](https://cwe.mitre.org/data/definitions/942.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** To allow cookies on cross-site requests you can't use the `*` wildcard, so a
common shortcut is to copy whatever `Origin` the caller sent straight back
into `Access-Control-Allow-Origin`. That is effectively a wildcard that ALSO
works with credentials: every site that calls your API gets approved, because
you echo their own origin back to them.

A malicious page a logged-in user visits can then call your API as that user
and read the private response. The fact that the value isn't a literal `*`
fools you into thinking it's restrictive — it isn't.

**How to fix it.** Keep an allowlist of origins you actually trust and only echo the Origin back
if it is on the list. Add `Vary: Origin` so caches don't serve one site's
allowed response to another.

```js
const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);
const origin = req.headers.origin;
if (origin && ALLOWED.has(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
}
```

### `cors.wildcard-credentials` — CORS allows any origin together with credentials

Severity: 🟠 **high**  ·  [CWE-942](https://cwe.mitre.org/data/definitions/942.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** CORS headers tell the browser which OTHER websites are allowed to read
responses from your API. Setting `Access-Control-Allow-Origin: *` (any site)
while also allowing credentials (`Access-Control-Allow-Credentials: true`,
or `cors({ origin: true, credentials: true })`) means any website on the
internet can make authenticated requests to your API using your user's
cookies and read the responses — effectively stealing logged-in users' data
from any malicious page they visit. The browser actually forbids the literal
`*` + credentials combo, so apps often reflect the caller's origin instead,
which is just as dangerous.

**How to fix it.** When you allow credentials, allow only a specific list of trusted origins —
never `*` and never blindly reflect the request's Origin header.

```js
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
```

### `cors.wildcard-with-credentials` — CORS allows any site AND sends credentials (Access-Control-Allow-Origin: * with Allow-Credentials: true)

Severity: 🟠 **high**  ·  [CWE-942](https://cwe.mitre.org/data/definitions/942.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** CORS is the browser rule that decides which OTHER websites are allowed to
read responses from your API. `Access-Control-Allow-Origin: *` means "any
website on the internet may call this API and read the reply".
`Access-Control-Allow-Credentials: true` means "and the browser should send
the user's cookies along too".

Together these two are a forbidden combination: any malicious site a logged-in
user visits can quietly make requests to your API AS that user (their session
cookie rides along) and read the private response — their account data, their
messages, whatever the endpoint returns. Browsers actually refuse the literal
`*` + credentials pair, which usually pushes developers into the even more
dangerous habit of reflecting the caller's Origin instead (see
cors.origin-reflection).

**How to fix it.** Decide which sites are actually allowed and list them explicitly. Never pair
a wildcard with credentials. If you only have a public, read-only API and you
genuinely want it open to everyone, then do NOT send credentials (drop
Allow-Credentials and don't rely on cookies).

```js
const ALLOWED = new Set(['https://app.example.com']);
const origin = req.headers.origin;
if (origin && ALLOWED.has(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Vary', 'Origin');
}
```

### `cors.permissive-middleware` — cors() middleware configured to allow every origin

Severity: 🟡 **medium**  ·  [CWE-942](https://cwe.mitre.org/data/definitions/942.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** The popular `cors` middleware (and Express/Hono/Nest equivalents) defaults to
allowing ALL origins when you call `cors()` with no options, or pass
`origin: true` / `origin: '*'`. That means any website can call your API from
a browser and read the response. For a public, read-only API that may be
fine — but it is almost never what you want for an authenticated API, and it
is easy to ship by accident because the permissive form is the shortest to
type.

**How to fix it.** Pass an explicit `origin` option naming the sites you trust, or a function
that checks the incoming origin against an allowlist. Only keep the open
configuration if the endpoint is genuinely public and uses no cookies.

```js
app.use(cors({
  origin: ['https://app.example.com'],
  credentials: true,
}));
```

## Content-Security-Policy

### `csp.disabled-in-helmet` — Helmet's Content-Security-Policy turned off (contentSecurityPolicy: false)

Severity: 🟡 **medium**  ·  [CWE-693](https://cwe.mitre.org/data/definitions/693.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Helmet sets a bundle of protective HTTP headers for you, including a
Content-Security-Policy that limits the damage of a cross-site scripting
(XSS) bug. Passing `contentSecurityPolicy: false` (or calling
`helmet({ contentSecurityPolicy: false })`) switches that protection off, so
the browser will run any script that gets injected into your pages. People
often disable it to silence a console warning during development and forget to
turn it back on.

**How to fix it.** Leave Helmet's CSP enabled and configure its directives instead of disabling
it. Start from Helmet's defaults and add the specific sources your app needs.

```js
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      'script-src': ["'self'"],
      'object-src': ["'none'"],
      'base-uri': ["'self'"],
    },
  },
}));
```

### `csp.frame-ancestors-wildcard` — Clickjacking protection disabled (frame-ancestors *)

Severity: 🟡 **medium**  ·  [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** `frame-ancestors` in your Content-Security-Policy controls which sites are
allowed to embed your pages inside an `<iframe>`. Setting it to `*` (or
leaving X-Frame-Options off and frame-ancestors wide open) lets ANY site frame
your app. An attacker can then overlay your real page under their own buttons
and trick a logged-in user into clicking things they didn't mean to —
transferring money, changing settings, granting access. This is called
clickjacking.

**How to fix it.** Set `frame-ancestors 'self'` (or list the specific partner domains allowed to
embed you) and pair it with `X-Frame-Options: SAMEORIGIN` for older browsers.

```js
res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
res.setHeader('X-Frame-Options', 'SAMEORIGIN');
```

### `csp.unsafe-eval` — Content-Security-Policy weakened with 'unsafe-eval'

Severity: 🟡 **medium**  ·  [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Adding `'unsafe-eval'` to your Content-Security-Policy lets the page turn
strings into live code again via `eval()`, `new Function()`, and
`setTimeout('code')`. Those are exactly the primitives an attacker needs to
run their own JavaScript if they manage to inject a string anywhere, so this
setting cancels much of the protection CSP gives you against cross-site
scripting (XSS).

**How to fix it.** Remove `'unsafe-eval'`. If a dependency genuinely needs it (some older
templating or WASM tools do), prefer upgrading or replacing that dependency
rather than weakening the policy for the whole site.

```js
res.setHeader(
  'Content-Security-Policy',
  "script-src 'self'; object-src 'none'; base-uri 'self'"
);
```

### `csp.unsafe-inline` — Content-Security-Policy weakened with 'unsafe-inline'

Severity: 🟡 **medium**  ·  [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** A Content-Security-Policy (CSP) is a header that tells the browser which
scripts and styles it is allowed to run — it is one of your strongest
defenses against cross-site scripting (XSS). Adding `'unsafe-inline'` to
`script-src` tells the browser to run inline `<script>...</script>` and
`onclick="..."` handlers again. That re-enables exactly the injection
technique CSP is supposed to block, so an attacker who finds an XSS hole can
execute their script as if you had no CSP at all.

**How to fix it.** Remove `'unsafe-inline'` from `script-src`. Move inline scripts into separate
files, and if you must allow specific inline snippets use a per-request nonce
(`'nonce-...'`) or a hash instead.

```js
// generate a fresh nonce per request and put it on your <script nonce={n}> tags
res.setHeader(
  'Content-Security-Policy',
  `script-src 'self' 'nonce-${nonce}'; object-src 'none'; base-uri 'self'`
);
```

## CSRF

### `csrf.disabled` — CSRF protection explicitly disabled

Severity: 🟠 **high**  ·  [CWE-352](https://cwe.mitre.org/data/definitions/352.html)  ·  A01:2021-Broken Access Control

**Why this matters.** Cross-site request forgery (CSRF) is when another website tricks your
logged-in user's browser into sending a state-changing request to your app
(e.g. "transfer money", "change email") using the cookies the browser
attaches automatically. CSRF protection — an unguessable token your form must
include, checked on the server — stops this. Turning it off (`csrf: false`,
`csrfProtection: false`, `app.use(csrf())` removed/commented) re-opens every
cookie-authenticated mutation to forgery from any site your users visit.

**How to fix it.** Keep CSRF protection enabled for cookie-based sessions, or rely on
`SameSite` cookies plus a custom-header / double-submit token check. Only
disable it for APIs that authenticate with a Bearer token and never use
cookies.

```js
import csrf from 'csurf';
app.use(csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'lax' } }));
```

### `csrf.disabled-protection` — CSRF protection explicitly disabled

Severity: 🟠 **high**  ·  [CWE-352](https://cwe.mitre.org/data/definitions/352.html)  ·  A01:2021-Broken Access Control

**Why this matters.** CSRF (cross-site request forgery) is when another website makes a logged-in
user's browser send a real request to YOUR app — the browser helpfully
attaches the user's session cookie, so the request looks legitimate and your
server performs the action (change email, transfer funds, delete data)
without the user intending it. Frameworks ship CSRF protection on by default;
options like `csrf: false`, `csrfProtection: false`, or NextAuth's
`skipCSRFCheck` turn that guard off and re-open the door.

**How to fix it.** Leave the framework's CSRF protection enabled. If you disabled it to make an
API call work, the right fix is usually to authenticate that endpoint with a
bearer token / API key (not cookies) instead of switching the protection off
for everyone.

```js
// Keep the default protection on; authenticate machine-to-machine calls with a token:
app.use(csurf());                       // do NOT pass { ignoreMethods: [...] } to skip POST
// or, for an API route, require an Authorization header instead of a cookie.
```

### `csrf.samesite-none-cookie` — Session cookie set with SameSite=None (sent on cross-site requests)

Severity: 🟡 **medium**  ·  [CWE-352](https://cwe.mitre.org/data/definitions/352.html)  ·  A01:2021-Broken Access Control

**Why this matters.** The `SameSite` attribute on a cookie controls whether the browser attaches it
to requests that other websites trigger. `SameSite=Lax` (the modern default)
already blocks most cross-site request forgery (CSRF) by withholding the
cookie on cross-site POSTs. Setting `sameSite: 'none'` on an authentication or
session cookie turns that built-in protection back off, so a malicious site
can make the user's browser fire authenticated requests at your app again.

**How to fix it.** Use `sameSite: 'lax'` (or `'strict'`) for session and auth cookies. Only use
`'none'` for cookies that truly must travel cross-site (e.g. a third-party
embed), and when you do, add a separate anti-CSRF token check.

```js
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
});
```

## Security headers (live)

### `headers.missing-csp` — No Content-Security-Policy header

Severity: 🟡 **medium**  ·  [CWE-693](https://cwe.mitre.org/data/definitions/693.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** A Content-Security-Policy tells the browser which scripts, styles, and other resources are allowed to load. Without it, if an attacker manages to inject any HTML/JS (an XSS bug), there is nothing stopping it from running or from exfiltrating data to their server. CSP is your most important safety net against XSS.

**How to fix it.** Add a Content-Security-Policy. In Next.js, set it in next.config.js `headers()` (or middleware). Start strict and loosen as needed; avoid 'unsafe-inline'/'unsafe-eval'.

```js
// next.config.js headers():
{ key: 'Content-Security-Policy', value: "default-src 'self'; object-src 'none'; frame-ancestors 'none'" }
```

### `headers.missing-hsts` — No Strict-Transport-Security (HSTS) header

Severity: 🟡 **medium**  ·  [CWE-319](https://cwe.mitre.org/data/definitions/319.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** HSTS forces browsers to always use HTTPS for your site. Without it, an attacker on the network can downgrade a user's first request to HTTP and intercept it (cookies, credentials). HSTS closes that window.

**How to fix it.** Send Strict-Transport-Security with a long max-age once you're fully on HTTPS.

```js
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

### `headers.missing-x-frame-options` — No X-Frame-Options / frame-ancestors (clickjacking)

Severity: 🟡 **medium**  ·  [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Without X-Frame-Options (or a CSP frame-ancestors directive), an attacker can embed your site invisibly in an iframe on their page and trick users into clicking buttons they can't see (clickjacking) — e.g. confirming a money transfer.

**How to fix it.** Send X-Frame-Options: DENY (or SAMEORIGIN), or set CSP frame-ancestors 'none'.

```js
X-Frame-Options: DENY
```

### `headers.missing-referrer-policy` — No Referrer-Policy header

Severity: 🔵 **low**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** The Referer header your users' browsers send can leak internal URLs and tokens to third-party sites. A Referrer-Policy limits what is shared.

**How to fix it.** Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).

```js
Referrer-Policy: strict-origin-when-cross-origin
```

### `headers.missing-x-content-type-options` — No X-Content-Type-Options: nosniff

Severity: 🔵 **low**  ·  [CWE-430](https://cwe.mitre.org/data/definitions/430.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Without 'nosniff', browsers may guess (sniff) a response's content type and, for example, run a file you intended as plain text as JavaScript — turning a harmless upload into an XSS vector.

**How to fix it.** Send X-Content-Type-Options: nosniff on all responses.

```js
X-Content-Type-Options: nosniff
```

### `headers.server-version-disclosure` — Server / X-Powered-By reveals software version

Severity: 🔵 **low**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Advertising your exact server/framework version (e.g. 'X-Powered-By: Next.js') hands attackers a shortlist of version-specific exploits to try. It's free reconnaissance for them and gains you nothing.

**How to fix it.** Remove or generalize Server/X-Powered-By. In Next.js set poweredByHeader: false.

```js
// next.config.js
module.exports = { poweredByHeader: false };
```

## Configuration

### `config.disabled-tls-verification` — TLS certificate verification disabled

Severity: 🟠 **high**  ·  [CWE-295](https://cwe.mitre.org/data/definitions/295.html)  ·  A02:2021-Cryptographic Failures

**Why this matters.** Setting NODE_TLS_REJECT_UNAUTHORIZED=0 or `rejectUnauthorized: false` turns off the check that you're really talking to the server you think you are. Anyone on the network can then impersonate that server and read or modify the traffic (man-in-the-middle).

**How to fix it.** Remove the override. If you use self-signed certs in development, add the specific CA instead of disabling verification globally.

```js
// remove rejectUnauthorized:false; pass { ca: fs.readFileSync('dev-ca.pem') } if needed
```

### `config.missing-security-headers` — Missing security response headers

Severity: 🟡 **medium**  ·  [CWE-693](https://cwe.mitre.org/data/definitions/693.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Security headers (Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options) are extra guardrails the browser enforces for you — blocking clickjacking, forcing HTTPS, and limiting the damage of an XSS bug. Without them you lose defense in depth.

**How to fix it.** Set security headers in next.config.js `headers()` (or your server/middleware).

```js
// next.config.js
async headers() {
  return [{ source: '/(.*)', headers: [
    { key: 'X-Frame-Options', value: 'DENY' },
    { key: 'X-Content-Type-Options', value: 'nosniff' },
    { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  ]}];
}
```

## Supply chain

### `supply-chain.dangerous-install-script` — Dangerous install lifecycle script in package.json

Severity: 🔴 **critical**  ·  [CWE-506](https://cwe.mitre.org/data/definitions/506.html)  ·  A08:2021-Software and Data Integrity Failures

**Why this matters.** `preinstall`/`postinstall` scripts run automatically on `npm install`, with your user's permissions. A script that pipes a remote file into a shell (curl | sh), opens a reverse shell, or reads credentials is a classic supply-chain attack — it runs before you ever start your app.

**How to fix it.** Review the script and the package that ships it. Install untrusted packages with `npm install --ignore-scripts`. Remove any install script that fetches and executes remote code.

```js
npm install --ignore-scripts   # then run only the build steps you trust
```

### `supply-chain.missing-lockfile` — No lockfile committed

Severity: 🟡 **medium**  ·  [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html)  ·  A06:2021-Vulnerable and Outdated Components

**Why this matters.** Without a lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml), every install can pull different dependency versions. That means a malicious or broken version can slip in without any change to your code, and builds are not reproducible.

**How to fix it.** Commit your lockfile and install with `npm ci` in CI for exact, reproducible installs.

```js
git add package-lock.json && git commit -m 'add lockfile'
```

## Dependencies

### `deps.known-vulnerability` — Dependency with a known security vulnerability

Severity: 🟠 **high**  ·  [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html)  ·  A06:2021-Vulnerable and Outdated Components

**Why this matters.** This package version has a publicly documented security flaw (a CVE/advisory). Attackers actively scan for apps using vulnerable versions because a working exploit is already published.

**How to fix it.** Upgrade to the patched version listed in the advisory (`npm update <pkg>` or bump it in package.json).

```js
npm install <package>@<patched-version>
```

### `deps.typosquat` — Dependency name looks like a typosquat

Severity: 🟠 **high**  ·  [CWE-427](https://cwe.mitre.org/data/definitions/427.html)  ·  A08:2021-Software and Data Integrity Failures

**Why this matters.** Attackers publish packages whose names are one keystroke away from a popular library (e.g. `reactt`, `loadsh`). Install the wrong one and you are running their code. The name in your package.json is very close to a well-known package but not exactly it.

**How to fix it.** Double-check the package name against the official docs and the publisher on npm before installing.

## AI / LLM application security

### `ai.key-clientside` — LLM provider API key exposed to the browser

Severity: 🔴 **critical**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A07:2021-Identification and Authentication Failures

**Why this matters.** Your OpenAI / Anthropic API key is being put somewhere the browser can see
it — either in client-side code, or behind a `NEXT_PUBLIC_` / `VITE_` prefix
that bundles it into the JavaScript every visitor downloads. Anyone can open
devtools, copy your key, and spend YOUR money on the AI provider until the
key is shut off (this regularly costs people thousands of dollars). The key
also usually grants access to your whole AI account, not just one feature.

**How to fix it.** Never ship a provider key to the browser. Keep the key in a plain
server-only environment variable (NOT prefixed with NEXT_PUBLIC_ / VITE_)
and call the model from a server route or Server Action; have the browser
call YOUR endpoint instead of the provider directly. If this key has already
shipped to the client, rotate it now — assume it is compromised.

```js
// server only — app/api/chat/route.ts
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY }); // no NEXT_PUBLIC_
// the browser fetches /api/chat, never the provider directly
```

### `ai.llm-output-to-sink` — AI model output passed to eval / exec / a shell / SQL (treats LLM output as trusted)

Severity: 🔴 **critical**  ·  [CWE-94](https://cwe.mitre.org/data/definitions/94.html)  ·  LLM05:2025-Improper Output Handling

**Why this matters.** Whatever an AI model returns is NOT trusted code or data — a user can steer
the model into producing almost anything, and the model can also be fooled by
content it read elsewhere (a web page, a document, a previous message). If you
take the model's reply and run it with `eval()` / `new Function()`, hand it to
a shell with `exec()`, or drop it into a SQL query string, an attacker can
make the model output a payload that then executes on your server — full
remote code execution or database takeover. The model becomes a confused
deputy that runs the attacker's commands for them.

**How to fix it.** Treat model output exactly like raw user input: never execute it and never
splice it into a command or query. If you want the model to "choose an
action", have it return a short label and look the real action up in a fixed
allowlist/map you wrote. For databases use parameterised queries. For shell
work use execFile/spawn with an arguments array and validate every value.

```js
// model returns a label; YOU decide what runs — never eval its text
const intent = completion.choices[0].message.content?.trim();
const handlers = { refund: doRefund, status: doStatus };
await handlers[intent]?.();   // unknown label = nothing happens
```

### `ai.dangerously-allow-browser` — OpenAI SDK started with dangerouslyAllowBrowser: true

Severity: 🟠 **high**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A07:2021-Identification and Authentication Failures

**Why this matters.** The OpenAI SDK refuses to run in the browser by default, on purpose:
anything that runs in the browser ships your API key to every visitor.
Setting `dangerouslyAllowBrowser: true` turns that safety check off, which
almost always means your secret key is now downloadable by anyone using your
site — they can copy it and spend your money on the AI provider. The word
"dangerously" is a deliberate warning.

**How to fix it.** Remove `dangerouslyAllowBrowser: true` and move the OpenAI client to the
server (a route handler / Server Action), reading the key from a server-only
env var. Have the browser call your own endpoint. The only safe browser use
is with a short-lived, per-user ephemeral token — never your main API key.

```js
// server route — key never reaches the browser
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
export async function POST(req) { /* ...call model here... */ }
```

### `ai.endpoint-no-auth` — AI route calls the model with no sign-in / auth check in the file

Severity: 🟠 **high**  ·  [CWE-770](https://cwe.mitre.org/data/definitions/770.html)  ·  A04:2021-Insecure Design

**Why this matters.** This route handler calls a paid AI model (OpenAI / Anthropic / etc.) but
nothing in the file checks who is calling it — no session, no login, no API
token. That means ANYONE on the internet who finds the URL can hit it as
many times as they like. Every call costs you money, so a bot can run up a
huge bill on your account overnight ("denial of wallet"), and your model
quota gets drained for real users. It also lets strangers use your app as a
free LLM proxy. (This is a heuristic: if your auth check lives in middleware
or a shared helper this file doesn't reference, you can add a
`// njordscan-ignore` comment on the call line.)

**How to fix it.** Before calling the model, confirm the request is from a logged-in user and
reject it otherwise. Use whatever auth you already have: `getServerSession`
(NextAuth), `auth()` (Clerk), `supabase.auth.getUser()`, or a check on the
`Authorization` header / API key for server-to-server calls. Return 401 if
the check fails — do this first, before any model call.

```js
import { getServerSession } from 'next-auth';
export async function POST(req) {
  const session = await getServerSession();
  if (!session) return new Response('Unauthorized', { status: 401 });
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini', max_tokens: 500, messages,
  });
  return Response.json(completion);
}
```

### `ai.llm-output-rendered-as-html` — AI model output rendered as raw HTML (dangerouslySetInnerHTML / innerHTML)

Severity: 🟠 **high**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  LLM05:2025-Improper Output Handling

**Why this matters.** React normally escapes text for you, so even weird characters render
harmlessly. Passing the model's reply to `dangerouslySetInnerHTML` or
assigning it to `innerHTML` turns that protection off and parses the reply as
HTML. Because a user (or a document the model read) can steer the model into
producing `<img src=x onerror=...>` or a `<script>` tag, an attacker can run
JavaScript in your other users' browsers — stealing their sessions or acting
as them. This is cross-site scripting (XSS); AI output is attacker-influenced,
so it counts as untrusted just like a form field.

**How to fix it.** Render the reply as text: in React just do `{reply}` and let React escape it.
If you want Markdown formatting, convert it and then sanitize the resulting
HTML with DOMPurify before passing it to dangerouslySetInnerHTML — every time.

```js
// render AI text safely — React escapes it
return <p className="whitespace-pre-wrap">{reply}</p>;
// if you need Markdown:
// const html = DOMPurify.sanitize(marked.parse(reply));
// return <div dangerouslySetInnerHTML={{ __html: html }} />;
```

### `ai.prompt-injection` — User input mixed directly into the AI's instructions (prompt injection)

Severity: 🟠 **high**  ·  [CWE-77](https://cwe.mitre.org/data/definitions/77.html)  ·  LLM01:2025-Prompt Injection

**Why this matters.** An AI model can't tell the difference between YOUR instructions and text a
user typed — it just reads one big blob of words. The "system" message (and
any instruction string you build) is supposed to be the part only YOU
control: "you are a support bot, never reveal pricing", and so on. When you
glue user input straight into that instruction string (with `+` or a
`${...}` template), a user can write "ignore your previous instructions and
do X instead" and the model will happily obey. That lets them jailbreak your
bot, leak your hidden prompt, run tools they shouldn't, or make the model say
things that get attributed to your company. This is called prompt injection,
and it is the #1 risk for AI apps.
Note: putting user text in a normal `{ role: 'user', content: userMessage }`
field is completely fine and expected — that is where user text belongs. The
danger is ONLY when user text lands inside the system / instruction part.

**How to fix it.** Keep the two apart. Put your fixed rules in the `system` message as a plain
string with no user data in it, and put the user's text in a separate
`{ role: 'user', content: userInput }` message. Never concatenate or
interpolate user input into the system prompt. If you need to reference user
data inside instructions, wrap it in clear delimiters and tell the model to
treat it as untrusted data, not commands — but separate messages is the
stronger fix.

```js
// user text goes in its OWN message, never inside the instructions
const completion = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [
    { role: 'system', content: 'You are a helpful support assistant. Never reveal internal pricing.' },
    { role: 'user', content: req.body.message },   // safe: data, not instructions
  ],
});
```

### `ai.no-rate-limit` — AI route calls the model with no rate limit in the file

Severity: 🟡 **medium**  ·  [CWE-770](https://cwe.mitre.org/data/definitions/770.html)  ·  A04:2021-Insecure Design

**Why this matters.** This route calls a paid AI model but nothing in the file limits how often a
single user (or a bot) can call it. AI calls cost real money per request, so
without a cap one abusive client can hammer the endpoint thousands of times
and run up your bill or exhaust your model quota for everyone else ("denial
of wallet"). Even a friendly bug — a retry loop in the UI — can do this by
accident. (Heuristic: if you rate-limit in middleware or a shared helper
this file doesn't reference, add `// njordscan-ignore` on the call line.)

**How to fix it.** Add a per-user / per-IP rate limit before the model call. A common setup is
Upstash Ratelimit on Vercel, but any limiter works. Reject requests that go
over the limit with HTTP 429 before spending money on a model call.

```js
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';
const ratelimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(10, '60 s') });
export async function POST(req) {
  const { success } = await ratelimit.limit(req.ip ?? 'anon');
  if (!success) return new Response('Too Many Requests', { status: 429 });
  // ...call the model...
}
```

### `ai.pii-or-secret-to-llm` — Secrets or personal data sent into an AI prompt

Severity: 🟡 **medium**  ·  [CWE-201](https://cwe.mitre.org/data/definitions/201.html)  ·  LLM02:2025-Sensitive Information Disclosure

**Why this matters.** Everything you put in a prompt leaves your server and goes to the model
provider (OpenAI, Anthropic, etc.). Stuffing secrets or personal data into the
prompt — an API key or password from process.env, a whole `req.body`, or
variables named like ssn / creditCard / passport — means that data is now
logged on their side, may be used for training depending on your plan, and can
leak back out: the model can repeat it to another user, or an attacker can use
prompt injection to make it read those values back. Sending more than the task
needs is an unnecessary privacy and compliance risk.

**How to fix it.** Send the model only the minimum it needs to do the job. Never put credentials
or secrets in a prompt — the model never needs them. Strip or redact personal
data (names, emails, SSNs, card numbers) before the call, or replace it with a
placeholder token you swap back afterwards. Pass specific fields, not the
entire request body.

```js
// send only the fields the task needs — no secrets, no raw req.body
const summary = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [
    { role: 'system', content: 'Summarise the support ticket.' },
    { role: 'user', content: ticket.text },   // not the whole request, no keys
  ],
});
```

### `ai.system-prompt-clientside` — AI system prompt / instructions defined in browser ('use client') code

Severity: 🟡 **medium**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  LLM07:2025-System Prompt Leakage

**Why this matters.** A "system prompt" is the hidden instruction that shapes how your AI behaves —
your secret sauce, and often the only thing stopping users from making the
bot do something off-brand. If you write that prompt in a file marked
`'use client'` (or anywhere that runs in the browser), it ships inside the
JavaScript bundle that every visitor downloads. Anyone can open dev tools,
read your exact instructions, copy your prompt design, and — worse — craft
inputs that defeat each rule because they can see all of them. Client-side
prompts can also be edited by the user before the request is sent, so any
"guardrails" in them are effectively optional.

**How to fix it.** Keep the system prompt on the server. Define it inside a Server Action, a
Route Handler (app/api/.../route.ts), or getServerSideProps — files WITHOUT
`'use client'` — and call the model from there. The browser should only send
the user's message to your server; your server adds the instructions and
talks to the model.

```js
// app/api/chat/route.ts  (server only — no 'use client')
const SYSTEM_PROMPT = 'You are a helpful assistant. Stay on topic.';
export async function POST(req: Request) {
  const { message } = await req.json();
  return openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: message },
    ],
  });
}
```

### `ai.unbounded-output` — Model call sets no max output token limit

Severity: 🔵 **low**  ·  [CWE-770](https://cwe.mitre.org/data/definitions/770.html)  ·  A04:2021-Insecure Design

**Why this matters.** This model call doesn't set a maximum on how much text the model can
generate (no `max_tokens` / `max_output_tokens` / `maxOutputTokens`). Output
tokens are usually the most expensive part of an AI call, so an unbounded
response can cost far more than you expect — and an attacker can deliberately
craft a prompt that makes the model ramble to the limit, multiplying your
bill across many requests. It can also make responses slow and unpredictable.

**How to fix it.** Set an explicit cap on output length on every model call. Pick the smallest
number that still fits your feature (e.g. a chat reply rarely needs more than
a few hundred tokens). The exact field name depends on the SDK: `max_tokens`
(OpenAI chat / Anthropic), `max_output_tokens` (OpenAI Responses), or
`maxOutputTokens` (Vercel AI SDK).

```js
const completion = await openai.chat.completions.create({
  model: 'gpt-4o-mini',
  max_tokens: 500,        // cap the response
  messages,
});
```

## AI endpoints (dynamic)

### `ai-endpoint.unauthenticated-live` — AI/LLM endpoint responds without authentication

Severity: 🟠 **high**  ·  [CWE-284](https://cwe.mitre.org/data/definitions/284.html)  ·  A01:2021-Broken Access Control

**Why this matters.** A likely AI/LLM endpoint (e.g. /api/chat) answered an unauthenticated request. If it proxies to a paid model (OpenAI/Anthropic) with no auth or rate limit, anyone on the internet can run up your bill, exfiltrate your prompts, or abuse your model quota — a "denial of wallet" attack that has cost startups thousands overnight.

**How to fix it.** Require authentication on AI routes, add per-user rate limiting and spend caps, and never expose your provider key to the client.

```js
const session = await auth();
if (!session) return new Response('Unauthorized', { status: 401 });
// + rate-limit per user before calling the model
```

## Dynamic scan (DAST)

### `dast.reflected-xss` — Reflected input appears unescaped in the response

Severity: 🟠 **high**  ·  [CWE-79](https://cwe.mitre.org/data/definitions/79.html)  ·  A03:2021-Injection

**Why this matters.** NjordScan sent a harmless marker in the URL and the live app echoed it back into the HTML without escaping it. That means an attacker can put real <script> in that same parameter and it will run in your users' browsers (reflected XSS) — letting them steal sessions or act as the victim.

**How to fix it.** Escape all user input before placing it in HTML (frameworks like React do this for you when you render {value}); never build HTML by string concatenation with request data.

```js
return <p>{userInput}</p>; // React escapes it automatically
```

### `dast.open-redirect` — Open redirect to an attacker-controlled URL

Severity: 🟡 **medium**  ·  [CWE-601](https://cwe.mitre.org/data/definitions/601.html)  ·  A01:2021-Broken Access Control

**Why this matters.** NjordScan asked the live app to redirect to an external URL and it complied. An attacker can craft a link that starts on your trusted domain but sends users to a phishing site — perfect for stealing credentials because the link looks legitimate.

**How to fix it.** Only redirect to relative paths you control, or check the destination against an allowlist.

```js
if (!target.startsWith('/')) target = '/';
```

### `dast.verbose-error` — Server returns a stack trace / verbose error to the client

Severity: 🟡 **medium**  ·  [CWE-209](https://cwe.mitre.org/data/definitions/209.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** The live app returned a stack trace or detailed error to an unauthenticated request. Stack traces reveal file paths, library versions, and internal logic that help an attacker plan an exploit — and sometimes leak secrets directly.

**How to fix it.** Return generic error messages to clients; log details server-side only. Ensure NODE_ENV=production.

```js
res.status(500).json({ error: 'Internal Server Error' }); // log the real one server-side
```

## Hardening & info-leak

### `hardening.env-committed` — Environment file appears to be tracked by git

Severity: 🔴 **critical**  ·  [CWE-538](https://cwe.mitre.org/data/definitions/538.html)  ·  A01:2021-Broken Access Control

**Why this matters.** A .env file is tracked in this git repository. Any secret inside it is in the repo (and its history) and is visible to anyone with access — and likely already scraped if the repo is or ever was public. This is a credential leak.

**How to fix it.** Remove the file from tracking (`git rm --cached .env`), add it to .gitignore, commit, and ROTATE every secret it contained (assume all are compromised). To purge it from history, use `git filter-repo` or the BFG tool.

```js
git rm --cached .env
echo ".env" >> .gitignore
git commit -m "stop tracking .env"
```

### `hardening.insecure-deserialization` — Untrusted data turned back into objects/code (insecure deserialization)

Severity: 🔴 **critical**  ·  [CWE-502](https://cwe.mitre.org/data/definitions/502.html)  ·  A08:2021-Software and Data Integrity Failures

**Why this matters.** Libraries like `node-serialize` (`unserialize()`) and Node's `vm` module
(`vm.runInNewContext`, `vm.runInThisContext`) can rebuild not just data but live
functions from a string. If that string comes from a user — a cookie, a request
body, a query param — an attacker can craft a payload that runs their own code on
your server the instant you deserialize it. This is one of the most reliable ways
to fully take over a server.

**How to fix it.** For data, use `JSON.parse` — it only produces plain values, never executable code.
Never feed user input to `node-serialize`, `vm.runInNewContext`, or similar. If you
genuinely need structured objects, validate the parsed JSON against a schema (Zod)
before using it.

```js
const data = JSON.parse(req.body.payload); // never functions; then validate:
const parsed = MySchema.parse(data);
```

### `hardening.dev-only-branch-shipping-secret-bypass` — Security check bypassed when NODE_ENV is not 'production'

Severity: 🟠 **high**  ·  [CWE-489](https://cwe.mitre.org/data/definitions/489.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Code like `if (process.env.NODE_ENV !== 'production') skipAuth()` is meant to
make local development convenient, but it backfires the moment NODE_ENV is unset
or wrong on a real server — and it often is (a missed env var, a preview deploy,
a misconfigured container all default to a non-production value). The "dev only"
shortcut then runs in the open, disabling authentication or other checks for
real users. The safe default must be the secure one.

**How to fix it.** Never gate a security control on "are we in development". Keep auth and checks
always on, and instead make development easier with seeded test accounts or a
separate dev-only login that does not bypass the real check. If you must guard
debug-only code, fail closed (default to the secure branch).

```js
// auth always runs; dev convenience comes from a seeded test user, not a bypass
const user = await requireUser(req);
```

### `hardening.env-not-gitignored` — Environment file is not ignored by git

Severity: 🟠 **high**  ·  [CWE-538](https://cwe.mitre.org/data/definitions/538.html)  ·  A01:2021-Broken Access Control

**Why this matters.** This project has a .env file that is NOT listed in .gitignore, so the next `git add .` will commit it. Env files almost always hold secrets (database URLs, API keys), and once a secret is pushed it is in your git history forever — scrapers find committed secrets within minutes. This is one of the most common ways beginners leak credentials.

**How to fix it.** Add `.env`, `.env.local`, and `.env.*.local` to your .gitignore now (run `njordscan scan . --fix` to do it automatically). If the file was already committed, remove it from history and rotate every secret it contained.

```js
# .gitignore
.env
.env.local
.env.*.local
```

### `hardening.debug-enabled-in-prod` — Debug / verbose mode hard-coded on

Severity: 🟡 **medium**  ·  [CWE-489](https://cwe.mitre.org/data/definitions/489.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** A `debug: true` flag (or `devtools: true`, `DEBUG=*`) left on in a config that
ships to production exposes internal details: verbose errors, query logs,
framework dashboards, and source maps. Anything meant for "while I'm developing"
becomes visible to anyone poking at your live site, giving attackers a clearer
picture of how your app works and where it breaks.

**How to fix it.** Drive debug flags from the environment, defaulting to OFF, so production never
runs in debug mode by accident: `debug: process.env.NODE_ENV !== 'production'`.
Make sure source maps and dev dashboards are disabled in your production build.

```js
const config = { debug: process.env.NODE_ENV !== 'production' };
```

### `hardening.redos-regex` — Regular expression vulnerable to catastrophic backtracking (ReDoS)

Severity: 🟡 **medium**  ·  [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** A regex with nested quantifiers — like `(a+)+`, `(.*)*`, or `(\d+)+$` — can take
an exponential amount of time to fail on certain inputs. When that regex runs on
user input (validating an email, a URL, a header), an attacker sends one short
crafted string and your single Node.js thread spins at 100% CPU, freezing the
whole app for everyone. This is a denial-of-service with no special access needed.

**How to fix it.** Rewrite the pattern to avoid a quantifier inside another quantifier. Use specific
character classes and bounded repetition (`{1,64}`) instead of `+`/`*` stacks, or
validate with a parser/library instead of a hand-rolled regex. Test patterns with
a ReDoS checker (e.g. `recheck`, `safe-regex`).

```js
const re = /^[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,255}\.[a-z]{2,}$/i; // bounded, no nesting
```

### `hardening.source-map-shipped-to-prod` — Production source maps enabled (ships readable source to the browser)

Severity: 🔵 **low**  ·  [CWE-540](https://cwe.mitre.org/data/definitions/540.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Source maps let the browser show your original, un-minified code in DevTools.
That is great while developing, but enabling `productionBrowserSourceMaps: true`
(Next.js) or `build.sourcemap: true` (Vite) publishes your readable source —
comments, internal logic, sometimes commented-out secrets — to every visitor.
Attackers download the maps to study exactly how your app works.

**How to fix it.** Leave production source maps off (the default). If you need them for error
monitoring, upload them privately to your error tracker (Sentry) instead of
serving them to browsers, and delete them from the public build output.

```js
// next.config.js — keep maps off the public bundle
const nextConfig = { productionBrowserSourceMaps: false };
```

### `hardening.unhandled-todo-security` — TODO/FIXME marker on a security-sensitive line

Severity: 🔵 **low**  ·  [CWE-546](https://cwe.mitre.org/data/definitions/546.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** A comment like `// TODO: add auth here` or `// FIXME: validate this input` is an
honest note to yourself — but it is also a signed confession that a security
control is missing, sitting in code that may already be live. These get forgotten,
survive into production, and conveniently point an attacker (who can read your
public repo) straight at the soft spot you meant to come back to.

**How to fix it.** Treat a security TODO as a blocker, not a nice-to-have: finish the control before
shipping, or track it as a real issue/ticket and remove the marker from code that
deploys. Don't leave unfinished auth/validation behind a comment.

```js
// resolved: input is now validated with Zod below — no outstanding security TODO
```

## Information leakage

### `info-leak.process-env-to-client` — process.env serialized or sent to the browser

Severity: 🟠 **high**  ·  [CWE-200](https://cwe.mitre.org/data/definitions/200.html)  ·  A01:2021-Broken Access Control

**Why this matters.** `process.env` holds every server secret — database passwords, API keys, signing
secrets. Serializing the whole object (`JSON.stringify(process.env)`,
`{ ...process.env }` in props, or returning it from an API) ships those secrets
to the browser, where any visitor can read them in the page source or network
tab. One line like this can leak your entire backend's credentials at once.

**How to fix it.** Pick out only the specific, non-secret values the browser needs and pass those.
On Next.js, expose public values with the `NEXT_PUBLIC_` prefix (on Vite, `VITE_`)
and read real secrets only in server code. Never hand the whole env object to the
client.

```js
return { props: { appName: process.env.NEXT_PUBLIC_APP_NAME } }; // one safe value
```

### `info-leak.console-logs-secret` — Secret, token, or password written to the logs

Severity: 🟡 **medium**  ·  [CWE-532](https://cwe.mitre.org/data/definitions/532.html)  ·  A09:2021-Security Logging and Monitoring Failures

**Why this matters.** `console.log(password)` or `console.error('token', token)` looks harmless in
development, but in production those lines flow into log files, your hosting
dashboard, and third-party log collectors (Datadog, CloudWatch, Sentry) where
far more people can read them than can read your database. Logged secrets are a
very common way credentials leak — they sit in plaintext, get backed up, and
are rarely scrubbed.

**How to fix it.** Never log secrets, passwords, tokens, or full request bodies. Log an id or a
boolean ("auth succeeded") instead of the value. If you must debug a value,
redact it (`token.slice(0, 4) + '…'`) and remove the line before shipping.

```js
console.log('login attempt', { userId, ok: result.success }); // no secret values
```

### `info-leak.error-stack-to-client` — Raw error stack or full error object sent to the client

Severity: 🟡 **medium**  ·  [CWE-209](https://cwe.mitre.org/data/definitions/209.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** When something throws, the error object (and especially `err.stack`) contains
a goldmine for an attacker: absolute file paths on your server, function names,
library versions, SQL fragments, and sometimes the very secret that failed to
validate. Sending that straight back in the HTTP response — `res.send(err.stack)`
or `res.json({ error: err })` — turns every crash into a free map of your
internals. Attackers deliberately trigger errors just to read these messages.

**How to fix it.** Show the user a short, generic message ("Something went wrong") and log the
real error server-side where only you can see it. Send a stable error code or
request id the user can quote to support, never the stack trace.

```js
catch (err) {
  console.error(err);              // full detail stays on the server
  res.status(500).json({ error: 'Internal Server Error' });
}
```

### `info-leak.console-logs-request-body` — Full request body logged (may contain passwords or PII)

Severity: 🔵 **low**  ·  [CWE-532](https://cwe.mitre.org/data/definitions/532.html)  ·  A09:2021-Security Logging and Monitoring Failures

**Why this matters.** `console.log(req.body)` dumps everything the user submitted into your logs —
including passwords on a login form, credit-card-ish fields, and personal data.
Once it is in a log it is copied, backed up, and shared with whoever can see
your logging tool, often forever. This is how plaintext passwords end up in a
breach even when the database stored them hashed.

**How to fix it.** Log only the specific, non-sensitive fields you actually need to debug. Never
log a whole request/response body in production. If you need request logging,
use a logger with a redaction allowlist (e.g. pino's `redact`).

```js
console.log('signup', { email: req.body.email }); // not the password field
```

### `info-leak.error-message-to-client` — Error message forwarded to the client in an API/route handler

Severity: 🔵 **low**  ·  [CWE-209](https://cwe.mitre.org/data/definitions/209.html)  ·  A05:2021-Security Misconfiguration

**Why this matters.** Returning `err.message` to the caller leaks whatever the underlying library
decided to put there — database column names, file paths, "user not found"
vs "wrong password" (which lets attackers enumerate accounts), or pieces of an
internal URL. It is a smaller leak than a full stack trace, but it still hands
attackers details they should have to guess.

**How to fix it.** Map errors to your own generic, user-safe messages. Keep the original
`err.message` in your server logs only. For auth, use one identical message
for "wrong email" and "wrong password" so attackers cannot tell which is which.

```js
catch (err) {
  logger.error(err);
  return Response.json({ error: 'Request failed' }, { status: 500 });
}
```
