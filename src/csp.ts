/**
 * Content-Security-Policy of the production page, injected into index.html at build time (see vite.config.ts).
 *
 * The app only ever loads its own files, never talks to another site and has no inline scripts or styles, so the policy can be
 * as strict as it gets. Every directive is `'self'` or `'none'`: the browser itself refuses to send a key, a message or
 * anything else to a third party, even if a dependency were compromised.
 *
 * `connect-src 'self'` rather than `'none'`: Chrome downloads the icons listed in the web app manifest (to decide whether the
 * app is installable, and for the Application panel of the developer tools) under `connect-src`. With 'none' this floods the
 * console with violations and can get in the way of the install prompt. The page itself never calls fetch(), XHR or WebSocket.
 *
 * A <meta> policy cannot carry `frame-ancestors` or a report endpoint; those would need HTTP headers.
 */
export const DIRECTIVES: Record<string, string[]> = {
    'default-src': ["'none'"],
    'script-src': ["'self'"],
    'style-src': ["'self'"],
    'img-src': ["'self'"],
    'manifest-src': ["'self'"],
    // the service worker (and the scripts it imports) are served from the same origin
    'worker-src': ["'self'"],
    // same origin only (manifest icons, see above): nothing can be sent to another site
    'connect-src': ["'self'"],
    'base-uri': ["'none'"],
    'form-action': ["'none'"],
};

export const CONTENT_SECURITY_POLICY = Object.entries(DIRECTIVES)
    .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
    .join('; ');
