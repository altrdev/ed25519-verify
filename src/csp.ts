/**
 * Content-Security-Policy of the production page, injected into index.html at build time (see vite.config.ts).
 *
 * The app makes no network requests at all and has no inline scripts or styles, so the policy can be as strict as it gets.
 * `connect-src 'none'` is what turns "nothing is uploaded" from a promise into something the browser enforces:
 * even a compromised dependency could not send a key or a message anywhere.
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
    // the page never talks to the network
    'connect-src': ["'none'"],
    'base-uri': ["'none'"],
    'form-action': ["'none'"],
};

export const CONTENT_SECURITY_POLICY = Object.entries(DIRECTIVES)
    .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
    .join('; ');
