# Rui∇abla

Records of Light and Dust.

Rui∇abla means Ruin + Nabla( ∇).

## Tech Stack

- [Vue](https://vuejs.org)
- [TypeScript](https://www.typescriptlang.org)
- [Vite](https://vite.dev)
- [MDXjs](https://mdxjs.com)
- [Shiki 式](https://shiki.style)
- [Pinia](https://pinia.vuejs.org)

## Develop

```sh
bun install

export OPAQUE_SERVER_SETUP="$(npx @serenity-kit/opaque@latest create-server-setup)"

bun dev

bun new

bun run build
```

Set `OPAQUE_SERVER_SETUP` in your local env and deployment env before running auth flows. Keep the same value permanently. Rotating it invalidates existing OPAQUE password records.

## OpenID Connect

The site exposes an OpenID Connect provider at `https://shikoch.in/.well-known/openid-configuration`. Apply `migrations/003_oidc.sql` to D1 before deploying the provider:

```sh
npx wrangler d1 execute ruinabla-db --remote --file=migrations/003_oidc.sql
```

Create a persistent RSA signing key and store its private JWK JSON as the Cloudflare Pages secret `OIDC_PRIVATE_JWK`; keep this value stable so clients can continue validating tokens against the published JWKS. A key can be generated with:

```sh
node -e "const { generateKeyPairSync } = require('node:crypto'); console.log(JSON.stringify(generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' })))"
```

Set the generated value with `npx wrangler pages secret put OIDC_PRIVATE_JWK`; use the same private JWK in `.dev.vars` for local Pages development. Users can register confidential clients in Settings > OIDC clients. The provider supports the authorization code flow with mandatory S256 PKCE, `openid` and `email` scopes, and exact registered redirect URI matching.

The site can also sign users in through krtl.net. Set the credentials from the krtl OAuth client registration as Pages secrets (never commit them), then apply the migration:

```sh
npx wrangler pages secret put KRTL_CLIENT_ID
npx wrangler pages secret put KRTL_CLIENT_SECRET
npx wrangler d1 execute ruinabla-db --remote --file=migrations/004_add_krtl_login.sql
```

The registered callback URL is `https://shikoch.in/oidc/callback`. The integration uses S256 PKCE, nonce and state validation, verifies krtl's RS256 ID token, and requires a verified email before creating or linking a local account.

## License

Code: Unlicense

Content: CC BY-SA 4.0
