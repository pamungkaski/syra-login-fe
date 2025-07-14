# SyRA Login Front‑End

**Privacy‑Preserving, Sybil‑Resilient OAuth 2.0 Authentication**

SyRA Login FE is a Next.js 15 client that turns a regular Google sign‑in into a zero‑knowledge, SyRA‑compatible authentication flow for blockchain dApps. It demonstrates how to:

- Prove selected JWT claims (e.g. `sub`) in zero knowledge with Noir circuits.
- Mint SyRA user keys after a cryptographic attest by an admin service.
- Produce a final verifier proof that binds the JWT, Google’s JWK and your keys.
- Sign arbitrary messages with a SyRA zk‑signature and verify it locally.

## Live demo

```bash
git clone https://github.com/pamungkaski/syra-login-fe.git
cd syra-login-fe
npm install        # or yarn / pnpm
npm run dev
```

Then open [**http://localhost:8080**](http://localhost:8080) in your browser.

## Tech stack

| Layer      | Libraries                        |
| ---------- | -------------------------------- |
| Framework  | Next.js 15, React 19, TypeScript |
| Styling    | Tailwind CSS 4                   |
| ZK Toolkit | noir\_js, snarkjs, @aztec/bb.js  |
| OAuth      | @react-oauth/google              |
| Crypto     | @noble/secp256k1, @noble/hashes  |

## Environment

Create a `.env.local` at project root:

```env
NEXT_PUBLIC_GOOGLE_CLIENT_ID=<your Google OAuth client ID>
```

> Optional: change the port in `package.json` if you cannot use **8080**.

## Scripts

```bash
npm run dev     # Dev server (8080)
npm run build   # Production build
npm start       # Start production server (3000)
npm run lint    # ESLint
```

## Usage flow

1. **Google sign‑in** – `GoogleLoginButton` stores the raw ID token and generates an ephemeral secp256k1 keypair.
2. **JWT proof** – `ProveJWTButton` invokes `proveGoogleJWT()` to create a zk‑proof of the `sub` claim.
3. **Key generation** – `GenerateUserKeysButton` POSTs the proof to `/admin/generate_user_key` and receives `ivk`, `usk` and `usk_hat`.
4. **Final verifier proof** – `ProveJWTFinalVerifier` combines the JWK, claims and prior proof into a succinct proof for the verifier.
5. **SyRA signature** – `SyraSection` signs an arbitrary message and can also verify the resulting proof.

All artefacts are cached in `localStorage` so the flow can be executed step‑by‑step without refresh‑induced data loss.

## Project structure

```
src/
 ├─ app/                 # Next.js pages & layout
 ├─ components/          # React UI components (buttons, forms, sections)
 ├─ lib/
 │   ├─ api/             # REST helpers → backend admin service
 │   └─ zk/              # Noir circuits, provers, input generators
 └─ styles/              # Tailwind config & global CSS
```

## Backend requirements
https://github.com/pamungkaski/syra-login-rs

This front‑end expects an admin service exposing:

```
POST http://127.0.0.1:9000/admin/generate_user_key
```

with body:

```json
{
  "user_id": "<jwt.sub>",
  "kid": "<jwt.header.kid>",
  "proof": "<base64‑encoded proof>"
}
```

and responds with:

```json
{
  "ivk": "...",
  "usk": "...",
  "usk_hat": "..."
}
```

## Contributing

PRs and issues are welcome! Please open an issue first to discuss major changes.

## License

Distributed without an explicit license. See `LICENSE` if one is later added.

