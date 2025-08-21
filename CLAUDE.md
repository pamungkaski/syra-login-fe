# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Development
```bash
npm run dev        # Start Next.js dev server with Turbopack on port 8080
npm run build      # Build production bundle
npm start          # Start production server (port 3000)
npm run lint       # Run ESLint
```

### Environment Setup
Create `.env.local` with:
```
NEXT_PUBLIC_GOOGLE_CLIENT_ID=<your Google OAuth client ID>
```

### Proving Key Setup
```bash
chmod +x download_proving_key.sh
./download_proving_key.sh    # Downloads zkey files to ./public/
```

## Architecture

### Zero-Knowledge Authentication Flow
1. **Google OAuth** - User signs in with Google, receives JWT ID token
2. **JWT ZK Proof** - Creates SNARK proof of JWT `sub` claim without revealing full token
3. **Key Generation** - Admin service generates SyRA keys (ivk, usk, usk_hat) after verifying proof
4. **Final Verifier Proof** - Combines JWK, claims, and prior proof into succinct proof
5. **SyRA Signature** - Signs messages with SyRA keys and verifies signatures locally

### Key Components

#### React Components (`src/components/`)
- **GoogleLoginButton** - Handles OAuth flow, stores JWT and generates ephemeral secp256k1 keypair
- **ProveJWTButton** - Creates ZK proof of JWT `sub` claim using Noir circuits
- **GenerateUserKeysButton** - Calls admin API to generate SyRA user keys
- **ProveJWTFinalVerifier** - Creates final verifier proof binding JWT, JWK, and keys
- **SyraSection** - Signs messages with SyRA keys and verifies signatures

#### ZK Libraries (`src/lib/zk/`)
- **jwt.ts** - Main JWT proof generation logic, handles Google JWK fetching
- **prover.ts** - SNARK proof generation using noir_js and snarkjs
- **final_verifier_jwt_proof.ts** - Final verifier proof generation
- **syra-signature.ts** - SyRA signature generation and verification
- **noir-circuits/** - Noir circuit definitions for JWT and SyRA proofs

### Technical Details

#### Buffer Polyfill
Next.js config includes webpack configuration to polyfill Buffer for browser:
- Uses `buffer` npm package
- Configured in `next.config.ts` via webpack fallback and ProvidePlugin

#### Storage
All proofs and keys are stored in localStorage for persistence across page refreshes.

#### Backend Integration
Expects admin service at `http://127.0.0.1:9000` with endpoint:
```
POST /admin/generate_user_key
Body: { user_id, kid, proof }
Response: { ivk, usk, usk_hat }
```

### Circuit Constants
- `NONCE_MAX_BYTES`: 66
- `ISSUER_MAX_BYTES`: 32  
- `AUDIENCE_MAX_BYTES`: 128
- `maxMessageLength`: 1344 (for JWT verification)