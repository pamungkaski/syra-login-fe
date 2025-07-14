# SyRA Login – Noir Circuits

This directory bundles the **Noir** programs that generate the proofs consumed by the SyRA Login front‑end and issuer service.  The circuits compile with **Noir ≥ 0.20** and Nargo, then export to **R1CS / ACIR** for proving with Barretenberg or SnarkJS.

---

## Circuit catalogue

| Package (crate)             | Type  | Purpose                                                                                                                                                                                                                                                                                |
| --------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **id\_token**               | `lib` | Parses and verifies a Google ID token: checks RSA‑2048 signature, `iss`, `aud`, `exp` and returns the `sub` claim as a `BoundedVec` ([raw.githubusercontent.com](https://raw.githubusercontent.com/pamungkaski/syra-login-fe/main/src/lib/zk/noir-circuits/id_token/src/lib.nr))       |
| **shamir\_secret\_sharing** | `lib` | Reconstructs a secret from *T* Shamir shares with Lagrange interpolation in the prime field ([raw.githubusercontent.com](https://raw.githubusercontent.com/pamungkaski/syra-login-fe/main/src/lib/zk/noir-circuits/shamir_secret_sharing/src/lib.nr))                                  |
| **syra\_login** (root)      | `bin` | Entry circuit `src/main.nr` – wraps **id\_token**, converts `sub` to a scalar, and proves that `s·G₃ + r·G₄ = bridge` on the BN254 embedded curve ([raw.githubusercontent.com](https://raw.githubusercontent.com/pamungkaski/syra-login-fe/main/src/lib/zk/noir-circuits/src/main.nr)) |

---

## Repository layout

```
noir-circuits/
├─ Nargo.toml               # root package (syra_login) ([raw.githubusercontent.com](https://raw.githubusercontent.com/pamungkaski/syra-login-fe/main/src/lib/zk/noir-circuits/Nargo.toml))
├─ src/
│   └─ main.nr              # entry circuit (syra_login)
├─ id_token/
│   ├─ Nargo.toml           # crate metadata ([raw.githubusercontent.com](https://raw.githubusercontent.com/pamungkaski/syra-login-fe/main/src/lib/zk/noir-circuits/id_token/Nargo.toml))
│   └─ src/lib.nr           # token verifier circuit
└─ shamir_secret_sharing/
    └─ src/lib.nr           # Shamir reconstruction
```

---

## Prerequisites

* **Rust** tool‑chain (for `nargo` install)
* `cargo install nargo`
* **Barretenberg** prover

Optional: `docker compose up circuits` if you use the repo’s dev‑container.

---

## Building & proving

```bash
# 1. Compile → ACIR
nargo compile  # outputs target/...

# 2. Generate proving and verification keys (Groth16)
#    Note: --protocol can be changed to plonk if supported
nargo setup

# 3. Create a witness file (input.json → witness.tr)
#    You can generate the JSON from the FE helper "buildCircuitInput()"
nargo execute witness.json

# 4. Produce a proof
nargo prove

# 5. Verify
nargo verify
```

### Witness schema (syra\_login)

```jsonc
{
  "pubkey_modulus_limbs": ["0x...", 18 items],
  "redc_params_limbs":    ["0x...", 18 items],
  "domain": "syra.example",
  "issuer": "https://accounts.google.com",
  "g3": { "x": "0x...", "y": "0x..." },
  "g4": { "x": "0x...", "y": "0x..." },
  "bridge": { "x": "0x...", "y": "0x..." },
  "data": "<raw JWT bytes>",
  "signature_limbs": ["0x...", 18 items],
  "base64_decode_offset": 1244,
  "current_time": 1720886400,
  "r": "0x..." // random nonce
}
```

> **Tip:** The front‑end generates the limbs and offsets automatically via `constructCircuitInput()`; export them from browser dev‑tools.

---

## Integration points

* **Front‑end:** `src/lib/zk/*` wraps these circuits with `noir_js`, compiles on‑demand and returns proofs to React components.
* **Issuer (Rust):** verifies Groth16 proof produced by **syra\_login** before minting user keys.

---

## Testing

The folder includes a minimal `nargo test` that runs the **id\_token** verifier against a mocked JWT and RSA key.  Use `NARGO_TEST_CURRENT_TIME` to control the timestamp.

---

## Roadmap

* [ ] Swap Groth16 for **PLONK** once Barretenberg stabilises its verifier gadget.
* [ ] Benchmarks for proof size and constraint count.
* [ ] Integrate **Poseidon‑based** Shamir hashing for better recursion.

Pull requests and issues are welcome – especially if you can provide a cleaner witness builder!
