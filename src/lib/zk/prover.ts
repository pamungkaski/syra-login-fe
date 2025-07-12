// src/lib/zk/prover.ts
import * as snarkjs from 'snarkjs'
import builderSub from './jwt_js/witness_calculator.js'
import builderNonSub from './syra-login_js/witness_calculator.js'
import { get, set } from 'idb-keyval'

export interface ProofResult {
    proof: snarkjs.Groth16Proof
    publicSignals: string[]
}

/**
 * Fetches and caches a Uint8Array asset at `url` under `cacheKey`.
 */
async function loadCachedAsset(cacheKey: string, url: string): Promise<Uint8Array> {
    // 1) Try to get from IndexedDB
    const cached = await get<Uint8Array>(cacheKey)
    if (cached) {
        return cached
    }
    // 2) Otherwise fetch it
    const res = await fetch(url)
    if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`)
    const buffer = await res.arrayBuffer()
    const bytes = new Uint8Array(buffer)
    // 3) Cache for next time
    await set(cacheKey, bytes)
    return bytes
}

export async function proveJWTSub(input: Record<string, any>): Promise<ProofResult> {
    // load wasm and zkey, cached in IndexedDB
    const wasmBytes = await loadCachedAsset('jwt-wasm', '/jwt_js/jwt.wasm')
    const zkeyBytes = await loadCachedAsset('jwt-zkey', '/jwt_0001.zkey')

    // build witness calculator and proof as before
    const wc = await builderSub(wasmBytes)
    const wtnsBin = await wc.calculateWTNSBin(input, false)
    const { proof, publicSignals } = await snarkjs.groth16.prove(zkeyBytes, wtnsBin)

    return { proof, publicSignals }
}

export async function proveJWTNonSub(input: Record<string, any>): Promise<ProofResult> {
    const wasmBytes = await loadCachedAsset('nonSub-wasm', '/syra-login_js/syra-login.wasm')
    const zkeyBytes = await loadCachedAsset('nonSub-zkey', '/syra_0001.zkey')

    const wc = await builderNonSub(wasmBytes)
    const wtnsBin = await wc.calculateWTNSBin(input, false)
    const { proof, publicSignals } = await snarkjs.groth16.prove(zkeyBytes, wtnsBin)

    return { proof, publicSignals }
}
