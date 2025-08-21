'use client'

import { useState, useEffect, useCallback } from 'react'
import {
    FinialVerifierJWTProof,
    Verify,
} from '@/lib/zk/final_verifier_jwt_proof'

/**
 * localStorage key where the *final* ZK‑proof is persisted by
 * `ProveJWTFinalVerifier.tsx`.
 */
const FINAL_KEY = 'jwtFinalProof'

/**
 * ————————————————————————————————————————————————————————————
 * Helpers
 * ————————————————————————————————————————————————————————————
 */

/**
 * Reviver for `JSON.parse` that
 *   • restores `bigint` values (numeric strings → BigInt)
 *   • turns any numeric‑keyed object → *plain* array (temporarily)
 */
function revive(_k: string, v: any): any {
    // 1. "123456…" → BigInt(123456…)
    if (typeof v === 'string' && /^\d+$/.test(v)) {
        try {
            return BigInt(v)
        } catch {
            /* silent fall‑through: leave as string on overflow (unlikely) */
        }
    }

    // 2. {"0": …, "1": …} → [ …, … ]
    if (v && typeof v === 'object' && !Array.isArray(v)) {
        const keys = Object.keys(v)
        if (keys.length && keys.every((k) => /^\d+$/.test(k))) {
            return keys
                .sort((a, b) => Number(a) - Number(b))
                .map((k) => v[k])
        }
    }

    return v
}

/** Ensures the deeply‑nested `proof.proof` field is a *Uint8Array*. */
function normaliseProofStructure(proof: FinialVerifierJWTProof): FinialVerifierJWTProof {
    // Defensive clone so we don’t mutate the original reference (React sanity)
    const out: any = structuredClone(proof)

    // Bail early if already correct
    if (out?.proof?.proof instanceof Uint8Array) return out

    // Helper: whatever ↦ Uint8Array
    const toU8 = (val: any): Uint8Array => {
        if (val instanceof Uint8Array) return val

        // Accept array‑likes with numbers/bigints/strings
        if (Array.isArray(val)) {
            return Uint8Array.from(val.map((n) => Number(n)))
        }

        // Object map → array first
        if (val && typeof val === 'object') {
            const keys = Object.keys(val).filter((k) => /^\d+$/.test(k)).sort((a, b) => Number(a) - Number(b))
            if (keys.length) return Uint8Array.from(keys.map((k) => Number(val[k])))
        }

        // Fallback: empty
        return new Uint8Array()
    }

    if (out?.proof && 'proof' in out.proof) {
        out.proof.proof = toU8(out.proof.proof)
    }

    return out as FinialVerifierJWTProof
}

/**
 * ————————————————————————————————————————————————————————————
 * Component
 * ————————————————————————————————————————————————————————————
 */
export default function VerifyJWTFinalVerifier() {
    const [finalProof, setFinalProof] = useState<FinialVerifierJWTProof | null>(null)
    const [verified, setVerified] = useState<boolean | null>(null)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)

    // On mount: read, revive & normalise
    useEffect(() => {
        const raw = localStorage.getItem(FINAL_KEY)
        if (!raw) return

        try {
            const revived = JSON.parse(raw, revive)
            const normalised = normaliseProofStructure(revived)
            setFinalProof(normalised)
        } catch (e) {
            console.error('Failed to restore proof', e)
            localStorage.removeItem(FINAL_KEY)
        }
    }, [])

    // Click → verify
    const handleVerify = useCallback(async () => {
        if (!finalProof) return

        setLoading(true)
        setError(null)
        setVerified(null)

        try {
            const ok = await Verify(finalProof.proof)
            setVerified(ok)
        } catch (err: any) {
            console.error(err)
            setError(err.message || 'Unknown error')
        } finally {
            setLoading(false)
        }
    }, [finalProof])

    const disabled = !finalProof || loading

    return (
        <div className="space-y-4">
            <button
                onClick={handleVerify}
                disabled={disabled}
                className="flex items-center px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
            >
                {loading && (
                    <svg className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
                    </svg>
                )}
                {loading ? 'Verifying…' : 'Verify Proof'}
            </button>

            {!finalProof && (
                <p className="text-yellow-600">No final proof found. Generate it first.</p>
            )}

            {error && <p className="text-red-600">Error: {error}</p>}

            {verified !== null && (
                <p className={verified ? 'text-green-700' : 'text-red-700'}>
                    {verified ? 'Proof is valid ✅' : 'Proof failed ❌'}
                </p>
            )}
        </div>
    )
}
