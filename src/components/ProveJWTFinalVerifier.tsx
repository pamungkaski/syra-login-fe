'use client'

import { useState, useEffect, useCallback } from 'react'
import { proveGoogleJWTFinalVerifier, FinialVerifierJWTProof } from '@/lib/zk/final_verifier_jwt_proof'
import {GoogleJWTProofResult} from "@/lib/zk/jwt";

const TOKEN_KEY         = 'idToken'
const INTERMEDIATE_KEY  = 'jwtProof'        // your first proof with .publicKey & .claims
const FINAL_KEY         = 'jwtFinalProof'   // where we’ll store the final proof

export default function ProveJWTFinalVerifier() {
    const [jwt, setJwt]                   = useState<string | null>(null)
    const [intermediate, setIntermediate] = useState<GoogleJWTProofResult | null>(null)
    const [finalProof, setFinalProof]     = useState<FinialVerifierJWTProof | null>(null)
    const [loading, setLoading]           = useState(false)
    const [error, setError]               = useState<string | null>(null)

    // on mount: load raw JWT, intermediate proof, and any existing final-proof
    useEffect(() => {
        setJwt(localStorage.getItem(TOKEN_KEY))

        const rawIntermediate = localStorage.getItem(INTERMEDIATE_KEY)
        if (rawIntermediate) {
            setIntermediate(JSON.parse(rawIntermediate));
        }

        const rawFinal = localStorage.getItem(FINAL_KEY)
        if (rawFinal) {
            try {
                setFinalProof(JSON.parse(rawFinal))
            } catch {
                localStorage.removeItem(FINAL_KEY)
            }
        }
    }, [])

    const handleClick = useCallback(async () => {
        if (!jwt || !intermediate) return

        const { jwk, payload: claims } = intermediate
        if (!jwk || !claims) {
            setError('Intermediate proof missing publicKey or claims')
            return
        }

        setError(null)
        setLoading(true)
        try {
            const result = await proveGoogleJWTFinalVerifier(jwt, jwk, claims)
            localStorage.setItem(
                FINAL_KEY,
                JSON.stringify(result, (_, v) =>
                    typeof v === 'bigint' ? v.toString() : v   // BigInt → decimal string
                ),
            );
            setFinalProof(result)
        } catch (err: any) {
            console.error(err)
            setError(err.message || 'Unknown error')
        } finally {
            setLoading(false)
        }
    }, [jwt, intermediate])

    const serialize = (obj: any) =>
        JSON.stringify(obj, (_k, v) =>
            typeof v === 'bigint' ? v.toString() : v, 2
        )

    const disabled = !jwt || !intermediate || loading

    return (
        <div className="space-y-4">
            <button
                onClick={handleClick}
                disabled={disabled}
                className="flex items-center px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-700 disabled:opacity-50"
            >
                {loading && (
                    <svg className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"/>
                    </svg>
                )}
                {loading ? 'Generating Final Proof…' : 'Generate Final Proof'}
            </button>

            {!jwt && <p className="text-yellow-600">No JWT found. Run the initial flow.</p>}
            {!intermediate && <p className="text-yellow-600">No intermediate proof. Run the first proof.</p>}
            {error && <p className="text-red-600">Error: {error}</p>}

            {finalProof && (
                <div className="border rounded bg-gray-100 p-4 max-h-64 overflow-auto">
                    <h3 className="font-semibold mb-2">Final Verifier Proof</h3>
                    <pre className="text-sm font-mono whitespace-pre-wrap break-all">
            {serialize(finalProof)}
          </pre>
                </div>
            )}
        </div>
    )
}
