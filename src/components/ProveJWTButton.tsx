'use client'

import { useState, useEffect, useCallback } from 'react'
import { proveGoogleJWT, GoogleJWTProofResult } from '@/lib/zk/jwt'

const PROOF_KEY = 'jwtProof'
const TOKEN_KEY = 'idToken'

export default function ProveJWTButton() {
    const [jwt, setJwt] = useState<string | null>(null)
    const [proof, setProof] = useState<GoogleJWTProofResult | null>(null)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)

    // load initial JWT and any saved proof
    useEffect(() => {
        setJwt(localStorage.getItem(TOKEN_KEY))

        const saved = localStorage.getItem(PROOF_KEY)
        if (saved) {
            try {
                setProof(JSON.parse(saved))
            } catch {
                localStorage.removeItem(PROOF_KEY)
            }
        }
    }, [])

    const handleProve = useCallback(async () => {
        if (!jwt) return
        setError(null)
        setLoading(true)
        try {
            const result = await proveGoogleJWT(jwt)
            // persist proof
            localStorage.setItem(PROOF_KEY, JSON.stringify(result))
            setProof(result)
        } catch (err: any) {
            console.error(err)
            setError(err.message || 'Unknown error')
        } finally {
            setLoading(false)
        }
    }, [jwt])

    // JSON replacer that turns BigInt into string
    const serialize = (obj: any) =>
        JSON.stringify(obj, (_k, v) =>
            typeof v === 'bigint' ? v.toString() : v, 2
        )

    return (
        <div className="space-y-4">
            <button
                onClick={handleProve}
                disabled={!jwt || loading}
                className="flex items-center px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
            >
                {loading && (
                    <svg className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
                        <circle
                            className="opacity-25"
                            cx="12" cy="12" r="10"
                            stroke="currentColor" strokeWidth="4"
                        />
                        <path
                            className="opacity-75"
                            fill="currentColor"
                            d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
                        />
                    </svg>
                )}
                {loading ? 'Generating Proof...' : 'Prove JWT'}
            </button>

            {error && <p className="text-red-600">Error: {error}</p>}

            {proof && (
                <div className="space-y-4">
                    <div className="w-full max-h-64 overflow-auto border rounded bg-gray-100 p-4">
                        <h3 className="font-semibold mb-2">Sub‐JWT Proof</h3>
                        <pre className="text-sm font-mono whitespace-pre-wrap break-all">
              {serialize(proof.subJWTProof)}
            </pre>
                    </div>
            {/*        <div className="w-full max-h-64 overflow-auto border rounded bg-gray-100 p-4">*/}
            {/*            <h3 className="font-semibold mb-2">Non‐Sub‐JWT Proof</h3>*/}
            {/*            <pre className="text-sm font-mono whitespace-pre-wrap break-all">*/}
            {/*  {serialize(proof.nonSubJWTProof)}*/}
            {/*</pre>*/}
            {/*        </div>*/}
                </div>
            )}
        </div>
    )
}
