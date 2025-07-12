'use client'

import { useState } from 'react'
import { Buffer } from 'buffer'
import { generateCircomSignals } from '@/lib/zk/syra_input'    // adjust to your path
import { proveFromSignals, verifyFromProof, Proof } from '@/lib/zk/syra-signature'
import type { GoogleJWTProofResult } from '@/lib/zk/jwt'
import {FinialVerifierJWTProof} from "@/lib/zk/final_verifier_jwt_proof";

const PROOF_KEY = 'jwtProof'

export default function SyraSection() {
    const [message, setMessage] = useState('')
    const [syraProof, setSyraProof] = useState<Proof | null>(null)
    const [proving, setProving] = useState(false)
    const [verifying, setVerifying] = useState(false)
    const [verified, setVerified] = useState<boolean | null>(null)
    const [error, setError] = useState<string | null>(null)

    // Load nonSubJWTProof from localStorage
    const getJwtProof = (): GoogleJWTProofResult | null => {
        const raw = localStorage.getItem(PROOF_KEY)
        if (!raw) return null
        try { return JSON.parse(raw) } catch { return null }
    }

    const handleProve = async () => {
        setError(null)
        setVerified(null)
        setProving(true)
        try {
            const jwtProof = getJwtProof()
            if (!jwtProof) throw new Error('No JWT proof found')
            const ivk     = localStorage.getItem('ivk')!
            const usk     = localStorage.getItem('usk')!
            const usk_hat = localStorage.getItem('usk_hat')!
            const rawJWT  = localStorage.getItem('idToken')!
            const rawFinalVerifier  = localStorage.getItem('jwtFinalProof')!
            const finalVerifier: FinialVerifierJWTProof = JSON.parse(
                rawFinalVerifier,
                (_, v) => {
                    // recognise plain decimal strings (optionally allow "0x…" too)
                    return typeof v === 'string' && /^-?\d+$/.test(v) ? BigInt(v) : v;
                },
            );
            const publicKey = jwtProof.publicKey
            const claims    = jwtProof.payload

            // base64 of non-sub JWT proof
            // const proofJson = JSON.stringify(jwtProof.nonSubJWTProof.proof)
            // const proofB64  = Buffer.from(proofJson, 'utf8').toString('base64')


            // 1) generate witness signals
            const signals = await generateCircomSignals(
                ivk, usk, usk_hat,
                rawJWT, publicKey, claims,
                message
            )

            // 2) compute the Syra proof
            const P: Proof = proveFromSignals({
                ...signals,
                g3: finalVerifier.g3,
                g4: finalVerifier.g4,
                r: finalVerifier.r,
                bridge: finalVerifier.bridge,
            })
            setSyraProof(P)
        } catch (err: any) {
            console.error(err)
            setError(err.message || 'Failed to prove Syra')
        } finally {
            setProving(false)
        }
    }

    const handleVerify = () => {
        setError(null)
        setVerifying(true)
        try {
            if (!syraProof) throw new Error('No Syra proof to verify')
            const ok = verifyFromProof(syraProof)
            setVerified(ok)
        } catch (err: any) {
            console.error(err)
            setError(err.message || 'Verification error')
            setVerified(false)
        } finally {
            setVerifying(false)
        }
    }

    // serialize BigInts in the proof
    const serialize = (obj: any) =>
        JSON.stringify(obj, (_k, v) =>
            typeof v === 'bigint' ? v.toString() : v, 2
        )

    return (
        <div className="space-y-6">
            <div className="space-y-2">
                <label className="block font-medium">Message to Sign:</label>
                <input
                    type="text"
                    value={message}
                    onChange={e => setMessage(e.target.value)}
                    className="w-full p-2 border rounded"
                    placeholder="Enter your message"
                />
            </div>

            <button
                onClick={handleProve}
                disabled={!message || proving}
                className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50"
            >
                {proving ? 'Proving Syra…' : 'Prove Syra'}
            </button>

            {syraProof && (
                <div className="w-full max-h-64 overflow-auto border rounded bg-gray-100 p-4">
          <pre className="text-sm font-mono whitespace-pre-wrap break-all">
            {serialize(syraProof)}
          </pre>
                </div>
            )}

            <button
                onClick={handleVerify}
                disabled={!syraProof || verifying}
                className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
            >
                {verifying ? 'Verifying Syra…' : 'Verify Syra'}
            </button>

            {verified !== null && (
                <p className={verified ? 'text-green-600 font-semibold' : 'text-red-600 font-semibold'}>
                    {verified ? '✅ Proof is valid' : '❌ Proof is invalid'}
                </p>
            )}

            {error && <p className="text-red-600">{error}</p>}
        </div>
    )
}
