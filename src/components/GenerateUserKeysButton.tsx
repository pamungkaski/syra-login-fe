'use client'

import { useState, useEffect, useCallback } from 'react'
import { generateUserKeys } from '@/lib/api/generate_user_key'      // adjust import path
import { GoogleJWTProofResult } from '@/lib/zk/jwt'

const PROOF_KEY = 'jwtProof'

interface UserKeyResponse {
  ivk: string
  usk: string
  usk_hat: string
}

export default function GenerateUserKeysButton() {
  const [proof, setProof] = useState<GoogleJWTProofResult | null>(null)
  const [ivk, setIvk] = useState<string | null>(null)
  const [usk, setUsk] = useState<string | null>(null)
  const [uskHat, setUskHat] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // 1) load proof and any existing keys from localStorage
  useEffect(() => {
    const rawProof = localStorage.getItem(PROOF_KEY)
    if (rawProof) {
      try {
        setProof(JSON.parse(rawProof))
      } catch {
        localStorage.removeItem(PROOF_KEY)
      }
    }
    setIvk(localStorage.getItem('ivk'))
    setUsk(localStorage.getItem('usk'))
    setUskHat(localStorage.getItem('usk_hat'))
  }, [])

  const handleGenerate = useCallback(async () => {
    if (!proof) return
    setError(null)
    setLoading(true)
    try {
      // proof.payload.sub is userId, proof.kid is the key ID
      const { ivk, usk, usk_hat }: UserKeyResponse =
          await generateUserKeys(proof.payload.sub, proof.kid, proof.subJWTProof)

      // persist keys
      localStorage.setItem('ivk', ivk)
      localStorage.setItem('usk', usk)
      localStorage.setItem('usk_hat', usk_hat)

      setIvk(ivk)
      setUsk(usk)
      setUskHat(usk_hat)
    } catch (err: any) {
      console.error(err)
      setError(err.message || 'Failed to generate keys')
    } finally {
      setLoading(false)
    }
  }, [proof])

  return (
      <div className="space-y-4">
        <button
            onClick={handleGenerate}
            disabled={!proof || loading}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
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
          {loading ? 'Generating Keys…' : 'Generate User Keys'}
        </button>

        {error && <p className="text-red-600">{error}</p>}

        {ivk && usk && uskHat && (
            <div className="space-y-2 bg-gray-50 p-4 rounded border w-full overflow-x-auto">
              <div>
                <strong>Issuer Verification Key (ivk):</strong>
                <pre className="font-mono text-sm whitespace-pre-wrap break-all">{ivk}</pre>
              </div>
              <div>
                <strong>User Signing Key (usk):</strong>
                <pre className="font-mono text-sm whitespace-pre-wrap break-all">{usk}</pre>
              </div>
              <div>
                <strong>User Signing Key Hat (usk_hat):</strong>
                <pre className="font-mono text-sm whitespace-pre-wrap break-all">{uskHat}</pre>
              </div>
            </div>
        )}
      </div>
  )
}
