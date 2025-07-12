// components/GoogleLoginButton.tsx
'use client'

import { GoogleLogin, CredentialResponse } from '@react-oauth/google'
import {jwtDecode} from 'jwt-decode'
import { useState, useEffect } from 'react'
import { utils, getPublicKey } from '@noble/secp256k1'
import {bytesToHex, hexToBytes} from '@noble/hashes/utils'

interface DecodedToken {
    iss: string
    azp: string
    aud: string
    sub: string
    email: string
    email_verified: boolean
    at_hash: string
    nonce: string
    name: string
    picture: string
    given_name: string
    family_name: string
    iat: number
    exp: number
    // add any other fields you expect
}

export default function GoogleLoginButton() {
    const [user, setUser] = useState<DecodedToken | null>(null)
    const [idToken, setIdToken] = useState<string | null>(null)
    const [nonce, setNonce] = useState<string>('')
    const [privKey, setPrivKey] = useState<string>('')

    useEffect(() => {
        let privHex = localStorage.getItem('oauthEphPrivKey') || ''

        if (!privHex) {
            // 2) None found → generate a new one
            const privBytes = utils.randomPrivateKey()
            privHex = bytesToHex(privBytes)
            localStorage.setItem('oauthEphPrivKey', privHex)
        }

        // 3) Derive the public key (nonce) from privHex
        const privBytes = hexToBytes(privHex)
        const pubBytes = getPublicKey(privBytes)
        const pubHex = bytesToHex(pubBytes)

        setNonce(pubHex)
        setPrivKey(privHex)
    }, [])

    // On successful sign-in
    const handleSuccess = (res: CredentialResponse) => {
        if (res.credential) {
            // 1) Store the raw JWT
            localStorage.setItem('idToken', res.credential)
            setIdToken(res.credential)
            window.dispatchEvent(new Event('idTokenChanged'))

            // 2) Decode for display/UI state
            const decoded = jwtDecode<DecodedToken>(res.credential)
            setUser(decoded)
        }
    }

    const handleError = () => {
        console.error('Google Login Failed')
    }

    const handleLogout = () => {
        localStorage.removeItem('idToken')
        localStorage.removeItem('oauthEphPrivKey')
        localStorage.removeItem('jwtProof')
        setUser(null)
        setIdToken(null)
        setNonce('')
        setPrivKey('')
    }

    // On mount, restore any existing token
    useEffect(() => {
        const stored = localStorage.getItem('idToken')
        if (stored) {
            setIdToken(stored)
            try {
                const decoded = jwtDecode<DecodedToken>(stored)
                setUser(decoded)
            } catch {
                localStorage.removeItem('idToken')
            }
        }
    }, [])

    // If signed in, show user info + full JWT
    if (user && idToken) {
        return (
            <div className="space-y-4">
                <div className="flex items-center space-x-4">
                    <img src={user.picture} alt={user.name} className="w-8 h-8 rounded-full" />
                    <span className="font-medium">{user.name}</span>
                    <button
                        onClick={handleLogout}
                        className="px-3 py-1 bg-red-500 text-white rounded hover:bg-red-600"
                    >
                        Sign out
                    </button>
                </div>
                <div className="bg-gray-50 p-4 rounded border">
                    <h3 className="font-semibold mb-1">Ephemeral Keypair</h3>
                    <p className="text-sm font-mono break-all"><strong>Private:</strong> {privKey}</p>
                    <p className="text-sm font-mono break-all"><strong>Public (nonce):</strong> {nonce}</p>
                </div>
                <div>
                    <h3 className="font-semibold mb-1">Full ID Token (JWT):</h3>
                    <textarea
                        readOnly
                        value={idToken}
                        rows={6}
                        className="w-full p-2 border rounded resize-none font-mono text-sm"
                    />
                </div>
                 <div>
                   <h3 className="font-semibold mb-1">Decoded JWT Payload:</h3>
                   <pre className="w-full p-2 bg-gray-100 border rounded overflow-auto text-sm font-mono">
     {JSON.stringify(user, null, 2)}
                   </pre>
                 </div>
            </div>
        )
    }

    // If not signed in, show the Google button
    return (
        <GoogleLogin
            onSuccess={handleSuccess}
            onError={handleError}
            nonce={nonce}
            shape="rectangular"
            size="large"
        />
    )
}
