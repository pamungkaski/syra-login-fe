'use client'
import GoogleLoginButton from '@/components/GoogleLoginButton'
import ProveJWTButton from '@/components/ProveJWTButton'
import ProveJWTFinalVerifier from '@/components/ProveJWTFinalVerifier'
import GenerateUserKeysButton from '@/components/GenerateUserKeysButton'
import SyraSection from '@/components/SyraSection'

export default function FeatureAuth() {
    return (
        <>
            <section className="min-h-screen flex flex-col items-center justify-center p-6">
                <h2 className="text-xl font-semibold mb-4">Sign in with Google</h2>
                <GoogleLoginButton />
            </section>

            <section className="min-h-screen flex flex-col items-center justify-center p-6">
                <h2 className="text-xl font-semibold mb-4">SNARK Proof of JWT</h2>
                <ProveJWTButton />
            </section>

            <section className="min-h-screen flex flex-col items-center justify-center p-6">
                <h2 className="text-xl font-semibold mb-4">Generate User Keys</h2>
                <GenerateUserKeysButton />
            </section>

            <section className="min-h-screen flex flex-col items-center justify-center p-6">
                <h2 className="text-xl font-semibold mb-4">SNARK Proof of JWT for Final Verifier</h2>
                <ProveJWTFinalVerifier />
            </section>

            <section className="min-h-screen flex flex-col items-center justify-center p-6">
                <h2 className="text-xl font-semibold mb-4">Generate User Keys</h2>
                <SyraSection />
            </section>
        </>
    )
}
