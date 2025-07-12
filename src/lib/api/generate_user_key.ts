interface UserKeyResponse {
    ivk: string;
    usk: string;
    usk_hat: string;
}

export async function generateUserKeys(
    userId: string,
    kid: string,
    subJWTProof: Record<string, any>
): Promise<UserKeyResponse> {
    const proofJson = JSON.stringify(subJWTProof.proof);
    const proofB64 = Buffer.from(proofJson, "utf8").toString("base64");

    const res = await fetch("http://127.0.0.1:9000/admin/generate_user_key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            user_id: userId,
            kid,
            proof: proofB64,
        }),
    });

    if (!res.ok) {
        const errText = await res.text();
        throw new Error(`generate_user_key failed (${res.status}): ${errText}`);
    }

    return (await res.json()) as UserKeyResponse;
}
