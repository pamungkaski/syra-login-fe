# ZK part of Syra Login

/id_token/src/lib.nr <<< Contain ID Token Verification Relation, verify signature, validating aud iss and exp too, return sub inside the JWT

/shamir_secret_sharing/src/lib.nr <<< contain the reconstruction of shamir secret sharing of BN254 Field.

/src/main.nr <<< Main circuit, Call JWT verify, Call Shamir Reconstruct, Match sub from JWT and reconstructed secret.