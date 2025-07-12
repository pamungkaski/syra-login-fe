use dep::jwt::JWT;

global MAX_DATA_LENGTH: u32 = 1344;
global MAX_SUB_LENGTH: u32 = 100;
global MAX_ISSUER_LENGTH: u32 = 100;
global MAX_AUDIENCE_LENGTH: u32 = 100;
global MAX_NONCE_LENGTH: u32 = 32;
global MAX_VALUE_LENGTH: u32 = 100;

pub fn verify(
    data: BoundedVec<u8, MAX_DATA_LENGTH>,  // Encoded JWT token
    b64_offset: u32,                        // Base64 offset for signature
    pubkey_modulus_limbs: [u128; 18],  // RSA modulus
    redc_params_limbs: [u128; 18],         // RSA reduction parameters
    signature_limbs: [u128; 18],           // RSA signature
    domain: BoundedVec<u8, MAX_AUDIENCE_LENGTH>, // Expected audience
    issuer: BoundedVec<u8, MAX_ISSUER_LENGTH>,  // Expected issuer
    current_time: u64                     // Current timestamp
) -> BoundedVec<u8, MAX_SUB_LENGTH> { // Returning sub as output

    let jwt = JWT::init(
        data,
        b64_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );
    jwt.verify(); // Ensure signature is valid

    jwt.assert_claim_string(
        "iss".as_bytes(),
        issuer
    );

    jwt.assert_claim_string(
        "aud".as_bytes(),
        domain
    );

    let jwt_exp: u64 = jwt.get_claim_number("exp".as_bytes());
    assert(current_time < jwt_exp, "JWT has expired");

    let sub: BoundedVec<u8, MAX_SUB_LENGTH> = jwt.get_claim_string("sub".as_bytes());

    sub
}
