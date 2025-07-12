global MAX_SHARE: u32 = 3;
global SECRET_SHARE_T: u32 = 3;
global MAX_DATA_LENGTH: u32 = 900;
global MAX_ISSUER_LENGTH: u32 = 100;
global MAX_AUDIENCE_LENGTH: u32 = 100;
global MAX_SUB_LENGTH: u32 = 100;

fn single(
   // statement
   pubkey_modulus_limbs: pub [Field; 18],  // RSA modulus
   redc_params_limbs: pub [Field; 18],         // RSA reduction parameters
   sub_statement: pub BoundedVec<u8, MAX_SUB_LENGTH>, // sub for jwt
   domain: pub BoundedVec<u8, MAX_AUDIENCE_LENGTH>, // Expected audience
   issuer: pub BoundedVec<u8, MAX_ISSUER_LENGTH>,  // Expected issuer

   //witness
   data: BoundedVec<u8, MAX_DATA_LENGTH>,  // Encoded JWT token
   signature_limbs: [Field; 18],           // RSA signature
   b64_offset: u32                        // Base64 offset for signature
   current_time: u64,                     // Current timestamp
) {
    let sub = id_token::verify(
        data,
        b64_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
        domain,
        issuer,
        current_time
    );


    assert(sub == sub_statement, "sub doesnt match");
}


