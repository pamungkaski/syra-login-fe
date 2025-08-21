pragma circom 2.1.6;
include "node_modules/@zk-email/jwt-tx-builder-circuits/jwt-verifier.circom";

include "node_modules/@zk-email/circuits/helpers/reveal-substring.circom";
include "node_modules/@zk-email/email-tx-builder-circom/src/utils/bytes2ints.circom";
include "node_modules/@zk-email/email-tx-builder-circom/src/utils/digit2int.circom";

include "node_modules/@zk-email/jwt-tx-builder-circuits/utils/constants.circom";

/// from @zk-email/jwt-tx-builder-circuits/helpers/fields.circom
template ExtractSub(maxPayloadLength) {
    signal input payload[maxPayloadLength];
    signal input subKeyStartIndex;

    signal output sub;

    // Verify if the key `sub` in the payload is unique
    var subKeyLength = SUB_KEY_LENGTH();
    var subKey[subKeyLength] = SUB_KEY();
    signal subKeyMatch[subKeyLength] <== RevealSubstring(maxPayloadLength, subKeyLength, 1)(payload, subKeyStartIndex, subKeyLength);
    for (var i = 0; i < subKeyLength; i++) {
        subKeyMatch[i] === subKey[i];
    }

    // Reveal the sub
    signal subStartIndex <== subKeyStartIndex + SUB_KEY_LENGTH() + 1;
    signal subMatch[SUB_VALUE_LENGTH()] <== RevealSubstring(maxPayloadLength, SUB_VALUE_LENGTH(), 0)(payload, subStartIndex, SUB_VALUE_LENGTH());
    sub <== Digit2Int(SUB_VALUE_LENGTH())(subMatch);
}


template VerifyJWT() {
    signal input message[1344];
    signal input messageLength;   // your padded length (e.g. 832)
    signal input pubkey[17];
    signal input signature[17];
    signal input periodIndex;
    signal input subKeyStartIndex;
    signal input subStatement;

    signal output sub;

    component verifier = JWTVerifier(121, 17, 1344, 256, 1344);

    for (var i = 0; i < 1344; i++) {
        verifier.message[i] <== message[i];
    }
    // Use the real padded length now
    verifier.messageLength <== messageLength;

    for (var i = 0; i < 17; i++) {
        verifier.pubkey[i]     <== pubkey[i];
        verifier.signature[i]  <== signature[i];
    }
    verifier.periodIndex <== periodIndex;

    var maxPayloadLength = (1344 * 3) \ 4;

    signal payload[maxPayloadLength] <== verifier.payload;

    component extractSub = ExtractSub(maxPayloadLength);
    extractSub.payload <== payload;
    extractSub.subKeyStartIndex <== subKeyStartIndex;
    sub <== extractSub.sub;


    log(sub);
    log(subStatement);
    sub === subStatement;
}

component main { public [pubkey, subStatement] } = VerifyJWT();
