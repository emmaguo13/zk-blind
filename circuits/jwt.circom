pragma circom 2.0.3;

include "../node_modules/circomlib/circuits/bitify.circom";
include "./sha.circom";
include "./rsa.circom";
include "./base64.circom";

// k - bignum
template JWTVerify(max_msg_bytes, n, k) {
    // signal input in_padded[max_header_bytes]; // prehashed email data, includes up to 512 + 64? bytes of padding pre SHA256, and padded with lots of 0s at end after the length
    signal input message[max_msg_bytes]; // TODO: header + . + payload. idk if it's k, we should pad this in javascript beforehand
    signal input modulus[k]; // rsa pubkey, verified with smart contract + optional oracle
    signal input signature[k];

    // signal input in_len_padded_bytes; // length of in email data including the padding, which will inform the sha256 block length
    signal input message_padded_bytes; // length of the message including the padding

    signal input address;
    signal input address_plus_one;

    var max_domain_len = 30;
    var max_domain_packed_bytes = (max_domain_len - 1) \ 7 + 1; // ceil(max_num_bytes / 7)

    signal input email_idx; // indexx of email domain in message
    signal input reveal_email[max_domain_len][max_msg_bytes];
    signal output reveal_email_packed[max_domain_packed_bytes];

    // *********** hash the padded message ***********
    component sha = Sha256Bytes(max_msg_bytes);
    for (var i = 0; i < max_msg_bytes; i++) {
        sha.in_padded[i] <== message[i];
    }
    sha.in_len_padded_bytes <== message_padded_bytes;

    var msg_len = (256+n)\n;
    component base_msg[msg_len];
    for (var i = 0; i < msg_len; i++) {
        base_msg[i] = Bits2Num(n);
    }
    for (var i = 0; i < 256; i++) {
        base_msg[i\n].in[i%n] <== sha.out[255 - i];
    }
    for (var i = 256; i < n*msg_len; i++) {
        base_msg[i\n].in[i%n] <== 0;
    }

    // *********** verify signature for the message *********** 
    component rsa = RSAVerify65537(n, k);
    for (var i = 0; i < msg_len; i++) {
        rsa.base_message[i] <== base_msg[i].out;
    }
    for (var i = msg_len; i < k; i++) {
        rsa.base_message[i] <== 0;
    }
    for (var i = 0; i < k; i++) {
        rsa.modulus[i] <== modulus[i];
    }
    for (var i = 0; i < k; i++) {
        rsa.signature[i] <== signature[i];
    }

    // // TODO: N for Base64Decode
    // component message_b64 = Base64Decode(1688);
    // for (var i = 0; i < max_msg_bytes; i++) {
    //     message_b64.in[i] <== message[i];
    // }

    // /* ensures signature is type jwt */
    // component type_jwt_regex = HeaderType(max_msg_bytes);
    // for (var i = 0; i < max_msg_bytes; i++) {
    //     type_jwt_regex.msg[i] <== message_b64[i];
    // }
    // type_jwt_regex.out === 1;
    // log(type_jwt_regex.out); 

    // /* ensures an email in json found */
    // component email_regex = payloadEmail(max_msg_bytes);
    // for (var i = 0; i < max_msg_bytes; i++) {
    //     email_regex.msg[i] <== message_b64[i];
    // }
    // email_regex.out === 1;
    // log(email_regex.reveal);

    // // isolate where email domain index is
    // component email_eq[max_msg_bytes];
    // for (var i = 0; i < max_msg_bytes; i++) {
    //     email_eq[i] = IsEqual();
    //     email_eq[i].in[0] <== i;
    //     email_eq[i].in[i] <== email_idx;
    // }

    // // shifts email domain to start of string
    // for (var j = 0; j < max_domain_len; j++) {
    //     reveal_email[j][j] <== email_eq[j].out * email_regex.reveal[j];
    //     for (var i = j + 1; i < max_msg_bytes; i++) {
    //         reveal_email[j][i] <== reveal_email[j][i - 1] + email_eq[i-j].out * email_regex.reveal[i];
    //     }
    // }

    // // Pack output for solidity verifier to be < 24kb size limit
    // // chunks = 7 is the number of bytes that can fit into a 255ish bit signal
    // var chunks = 7;
    // component packed_email_output[max_email_packed_bytes];
    // for (var i = 0; i < max_email_packed_bytes; i++) {
    //     packed_email_output[i] = Bytes2Packed(chunks);
    //     for (var j = 0; j < chunks; j++) {
    //         var reveal_idx = i * chunks + j;
    //         if (reveal_idx < max_body_bytes) {
    //             packed_email_output[i].in[j] <== reveal_email[i * chunks + j][max_body_bytes - 1];
    //         } else {
    //             packed_email_output[i].in[j] <== 0;
    //         }
    //     }
    //     reveal_email_packed[i] <== packed_email_output[i].out;
    //     log(reveal_email_packed[i]);
    // }

    // component packed_output[max_packed_bytes];
    // for (var i = 0; i < max_packed_bytes; i++) {
    //     packed_output[i] = Bytes2Packed(chunks);
    //     for (var j = 0; j < chunks; j++) {
    //         var reveal_idx = i * chunks + j;
    //         if (reveal_idx < max_header_bytes) {
    //             packed_output[i].in[j] <== reveal[i * chunks + j];
    //         } else {
    //             packed_output[i].in[j] <== 0;
    //         }
    //     }
    //     reveal_packed[i] <== packed_output[i].out;
    // }

}

// In circom, all output signals of the main component are public (and cannot be made private), the input signals of the main component are private if not stated otherwise using the keyword public as above. The rest of signals are all private and cannot be made public.
// This makes modulus and reveal_email_packed public. hash(signature) can optionally be made public, but is not recommended since it allows the mailserver to trace who the offender is.

component main { public [ modulus, address ] } = JWTVerify(1024, 121, 17);
