pragma circom 2.1.5;

// Circuits originally 1159565
include "./base64.circom"; // Adds 2046 constraints
include "@zk-email/circuits/helpers/sha.circom";
include "@zk-email/circuits/helpers/rsa.circom";
include "@zk-email/circuits/helpers/extract.circom"; // For VarShiftLeft and VarShiftMaskedStr
include "./jwt_email_regex.circom";
include "./jwt_type_regex.circom";
include "./ascii.circom";
include "./timestamp.circom";

template JWTVerify(max_msg_bytes, max_json_bytes, n, k) {
    signal input message[max_msg_bytes];
    signal input modulus[k]; // rsa pubkey
    signal input signature[k];

    signal input message_padded_bytes; // length of the message including the padding

    signal input period_idx; // index of the period in the base64 encoded msg
    var max_domain_len = 30;
    var max_timestamp_len = 10;

    signal reveal_timestamp[max_timestamp_len][max_json_bytes];

    signal input domain_idx; // index of email domain in message
    // signal input domain[max_domain_len]; // input domain with padding
    signal reveal_email[max_domain_len][max_json_bytes]; // reveals found email domain

    signal input time_idx; // index of expiration timestamp
    signal input time;

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

    // decode to JSON format
    component message_b64 = Base64Decode(max_json_bytes);
    component eqs[max_msg_bytes];
    signal int[max_msg_bytes];

    for (var i = 0; i < max_msg_bytes - 1; i++) {
        eqs[i] = GreaterEqThan(15);
        eqs[i].in[0] <== i;
        eqs[i].in[1] <== period_idx;

        var i_plus_one = eqs[i].out;
        var i_normal = 1 - eqs[i].out;

        int[i] <== (message[i] * i_normal);
        message_b64.in[i] <== (message[i + 1] * (i_plus_one)) + int[i];
    }
    message_b64.in[max_msg_bytes - 1] <== 0;

    /************************** JWT REGEXES *****************************/

    /* ensures signature is type jwt */
    // component type_jwt_regex = MessageType(max_json_bytes);
    // for (var i = 0; i < max_json_bytes; i++) {
    //     type_jwt_regex.msg[i] <== message_b64.out[i];
    // }
    // type_jwt_regex.out === 1;

    // /* ensures an email in json found */
    component email_regex = EmailDomain(max_json_bytes);
    for (var i = 0; i < max_json_bytes; i++) {
        email_regex.msg[i] <== message_b64.out[i];
    }
    email_regex.out === 1;

    // From 20K constraints to 13K constraints
    signal output domain[max_domain_len] <== VarShiftMaskedStr(max_json_bytes, max_domain_len)(email_regex.reveal0, domain_idx);

    // check expiration date is found
    // Updating this regex reduced it 8K, from 1,112,569 to 1,104,851 constraints
    component time_regex = Timestamp(max_json_bytes);
    for (var i = 0; i < max_json_bytes; i++) {
        time_regex.msg[i] <== message_b64.out[i];
    }
    time_regex.out === 1;

    // isolate where expiration index is
    component exp_eq[max_json_bytes];
    for (var i = 0; i < max_json_bytes; i++) {
        exp_eq[i] = IsEqual();
        exp_eq[i].in[0] <== i;
        exp_eq[i].in[1] <== time_idx;
    }
    // shifts timestamp to start of string
    for (var j = 0; j < max_timestamp_len; j++) {
        reveal_timestamp[j][j] <== exp_eq[j].out * time_regex.reveal[j];
        for (var i = j + 1; i < max_json_bytes; i++) {
            reveal_timestamp[j][i] <== reveal_timestamp[j][i - 1] + exp_eq[i-j].out * time_regex.reveal[i];
        }
    }

    // convert to number
    component time_num = AsciiToNum(max_timestamp_len);
    // signal time_reveal[max_timestamp_len] <== VarShiftMaskedStr(max_json_bytes, max_timestamp_len)(time_regex.reveal, time_idx);
    // time_num.in <== time_reveal;
    // <== VarShiftMaskedStr(max_json_bytes, max_timestamp_len)(reveal_timestamp, time_idx);
    for (var j = 0; j < max_timestamp_len; j++) {
        time_num.in[j] <== reveal_timestamp[j][max_json_bytes -1];
    }

    signal exp_time <== time_num.out + 86400;
    // check that the current time is less than a day after the expiration date
    component less_exp_time = LessThan(34);
    less_exp_time.in[0] <== time;
    less_exp_time.in[1] <== exp_time;

    less_exp_time.out === 1;
}

component main { public [ modulus, time ] } = JWTVerify(1024, 766, 121, 17);
