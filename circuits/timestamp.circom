pragma circom 2.1.4;

include "@zk-email/zk-regex-circom/circuits/regex_helpers.circom";

template Timestamp(max_json_bytes) {
    signal input msg[max_json_bytes];
    signal output out;

    var num_bytes = max_json_bytes + 1;
    signal in[num_bytes];
    in[0] <== 128;      // \x80 (sentinel for first character in string)
    for (var i = 0; i < max_json_bytes; i++) {
        in[i+1] <== msg[i];
    }
				
		component eq[6][num_bytes];
		component lt[4][num_bytes];
		component and[10][num_bytes];
		component multi_or[1][num_bytes];
		signal states[num_bytes+1][8];

		for (var i = 0; i < num_bytes; i++) {
						states[i][0] <== 1;
		}
		for (var i = 1; i < 8; i++) {
						states[0][i] <== 0;
		}

		for (var i = 0; i < num_bytes; i++) {
						lt[0][i] = LessThan(8);
						lt[0][i].in[0] <== 47;
						lt[0][i].in[1] <== in[i];
						lt[1][i] = LessThan(8);
						lt[1][i].in[0] <== in[i];
						lt[1][i].in[1] <== 58;
						and[0][i] = AND();
						and[0][i].a <== lt[0][i].out;
						and[0][i].b <== lt[1][i].out;
						and[1][i] = AND();
						and[1][i].a <== states[i][1];
						and[1][i].b <== and[0][i].out;
						lt[2][i] = LessThan(8);
						lt[2][i].in[0] <== 47;
						lt[2][i].in[1] <== in[i];
						lt[3][i] = LessThan(8);
						lt[3][i].in[0] <== in[i];
						lt[3][i].in[1] <== 58;
						and[2][i] = AND();
						and[2][i].a <== lt[2][i].out;
						and[2][i].b <== lt[3][i].out;
						and[3][i] = AND();
						and[3][i].a <== states[i][7];
						and[3][i].b <== and[2][i].out;
						multi_or[0][i] = MultiOR(2);
						multi_or[0][i].in[0] <== and[1][i].out;
						multi_or[0][i].in[1] <== and[3][i].out;
						states[i+1][1] <== multi_or[0][i].out;
						eq[0][i] = IsEqual();
						eq[0][i].in[0] <== in[i];
						eq[0][i].in[1] <== 34;
						and[4][i] = AND();
						and[4][i].a <== states[i][0];
						and[4][i].b <== eq[0][i].out;
						states[i+1][2] <== and[4][i].out;
						eq[1][i] = IsEqual();
						eq[1][i].in[0] <== in[i];
						eq[1][i].in[1] <== 101;
						and[5][i] = AND();
						and[5][i].a <== states[i][2];
						and[5][i].b <== eq[1][i].out;
						states[i+1][3] <== and[5][i].out;
						eq[2][i] = IsEqual();
						eq[2][i].in[0] <== in[i];
						eq[2][i].in[1] <== 120;
						and[6][i] = AND();
						and[6][i].a <== states[i][3];
						and[6][i].b <== eq[2][i].out;
						states[i+1][4] <== and[6][i].out;
						eq[3][i] = IsEqual();
						eq[3][i].in[0] <== in[i];
						eq[3][i].in[1] <== 112;
						and[7][i] = AND();
						and[7][i].a <== states[i][4];
						and[7][i].b <== eq[3][i].out;
						states[i+1][5] <== and[7][i].out;
						eq[4][i] = IsEqual();
						eq[4][i].in[0] <== in[i];
						eq[4][i].in[1] <== 34;
						and[8][i] = AND();
						and[8][i].a <== states[i][5];
						and[8][i].b <== eq[4][i].out;
						states[i+1][6] <== and[8][i].out;
						eq[5][i] = IsEqual();
						eq[5][i].in[0] <== in[i];
						eq[5][i].in[1] <== 58;
						and[9][i] = AND();
						and[9][i].a <== states[i][6];
						and[9][i].b <== eq[5][i].out;
						states[i+1][7] <== and[9][i].out;
		}

		signal final_state_sum[num_bytes+1];
		final_state_sum[0] <== states[0][7];
		for (var i = 1; i <= num_bytes; i++) {
						final_state_sum[i] <== final_state_sum[i-1] + states[i][7];
		}
		out <== final_state_sum[num_bytes];

    // reveals (cut the last character)
    signal output reveal[max_json_bytes];
    for (var i = 0; i < max_json_bytes; i++) {
        reveal[i] <== in[i] * states[i+1][1];
    }
}