import { wasm as wasm_tester } from "circom_tester";
import { Scalar } from "ffjavascript";
import path from "path";

import { ICircuitInputs, generate_inputs } from "../../scripts/generate_input";

exports.p = Scalar.fromString(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

describe("RSA", () => {
  jest.setTimeout(10 * 60 * 1000); // 10 minutes

  let circuit: any;
  // let dkimResult: DKIMVerificationResult;

  beforeAll(async () => {
    circuit = await wasm_tester(
      path.join(__dirname, "../jwt.circom"),
      {
        // @dev During development recompile can be set to false if you are only making changes in the tests.
        // This will save time by not recompiling the circuit every time.
        // Compile: circom "./tests/email-verifier-test.circom" --r1cs --wasm --sym --c --wat --output "./tests/compiled-test-circuit"
        recompile: true,
        output: path.join(__dirname, "./compiled-test-circuit"),
        include: path.join(__dirname, "../../../node_modules"),
      }
    );
  });

  it("should verify rsa signature correctly", async function () {
    const emailVerifierInputs: ICircuitInputs = await generate_inputs();

    const witness = await circuit.calculateWitness({
      ...emailVerifierInputs,
      // message[max_msg_bytes],
      // modulus[k],
      // signature[k],
      // message_padded_bytes,
      // period_idx,
      // domain_idx,
      // time_idx,
      // time,
    });
    await circuit.checkConstraints(witness);
    await circuit.assertOut(witness, {})
  });

  // it("should fail verifing incorrect rsa signature", async function () {
  //   const emailVerifierInputs: ICircuitInputs = await generate_inputs();

  //   const witness = await circuit.calculateWitness({
  //     ...emailVerifierInputs,
  //     time_idx: "1",
  //     // message[max_msg_bytes],
  //     // modulus[k],
  //     // signature[k],
  //     // message_padded_bytes,
  //     // period_idx,
  //     // domain_idx,
  //     // time_idx,
  //     // time,
  //   });
  //   await circuit.checkConstraints(witness);
  //   await circuit.assertOut(witness, {})
  // });
});
