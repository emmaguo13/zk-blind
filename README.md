# zk-blind

post anonymous confessions about your work place / organization in zero-knowledge!

`yarn` to install all dependencies.

## generate inputs

to generate inputs into `jwt.json`, replace `signature`, `msg`, and `ethAddress` in `node-ts scripts/gen_inputs.ts`. currently, this file will only generate inputs for OpenAI JWTs, but feel free to add more public keys to support JWTs from different sites.
```
node-ts scripts/gen_inputs.ts
``` 

## circuits 

These circuits check for (1) valid rsa signature, (2) that the message is a JWT, (3) ownership of a specific email domain, and (4) JWT expiration.

compile circuits in root project directory.
```
./shell_scripts/1_compile.sh
```

generate witness
```
./shell_scripts/2_gen_wtns.sh
```

generate chunked zkeys
```
./shell_scripts/3_gen_chunk_zkey.sh
```

phase 2 and getting full zkey + vkey
```
snarkjs groth16 setup ./build/jwt/jwt.r1cs ./circuits/powersOfTau28_hez_final_22.ptau ./build/jwt/jwt_single.zkey

snarkjs zkey contribute ./build/jwt/jwt_single.zkey ./build/jwt/jwt_single1.zkey --name="1st Contributor Name" -v

snarkjs zkey export verificationkey ./build/jwt/jwt_single1.zkey ./build/jwt/verification_key.json

```

generate proof
```
snarkjs groth16 prove ./build/jwt/jwt_single1.zkey ./build/jwt/witness.wtns ./build/jwt/proof.json ./build/jwt/public.json
```

verify proof offchain
```
snarkjs groth16 verify ./build/jwt/verification_key.json ./build/jwt/public.json ./build/jwt/proof.json
```

generate verifier.sol
```
snarkjs zkey export solidityverifier ./build/jwt/jwt_single1.zkey Verifier.sol
```

run local hardhat test 
```
npx hardhat test ./test/blind.test.js
```

deploy blind and verifier contracts
```
npx hardhat run ./scripts/deploy.js --network goerli
```

## on-chain verification

in our code, we have examples of verifying an OpenAI JWT on-chain. however, `./contracts/Blind.sol` and `./contracts/Verifier.sol` are not updated with the current state of the circuit, since our proof of concept app, Nozee, does not use on-chain verification.

however, if you are interested in deploying on-chain, `./scripts/deploy.js` allows you to do a hardhat deploy, and `./test/blind.test.js` allows you to test in hardhat.

run hardhat contract tests, first create a `secret.json` file that has a private key and goerli node provider endpoint.
```
yarn test
```
