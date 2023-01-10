const hre = require("hardhat");
const secret = require("../secret.json");

async function main() {
  const verifier = await hre.ethers.getContractFactory("contracts/Verifier.sol:Verifier");
  const v = await verifier.deploy();
  const v_d = await v.deployed();
  console.log(v_d)

  const contract = await hre.ethers.getContractFactory("Blind");

  const c = await contract.deploy([{
    verifier: v.address
  }]
  );
  await c.deployed();
}

main();
