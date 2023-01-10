const hre = require("hardhat");
const secret = require("../secret.json");

async function main() {
  const verifier = await hre.ethers.getContractFactory("contracts/Verifier.sol:Verifier");
  const v = await verifier.deploy();
  await v.deployed();

  console.log(v.address)

  const contract = await hre.ethers.getContractFactory("Blind");

  const c = await contract.deploy(
    v.address
  );
  await c.deployed();

  console.log(c.address)
}

main();
