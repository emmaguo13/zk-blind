const hre = require("hardhat");
const secret = require("../secret.json");

async function main() {
  const contract = await hre.ethers.getContractFactory("Blind");

  const c = await contract.deploy();
  await c.deployed();
}

main();
