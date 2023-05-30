import { shaHash } from '../helpers/shaHash'
import { bytesToBigInt, fromHex, toCircomBigIntBytes } from '../helpers/binaryFormat'
import {
  HEADSPACE_PUBKEY,
  MAX_HEADER_PADDED_BYTES,
  OPENAI_PUBKEY
} from "../helpers/constants"
import { Hash } from './fast-sha256'
const pki = require('node-forge').pki
import * as fs from "fs";

export async function generate_inputs(
  signature: string = 'yjlOzb9yd8JGpvPGJK9uoVubC2Hy69dFizQTgQyXDjqN7cyhGkenxTXZefAD7PxI-TJ07E804H0zBf3Gfna3vnuo4ggqGvwYzSFW1U_YWgJisHc-gTFbNS5AUm6ha-rVDSpQ-yyC1bkErAShLtWBk35Cw3el27lcskv7C9dyperELb0bK9qjE_fdTFg5_jPv3qJp2cZPgOPPn83I1077WnYV2TCHK3K478Wfa8HfwsTh4KOYCF78ZPK0lBcABS1YxR5W_W94hDdzYdSu3J0L_g0jrbTsp6RYMdGcdGsrOQZkhqtpVj1YoKA6GVLgqC4biF5ahfj9ndZe7U7MxazCXg',
  msg: string = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik1UaEVOVUpHTkVNMVFURTRNMEZCTWpkQ05UZzVNRFUxUlRVd1FVSkRNRU13UmtGRVFrRXpSZyJ9.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL3Byb2ZpbGUiOnsiZW1haWwiOiJlbW1hZ3VvQGJlcmtlbGV5LmVkdSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfSwiaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS9hdXRoIjp7InVzZXJfaWQiOiJ1c2VyLUp4TW40YnljU3ZWMGhwY3dOZmtjRzRhWCJ9LCJpc3MiOiJodHRwczovL2F1dGgwLm9wZW5haS5jb20vIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMTQxNzEyMDg3OTkxMzA3NjAxNjYiLCJhdWQiOlsiaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MSIsImh0dHBzOi8vb3BlbmFpLm9wZW5haS5hdXRoMGFwcC5jb20vdXNlcmluZm8iXSwiaWF0IjoxNjg1NDE1Mjk5LCJleHAiOjE2ODY2MjQ4OTksImF6cCI6IlRkSkljYmUxNldvVEh0Tjk1bnl5d2g1RTR5T282SXRHIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCBtb2RlbC5yZWFkIG1vZGVsLnJlcXVlc3Qgb3JnYW5pemF0aW9uLnJlYWQgb3JnYW5pemF0aW9uLndyaXRlIn0',
  ethAddress: string = '0x0000000000000000000000000000000000000000',
  key: string = 'openai'
//   signature: string,
//   msg: string,
//   ethAddress: string,
//   key: string
): Promise<any> {
  console.log('🚀 ~ signature', signature)
  const sig = BigInt('0x' + Buffer.from(signature, 'base64').toString('hex'))
  const message = Buffer.from(msg)
  const period_idx_num = BigInt(msg.indexOf('.'))

  const { domain: domainStr, domain_idx: domain_index } = findDomain(msg)
  const domain = Buffer.from(domainStr ?? '')
  const domain_idx_num = BigInt(domain_index ?? 0)

  const { timestamp:timeStr, time_index:timestamp_idx} = findTimestampInJSON(msg);
  const timestamp = BigInt(timeStr)
  const timestamp_idx_num = BigInt(timestamp_idx ?? 0)

  console.log("printing timestamp after buffer", timestamp)

  const circuitType = CircuitType.JWT

  const OPENAI_PUBKEY = `-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA27rOErDOPvPc3mOADYtQ
    BeenQm5NS5VHVaoO/Zmgsf1M0Wa/2WgLm9jX65Ru/K8Az2f4MOdpBxxLL686ZS+K
    7eJC/oOnrxCRzFYBqQbYo+JMeqNkrCn34yed4XkX4ttoHi7MwCEpVfb05Qf/ZAmN
    I1XjecFYTyZQFrd9LjkX6lr05zY6aM/+MCBNeBWp35pLLKhiq9AieB1wbDPcGnqx
    lXuU/bLgIyqUltqLkr9JHsf/2T4VrXXNyNeQyBq5wjYlRkpBQDDDNOcdGpx1buRr
    Z2hFyYuXDRrMcR6BQGC0ur9hI5obRYlchDFhlb0ElsJ2bshDDGRk5k3doHqbhj2I
    gQIDAQAB
    -----END PUBLIC KEY-----`
  
  const currentKey = OPENAI_PUBKEY

  const pubKeyData = pki.publicKeyFromPem(
    currentKey
  )

  const modulus = BigInt(pubKeyData.n.toString())
  const fin_result = await getCircuitInputs(
    sig,
    modulus,
    message,
    ethAddress,
    circuitType,
    period_idx_num,
    domain_idx_num,
    domain, 
    timestamp, 
    timestamp_idx_num
  )

  return fin_result.circuitInputs
}

export interface ICircuitInputs {
  message?: string[]
  modulus?: string[]
  signature?: string[]
  address?: string
  address_plus_one?: string
  message_padded_bytes?: string
  period_idx?: string
  domain_idx?: string
  domain?: string[]
  timestamp?: string
  timestamp_idx?: string
}
enum CircuitType {
  RSA = 'rsa',
  SHA = 'sha',
  TEST = 'test',
  JWT = 'jwt'
}

function assert(cond: boolean, errorMessage: string) {
  if (!cond) {
    throw new Error(errorMessage)
  }
}

// Works only on 32 bit sha text lengths
function int32toBytes(num: number): Uint8Array {
  const arr = new ArrayBuffer(4) // an Int32 takes 4 bytes
  const view = new DataView(arr)
  view.setUint32(0, num, false) // byteOffset = 0; litteEndian = false
  return new Uint8Array(arr)
}

// Works only on 32 bit sha text lengths
function int8toBytes(num: number): Uint8Array {
  const arr = new ArrayBuffer(1) // an Int8 takes 4 bytes
  const view = new DataView(arr)
  view.setUint8(0, num) // byteOffset = 0; litteEndian = false
  return new Uint8Array(arr)
}

// converts ascii to string
function AsciiArrayToString(arr: Buffer) {
  let str = ''
  for (let i = 0; i < arr.length; i++) {
    str += String.fromCharCode(arr[i])
  }
  return str
}

// find email domain in msg
function findDomain(msg: string) {
  let domain_idx
  let domain
  var s = Buffer.from(msg, 'base64')
  var json = AsciiArrayToString(s)
  const email_regex = /([-a-zA-Z._+]+)@([-a-zA-Z]+).([a-zA-Z]+)/
  const match = json.match(email_regex)
  console.log(match)
  if (match) {
    domain = match[2] // [0] = whole group, then capture groups
    let email_index = match.index
    if (email_index) domain_idx = match[0].indexOf(domain) + email_index
  }
  return { domain, domain_idx }
}

function findTimestampInJSON(msg: string) {
    var s = Buffer.from(msg, 'base64')
    var json = AsciiArrayToString(s)
    let time_index = json.indexOf(`"exp":`) + 6
    let timestamp = json.substring(time_index, time_index + 10)

    time_index += 1
  
    return {timestamp, time_index}
    
  }

function mergeUInt8Arrays(a1: Uint8Array, a2: Uint8Array): Uint8Array {
  // sum of individual array lengths
  var mergedArray = new Uint8Array(a1.length + a2.length)
  mergedArray.set(a1)
  mergedArray.set(a2, a1.length)
  return mergedArray
}

// Puts an end selector, a bunch of 0s, then the length, then fill the rest with 0s.
async function sha256Pad(
  prehash_prepad_m: Uint8Array,
  maxShaBytes: number
): Promise<[Uint8Array, number]> {
  const length_bits = prehash_prepad_m.length * 8 // bytes to bits
  const length_in_bytes = int32toBytes(length_bits)
  prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int8toBytes(2 ** 7))
  while (
    (prehash_prepad_m.length * 8 + length_in_bytes.length * 8) % 512 !==
    0
  ) {
    prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int8toBytes(0))
  }
  prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, length_in_bytes)
  assert(
    (prehash_prepad_m.length * 8) % 512 === 0,
    'Padding did not compconste properly!'
  )
  const messageLen = prehash_prepad_m.length
  while (prehash_prepad_m.length < maxShaBytes) {
    prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int32toBytes(0))
  }
  assert(
    prehash_prepad_m.length === maxShaBytes,
    'Padding to max length did not compconste properly!'
  )

  return [prehash_prepad_m, messageLen]
}

async function Uint8ArrayToCharArray(a: Uint8Array): Promise<string[]> {
  return Array.from(a).map(x => x.toString())
}

async function Uint8ArrayToString(a: Uint8Array): Promise<string> {
  return Array.from(a)
    .map(x => x.toString())
    .join(';')
}

async function partialSha(
  msg: Uint8Array,
  msgLen: number
): Promise<Uint8Array> {
  const shaGadget = new Hash()
  return await shaGadget.update(msg, msgLen).cacheState()
}

export async function getCircuitInputs(
  rsa_signature: BigInt,
  rsa_modulus: BigInt,
  msg: Buffer,
  eth_address: string,
  circuit: CircuitType,
  period_idx_num: BigInt,
  domain_idx_num: BigInt,
  domain_raw: Buffer, 
  timestamp: BigInt,
  timestamp_idx_num: BigInt
): Promise<{
  valid: {
    validSignatureFormat?: boolean
    validMessage?: boolean
  }
  circuitInputs: ICircuitInputs
}> {
  console.log('Starting processing of inputs')
  const modulusBigInt = rsa_modulus
  // Message is the header + payload
  const prehash_message_string = msg
  const signatureBigInt = rsa_signature

  // Perform conversions
  const prehashBytesUnpadded =
    typeof prehash_message_string == 'string'
      ? new TextEncoder().encode(prehash_message_string)
      : Uint8Array.from(prehash_message_string)

  // Sha add padding
  const [messagePadded, messagePaddedLen] = await sha256Pad(
    prehashBytesUnpadded,
    MAX_HEADER_PADDED_BYTES
  )

  // domain padding
  const domainUnpadded =
    typeof domain_raw == 'string'
      ? new TextEncoder().encode(domain_raw)
      : Uint8Array.from(domain_raw)

  const zerosPadArray = new Uint8Array(30 - domainUnpadded.length)
  const domainPadded = new Uint8Array([...domainUnpadded, ...zerosPadArray])

  // timestamp padding
//   const timeUnpadded =
//     typeof timestamp == 'string'
//       ? new TextEncoder().encode(timestamp)
//       : Uint8Array.from(timestamp)

//   console.log("timestamp with uint array", timeUnpadded)

//   const timePadArray = new Uint8Array(30 - timeUnpadded.length)
//   const domainPadded = new Uint8Array([...domainUnpadded, ...zerosPadArray])

  // Ensure SHA manual unpadded is running the correct function
  const shaOut = await partialSha(messagePadded, messagePaddedLen)
  assert(
    (await Uint8ArrayToString(shaOut)) ===
      (await Uint8ArrayToString(
        Uint8Array.from(await shaHash(prehashBytesUnpadded))
      )),
    'SHA256 calculation did not match!'
  )

  // Compute identity revealer
  const modulus = toCircomBigIntBytes(modulusBigInt)
  const signature = toCircomBigIntBytes(signatureBigInt)

  const message_padded_bytes = messagePaddedLen.toString()
  const message = await Uint8ArrayToCharArray(messagePadded) // Packed into 1 byte signals
  const domain = await Uint8ArrayToCharArray(domainPadded)
  const period_idx = period_idx_num.toString()
  const domain_idx = domain_idx_num.toString()


  const time = timestamp.toString()
  const time_idx = timestamp_idx_num.toString()

  console.log("timestamp as char array...", time)

  const address = bytesToBigInt(fromHex(eth_address)).toString()
  const address_plus_one = (bytesToBigInt(fromHex(eth_address)) + 1n).toString()

  const circuitInputs = {
    message,
    modulus,
    signature,
    message_padded_bytes,
    address,
    address_plus_one,
    period_idx,
    domain_idx,
    domain, 
    time, 
    time_idx
  }
  return {
    circuitInputs,
    valid: {}
  }
}

// If main
if (typeof require !== "undefined" && require.main === module) {
    // debug_file();
    const circuitInputs = generate_inputs().then((res) => {
      console.log("Writing to file...");
      console.log(res)
      fs.writeFileSync(`./confusion.json`, JSON.stringify(res), { flag: "w" });
    }
    );
    // gen_test();
  }

