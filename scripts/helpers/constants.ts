export const CIRCOM_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const MAX_MSG_PADDED_BYTES = 1024; // NOTE: this must be the same as the first arg in the email in main args circom

// circom constants from main.circom / https://zkrepl.dev/?gist=30d21c7a7285b1b14f608325f172417b
// template RSAGroupSigVerify(n, k, levels) {
// component main { public [ modulus ] } = RSAVerify(121, 17);
// component main { public [ root, payload1 ] } = RSAGroupSigVerify(121, 17, 30);
export const CIRCOM_BIGINT_N = 121;
export const CIRCOM_BIGINT_K = 17;
export const CIRCOM_LEVELS = 30;

export const OPENAI_PUBKEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA27rOErDOPvPc3mOADYtQ
BeenQm5NS5VHVaoO/Zmgsf1M0Wa/2WgLm9jX65Ru/K8Az2f4MOdpBxxLL686ZS+K
7eJC/oOnrxCRzFYBqQbYo+JMeqNkrCn34yed4XkX4ttoHi7MwCEpVfb05Qf/ZAmN
I1XjecFYTyZQFrd9LjkX6lr05zY6aM/+MCBNeBWp35pLLKhiq9AieB1wbDPcGnqx
lXuU/bLgIyqUltqLkr9JHsf/2T4VrXXNyNeQyBq5wjYlRkpBQDDDNOcdGpx1buRr
Z2hFyYuXDRrMcR6BQGC0ur9hI5obRYlchDFhlb0ElsJ2bshDDGRk5k3doHqbhj2I
gQIDAQAB
-----END PUBLIC KEY-----`

export const JWT_CLIENT_PUBKEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmhnp/JyDgCZXpMj5h+G4
DEAuoCLlJSugN++pEnDJGuCfoiT8/0TFG04grKi2UIEy7QtLc+6D4qCK9qddrPqq
kWc+dB5f6Is5FNfcU8N6fyOI5lFk46M6ECynwcWltBj9EVG553HXe7J4aI+Ixj5v
be759MaXBOZFyHO2S6JF1CBoYjiOp/9c0JK822JWstoBuuqOWEUd1EH60K8+2mbX
kvzKNvlOln6As6RrqtfcE2H3AWxfpofBOaGZ1lr5MAO3LIC9XQn//xoG5gKCj8qX
3iVhu67Vz/45dL7UmTWPa2dg0UZq38uwKSaS+CdLUxQXbNqQlzBnkAjbPn/cI/q8
SwIDAQAB
-----END PUBLIC KEY-----`

