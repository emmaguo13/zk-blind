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

export const HEADSPACE_PUBKEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA14yuGbqZ7adQ05MSgDxG
Z1xcl+qHhJ16corRoIVxesIdomcPhNd/Wwkn46UciBQTopZGiXQ27jaEd+vXl0rw
p6NCMByzUR5nH1P5f5IDaHaZKMH94cGHDPRWpUQdH6JrbOSyp2RcPwLIgiL0GwDv
ZI5se2gJdCR6Zt4Eq5fPdQM7yNeNWamPDLPo9TCroAu16HxQUq7zojVFjZ2wJjcr
35Ml+gLOJIm9rg1xVI9X13dmu5MwvWJQYSp4qoOvQumXr2LyYLYdi81p9lwtKAVb
IljzX6VziAph/2ekfERHLAJK2f58DfZlnyTAQ7VgrL48jYKrPwTauhzgc8+1zyw5
pwIDAQAB
-----END PUBLIC KEY-----`
