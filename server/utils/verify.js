const { toHex, hexToBytes, utf8ToBytes } = require("ethereum-cryptography/utils");
const {keccak256 } = require("ethereum-cryptography/keccak");
const secp = require("ethereum-cryptography/secp256k1");

 function verifyPbKey ({sign, hashMsg, senderPbKey}) {
  const [signature, recoverBit] = sign;
  const prevPbAddress = secp.recoverPublicKey(hashMsg,new Uint8Array(Object.values(signature)), recoverBit);
  const address = toHex(prevPbAddress);
  console.log(address);
  console.log(senderPbKey);
  if(address === senderPbKey){
    return true;
  }
  return false;
};

module.exports = {
  verifyPbKey
}