const express = require("express");
const app = express();
const cors = require("cors");
const port = 3042;
const secp = require("ethereum-cryptography/secp256k1");
const { toHex, hexToBytes, utf8ToBytes } = require("ethereum-cryptography/utils");
const { keccak256 } = require("ethereum-cryptography/keccak");
const { verifyPbKey } = require("./utils/verify");

app.use(cors());
app.use(express.json());

const balances = {
  "04fc73d4813d0720bb55d2b9f8b523ab7f0c449991c5d990c39e5427d7b93e073f825e2465105b4f3c2fa0af6f904d3a3c7ad182ad71cf6106b7e5e006f618e865": 100,
  "043dfdc97fb949f21a09c7002529723c76653e1e02a1047abfa2910f2ccb35eca0cd3f3a0ce89c41e35ab272d55bc0c8386f129eb97f80076ceb191432ee2f1d82": 50,
  "046a5b12b06cfe8578de4537f14ca5d2567faf333088a1b3fa255dc1d1f2cb859cefc494d63e11a0554eda6e1b76aa56151fd292f89929b7d79abc6de06a000ce4": 75,
};
// a6793c701347e900bace71241631d5c6b159e6f6b49df1c1d60b87798182c2ac
// 618a70458cfcd0cceab96562db56479effc5f6d0d226c45e0815f0a95efec840
// 256838b5a44f9497e2eb32821567074e0d97b8f1f778244e70be205b8c33e748

app.get("/balance/:address", (req, res) => {
  // address is who start transaction and this is public key, so we don't need to verify.
  const { address } = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  // we accept sender is who start transaction .
  // recipent is who accpect transaction and it's public key
  // amount is transaction amount
  // sign aka signature, this is maked by recipient and amount, so we need recover to pbkey and verify recoverpbkey equal with sender or not .
  // the sign maked by pvkey and hashmessage via front-end in transfer.jsx. because we don't know who will intercep the pbKey, so we need signatrue.
  // in back-end we just use sign and hashmessage and recoverBit to recover pbKey. if we can get pbkey that means ecdsa verify comfiremd. then we just to check pbkey and address . if it's equal then done.
  const { sender, recipient, amount, sign } = req.body;
  const data = {
    recipient,
    amount
  }
  const hashMsg = keccak256(utf8ToBytes(JSON.stringify(data)));

  const pbKey = toHex(secp.getPublicKey(recipient));
  if (!verifyPbKey({ hashMsg, sign, senderPbKey: sender })) {
    res.status(400).send({ message: "u have no right!" });
    return;
  }
  setInitialBalance(sender);
  setInitialBalance(recipient);

  if (balances[sender] < amount) {
    res.status(400).send({ message: "Not enough funds!" });
  } else {
    balances[sender] -= amount;
    balances[pbKey] += amount;
    res.send({ balance: balances[sender] });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}
