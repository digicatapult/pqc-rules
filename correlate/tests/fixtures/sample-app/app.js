const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

const digest = crypto.createHash("md5").update("x").digest("hex");

const token = jwt.sign({ sub: "1" }, privateKey, { algorithm: "RS256" });

const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
