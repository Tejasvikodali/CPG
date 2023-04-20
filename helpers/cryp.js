const CryptoJS = require("crypto-js");
const teleg = require("../helpers/telegram");

var password = process.env.CRYPTO_PASS;
var salt = process.env.CRYPTO_SALT;
var key = CryptoJS.PBKDF2(password, salt, {
  keySize: 256 / 32,
  iterations: 100,
});

module.exports = {
  encrypt: (str) => {
    try {
      return CryptoJS.AES.encrypt(str, key.toString()).toString();
    } catch (error) {
      return "tberror";
    }
  },
  decrypt: (str) => {
    try {
      const dattt = CryptoJS.AES.decrypt(str, key.toString());
      return dattt.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      return "tberror";
    }
  },
  encryptobj: (obj) => {
    try {
      return CryptoJS.AES.encrypt(
        JSON.stringify(obj),
        key.toString()
      ).toString();
    } catch (error) {
      return "tberror";
    }
  },
  decryptobj: (str) => {
    try {
      const objt = CryptoJS.AES.decrypt(str, key.toString());
      return JSON.parse(objt.toString(CryptoJS.enc.Utf8));
    } catch (error) {
      console.log("----", error);
      return "tberror";
    }
  },
  APIencryption: (object) => {
    try {
      return encodeURIComponent(
        CryptoJS.AES.encrypt(JSON.stringify(object), key.toString()).toString()
      ).toString("base64");
    } catch (error) {
      teleg.alert_Developers(`err in ecryptAPI-->${JSON.stringify(error)}`);

      return "tberror";
    }
  },
};
