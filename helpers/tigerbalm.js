const tiger = require("tiger-balm");

var password = process.env.TIGER_PASS;
var salt = process.env.TIGER_SALT;
module.exports = {
  encrypt: (text) => {
    const encrypteddata = tiger.encrypt(password, salt, text);
    if (!encrypteddata) {
      return "Data not encrypted";
    }
    return encrypteddata;
  },
  decrypt: (text) => {
    const decrypteddata = tiger.decrypt(password, salt, text);
    if (!decrypteddata) {
      return "Data not encrypted";
    }
    return decrypteddata;
  },
};
