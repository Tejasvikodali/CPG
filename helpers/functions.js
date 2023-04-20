const randomstring = require("randomstring");
module.exports = {
  userid: () => {
    var date = Date.now().toString().slice(-5);
    const randomstring = require("randomstring");
    const tid =
      "USER" +
      randomstring.generate({
        length: 5,
        charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
      }) +
      date;
    return tid;
  },
  cardid: () => {
    const randomstring = require("randomstring");
    const tid = randomstring.generate({
      length: 5,
      charset: "0123456789",
    });
    return tid;
  },
  usrid: () => {
    var date = Date.now().toString().slice(-5);
    const randomstring = require("randomstring");
    const tid =
      "USER" +
      randomstring.generate({
        length: 5,
        charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
      }) +
      date;
    return tid;
  },

  fcmtoken: () => {
    var date = Date.now().toString().slice(-5);
    const randomstring = require("randomstring");
    const tid =
      "FCMTOKEN" +
      randomstring.generate({
        length: 5,
        charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
      }) +
      date;
    return tid;
  },
  productcode: () => {
    var date = Date.now().toString().slice(-5);
    const randomstring = require("randomstring");
    const tid =
      "PROCODE" +
      randomstring.generate({
        length: 5,
        charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
      }) +
      date;
    return tid;
  },
  transactionid: () => {
    var date = Date.now().toString().slice(-5);
    const randomstring = require("randomstring");
    const tid =
      "TRANS" +
      randomstring.generate({
        length: 5,
        charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
      }) +
      date;
    return tid;
  },
  get_random_string: (str, length) => {
    return str + crypto.randomBytes(Number(length / 2)).toString("hex");
  },
  gensalt: () => {
    var date = Date.now().toString().slice(-5);
    const randomstring = require("randomstring");
    const tid =
      "TRANS" +
      randomstring.generate({
        length: 5,
        charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
      }) +
      date;
    return tid;
  },
  generateOTP: (environment) => {
    if (environment === "production") {
      return Math.floor(100000 + Math.random() * 900000);
    }
    return 123456;
  },
  bitcoin: () => {
    var date = Date.now().toString().slice(-5);
    const randomstring = require("randomstring");
    const tid =
      "BTC" +
      randomstring.generate({
        length: 5,
        charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
      }) +
      date;
    return tid;
  },
  usdt: () => {
    var date = Date.now().toString().slice(-5);
    const randomstring = require("randomstring");
    const tid =
      "USDT" +
      randomstring.generate({
        length: 5,
        charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
      }) +
      date;
    return tid;
  },
  busd: () => {
    var date = Date.now().toString().slice(-5);
    const randomstring = require("randomstring");
    const tid =
      "BUSD" +
      randomstring.generate({
        length: 5,
        charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
      }) +
      date;
    return tid;
  },
};
