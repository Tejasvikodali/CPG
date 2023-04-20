// const slowDown = require("express-slow-down");

// module.exports = slowDown({
//   windowMs: 1 * 1000, //1 seconds
//   delayAfter: 1, //allow 1 req for 1 seconds
//   delayMs: 2 * 1000, //after that add 2 seconds
//   keyGenerator: function (req /*, res*/) {
//     return req.user.userid;
//   },
//   onLimitReached: function (req, res, options) {
//     return "user limit reached";
//   },
// });

// const rateLimit = require("express-rate-limit");

// module.exports = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100, // limit each user to 100 requests per windowMs
//   keyGenerator: function (req) {
//     // use the user ID as the key for rate limiting
//     return req.user.id;
//   },
//   message: "Too many requests, please try again later",
// });

const rateLimit = require("express-rate-limit");

module.exports = rateLimit({
  windowMs: 10 * 1000,
  max: 2,
  message: "Too many request from this IP",
});
