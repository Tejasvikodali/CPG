const jwt = require("jsonwebtoken");

const crypto = require("../helpers/cryp");
const teleg = require("../helpers/telegram");
const rediscon = require("../redis/rediscon");

module.exports = async function (req, res, next) {
  var token = req.header("x-auth-token");
  console.log(token, "token");
  if (!token) return res.status(401).send("Access denied. No token provided.");
  // var dectoken = cryp.decrypt(token);
  //console.log(dectoken,"dectoken");
  // if (!dectoken)
  //   return res.status(401).send("Access denied. No token provided.");

  try {
    const decoded = jwt.verify(token, process.env.jwtPrivateKey);
    //const decoded = jwt.verify(dectoken, process.env.jwtPrivateKey);
    console.log("decoded----->", decoded);
    // get the user from Redis based on the decoded user ID

    const user = await rediscon.redisgethash("CPGUSERS", decoded.userid);

    if (!user) {
      console.log("User not found in Redis");
      return res.status(400).send("Session Expired! Please Login Again");
    }

    req.user = user;
    next();
  } catch (ex) {
    console.log(ex, "ex");
    teleg.alert_Dev(
      `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${ex.stack}  \n ❌❌❌❌❌❌👎`
    );
    res.status(400).send("Session Expired! Please Login Again");
  }
};
// const crypto = require("../helpers/cryp");
// const jwt = require("jsonwebtoken");
// const mongofunctions = require("../helpers/mongofunctions");
// const telegram = require("../helpers/telegram");
// const tiger = require("../helpers/tigerbalm");
// // const { Register } = require('../models/register');

// module.exports = async function (req, res, next) {
//   const token = req.header("x-auth-token");
//   if (!token || token === null)
//     return res.status(401).send("Access denied. No token provided...");
//   try {
//     const decoded = jwt.verify(
//       crypto.decrypt(token),
//       process.env.jwtPrivateKey
//     );
//     const user = await mongofunctions.find_one("User", {
//       user_email: tiger.encrypt(decoded.user_email),
//     });
//     if (!user) return res.status(400).send("User Not Found..!");
//     req.user = decoded;
//     req.userdata = user;
//     next();
//   } catch (ex) {
//     teleg.alert_Dev(
//       `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${ex.stack}  \n ❌❌❌❌❌❌👎`
//     );
//     res.status(400).send("Session Expired ! Please Login Again ");
//   }
// };
