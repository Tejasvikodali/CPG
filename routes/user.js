const express = require("express");
const router = express.Router();
const errhandler = require("../middleware/async");
const teleg = require("../helpers/telegram");
const ratelimiter = require("../helpers/ratelimiter");
const ratecutter = require("../middleware/ratecutter");
const validations = require("../helpers/validations");
const func = require("../helpers/functions");
const bcrypt = require("bcrypt");
const mongofunctions = require("../helpers/mongofunctions");
const rediscon = require("../redis/rediscon");
const crypto = require("../helpers/cryp");
const tiger = require("../helpers/tigerbalm");
var jwt = require("jsonwebtoken");
const verifyRecaptcha = require("../helpers/captcha");
const auth = require("../middleware/auth");

// Registration
router.post(
  "/userregistration",
  ratelimiter,
  errhandler(async (req, res) => {
    const adminControlsCheck = await rediscon.redisexistshash(
      "adminTransactions",
      "adminControls"
    );
    if (adminControlsCheck === 0 || adminControlsCheck === false)
      return res.status(400).send("Admin Controls Not Added in Redis.");
    const admin = await rediscon.redisgethash(
      "adminTransactions",
      "adminControls"
    );
    console.log(admin, "admin");
    if (admin.register !== "Enable")
      return res.status(400).send("Registration Suspended by Admin");
    var { error } = validations.getenc(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    console.log(req.body.enc, "FE");
    const data = crypto.decryptobj(req.body.enc);
    console.log(data, "data");
    if (data === "tberror") return res.status(400).send("Invalid Parameter");

    var { error } = await validations.registration(data);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    if (data.captcha) {
      const validcap = await verifyRecaptcha(data.captcha);

      if (validcap.success !== true)
        return res.status(400).send(" Invalid Captcha");
    }

    const userid = func.userid();
    console.log(userid, "userid");

    const user = await mongofunctions.findone(
      (collectionName = "User"),
      (condition = {
        user_email: tiger.encrypt(data.user_email),
      })
    );
    console.log(user, "user");
    if (user) {
      return res.status(400).send("User already exists");
    }
    const salt = await bcrypt.genSalt(10);
    const hashpassword = await bcrypt.hash(data.password, salt);

    const newuser = await mongofunctions.insert(
      (collectionName = "User"),
      (condition = {
        userid: userid,
        //user_name: data.user_name,
        fullName: data.fullName,
        user_email: tiger.encrypt(data.user_email),
        password: hashpassword,
        //status: "disabled",
      })
    );
    console.log(newuser, "newuser");

    const redisuser = await rediscon.redisinserthash(
      "CPGUSERS",
      newuser.userid,
      JSON.stringify(newuser)
    );
    console.log(redisuser, "redisuser");

    teleg.alert_Dev(`New User Registered in CPG🦧:
      Name : ${newuser.fullName},
      userid:${newuser.userid},
      user_email:${tiger.decrypt(newuser.user_email)}`);
    const setotp = await rediscon.otpredis(newuser.user_email, 123456);
    console.log(setotp, "setotp");

    return res.status(200).send(crypto.encrypt("Otp Sent Successfully"));
  })
);
//Registrationotpverification
router.post(
  "/Registrationotpverification",
  ratelimiter,
  errhandler(async (req, res) => {
    console.log("route hitted");
    var { error } = validations.getenc(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    console.log(req.body.enc, "FE");
    const data = crypto.decryptobj(req.body.enc);
    console.log(data, "data");
    if (data === "tberror") return res.status(400).send("Invalid Parameter");
    var { error } = validations.Otpverify(data);
    if (error) return res.status(400).send(error.details[0].message);

    const user = await mongofunctions.find_one(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(data.user_email) })
    );
    if (!user) {
      return res.status(400).send("No User Exists With Given Email");
    }

    const getotp = await rediscon.otpget(user.user_email);
    console.log(getotp, data.otp, "getotp");
    if (!getotp) {
      return res.status(400).send("otp expired");
    }
    if (Number(getotp) !== Number(data.otp)) {
      return res.status(400).send("Invalid otp");
    }
    const userstatus = await mongofunctions.findoneandupdate(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(data.user_email) }),
      (update = { email_status: "enabled" }),
      (options = { new: true })
    );
    const token = jwt.sign(
      {
        userid: userstatus.userid,
        // user_name: userstatus.user_name,
        fullName: userstatus.fullName,
        user_email: userstatus.user_email,
        user_status: userstatus.user_status,
        email_status: userstatus.email_status,

        // cryptoaddress: userstatus.cryptoaddress,
      },
      process.env.jwtPrivateKey,
      { expiresIn: "90d" }
    );
    await rediscon.mark_otp_used(user.user_email);
    return res.status(200).send(crypto.encrypt(token));
  })
);
//Login
router.post(
  "/userlogin",
  ratelimiter,
  errhandler(async (req, res) => {
    console.log("hitted");
    const adminControlsCheck = await rediscon.redisexistshash(
      "adminTransactions",
      "adminControls"
    );
    if (adminControlsCheck === 0 || adminControlsCheck === false)
      return res.status(400).send("Admin Controls Not Added in Redis.");
    const admin = await rediscon.redisgethash(
      "adminTransactions",
      "adminControls"
    );
    console.log(admin, "admin");
    if (admin.login !== "Enable")
      return res.status(400).send("Login Suspended by Admin");
    var { error } = validations.getenc(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const data = crypto.decryptobj(req.body.enc);
    if (data === "tberror") return res.status(400).send("Invalid Parameter");
    var { error } = validations.LoginOtp(data);
    if (error) return res.status(400).send(error.details[0].message);
    if (data.captcha) {
      const validcap = await verifyRecaptcha(data.captcha);

      if (validcap.success !== true)
        return res.status(400).send(" Invalid Captcha");
    }
    const user = await mongofunctions.find_one(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(data.user_email) })
    );
    if (!user) {
      return res.status(400).send("No User Exists With Given Email");
    }

    const valpass = await bcrypt.compare(data.password, user.password);
    if (!valpass) return res.status(400).send("Incorrect Password");
    const setotp = await rediscon.otpredis(user.user_email, 123456);
    console.log(setotp, "setotp");
    return res.status(200).send(crypto.encrypt("Otp Sent Successfully"));
  })
);
//otpverification
router.post(
  "/otpverification",
  ratelimiter,
  errhandler(async (req, res) => {
    console.log("hitted");
    var { error } = validations.getenc(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    console.log(req.body.enc, "FE");
    const data = crypto.decryptobj(req.body.enc);
    console.log(data, "data");
    if (data === "tberror") return res.status(400).send("Invalid Parameter");
    var { error } = validations.Otpverify(data);
    if (error) return res.status(400).send(error.details[0].message);
    const user = await mongofunctions.find_one(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(data.user_email) })
    );
    if (!user) {
      return res.status(400).send("No User Exists With Given Email");
    }

    const getotp = await rediscon.otpget(user.user_email);
    console.log(getotp, data.otp, "getotp");
    if (!getotp) {
      return res.status(400).send("otp expired");
    }
    if (Number(getotp) !== Number(data.otp)) {
      return res.status(400).send("Invalid otp");
    }

    const token = jwt.sign(
      {
        userid: user.userid,
        fullName: user.fullName,
        user_email: user.user_email,
        user_status: user.user_status,
        email_status: user.email_status,

        //cryptoaddress: user.cryptoaddress,
      },
      process.env.jwtPrivateKey,
      { expiresIn: "90d" }
    );
    await rediscon.mark_otp_used(user.user_email);
    return res.status(200).send(crypto.encrypt(token));
  })
);
//Resend otp
router.post(
  "/resend",
  ratelimiter,
  errhandler(async (req, res) => {
    console.log("resend otp hitted");
    var { error } = validations.getenc(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const data = crypto.decryptobj(req.body.enc);
    if (data === "tberror") return res.status(400).send("Invalid Parameter");
    console.log(req.body, "req.body");
    console.log(data, "data");
    var { error } = validations.resend(data);
    if (error) return res.status(400).send(error.details[0].message);
    const resend = await mongofunctions.find_one(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(data.user_email) })
    );

    if (!resend) return res.status(400).send("User Not Found.");

    await rediscon.otpredis(resend.user_email, 123456);
    return res.status(200).send(crypto.encrypt("Otp Sent Successfully"));
  })
);
//change password..!
router.post(
  "/PasswordChange",
  ratelimiter,

  errhandler(async (req, res) => {
    var { error } = validations.getenc(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const data = crypto.decryptobj(req.body.enc);
    if (data === "tberror") return res.status(400).send("Invalid Parameter");
    var { error } = validations.changePassword(data);
    if (error) return res.status(400).send(error.details[0].message);
    if (data.captcha) {
      const validcap = await verifyRecaptcha(data.captcha);

      if (validcap.success !== true)
        return res.status(400).send(" Invalid Captcha");
    }

    const user_email = tiger.encrypt(data.user_email);
    var user = await mongofunctions.find_one("User", {
      user_email: user_email,
    });
    if (!user) return res.status(400).send("User Email Does Not Exists.");
    const setotp = await rediscon.otpredis(user.user_email, 123456);
    console.log(setotp, "setotp");

    return res
      .status(200)
      .send(
        crypto.encrypt(
          `Otp Sent Successfully to this ${tiger.decrypt(user.user_email)}`
        )
      );
  })
);
//change password verification
router.post(
  "/chngpswdotpverification",
  ratelimiter,
  errhandler(async (req, res) => {
    var { error } = validations.getenc(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const data = crypto.decryptobj(req.body.enc);
    if (data === "tberror") return res.status(400).send("Invalid Parameter");
    var { error } = validations.chngpswdOtpverify(data);
    if (error) return res.status(400).send(error.details[0].message);

    const user = await mongofunctions.find_one(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(data.user_email) })
    );
    if (!user) {
      return res.status(400).send("No User Exists With Given email");
    }

    const getotp = await rediscon.otpget(user.user_email);
    console.log(getotp, req.body.otp, "getotp");
    if (!getotp) {
      return res.status(400).send("otp expired");
    }
    if (Number(getotp) !== Number(data.otp)) {
      return res.status(400).send("Invalid otp");
    }

    const salt = await bcrypt.genSalt(10);
    password = await bcrypt.hash(data.password, salt);
    const updtuser = await mongofunctions.findoneandupdate(
      "User",
      {
        user_email: tiger.encrypt(data.user_email),
      },
      { password: password },
      { new: true }
    );
    const redisuser = await rediscon.redisinserthash(
      "CPGUSERS",
      user.userid,
      JSON.stringify(updtuser)
    );
    teleg.alert_Dev(` User updated password in CPG🦧 for ${tiger.decrypt(
      updtuser.user_email
    )} by
     ${updtuser.fullName}`);
    const token = jwt.sign(
      {
        userid: updtuser.userid,
        fullName: updtuser.fullName,
        user_email: updtuser.user_email,
        user_status: user.user_status,
        email_status: user.email_status,

        //cryptoaddress: updtuser.cryptoaddress,
      },
      process.env.jwtPrivateKey,
      { expiresIn: "90d" }
    );
    await rediscon.mark_otp_used(user.user_email);
    return res.status(200).send(crypto.encrypt(token));
  })
);
//get user details
router.post(
  "/getusersdetails",
  auth,
  ratecutter,
  errhandler(async (req, res) => {
    console.log(req.user, "requser");
    const user = JSON.parse(req.user);
    console.log(user.userid, "user");
    const redisusercheck = await rediscon.redisexistshash(
      "CPGUSERS",
      user.userid
    );
    if (!redisusercheck) {
      return res.status(400).send("User not found in redis ");
    }
    const redisgetuser = await rediscon.redisgethash("CPGUSERS", user.userid);
    const userObj = JSON.parse(redisgetuser);
    delete userObj.createdAt;
    delete userObj.updatedAt;
    delete userObj.password;
    delete userObj.__v;
    delete userObj._id;

    userObj.user_email = tiger.decrypt(userObj.user_email);
    console.log(userObj, "userObj");

    return res.status(200).send(crypto.encryptobj(userObj));
  })
);
//generate api keys
router.post(
  "/generateapikey",
  auth,
  ratelimiter,
  errhandler(async (req, res) => {
    console.log(req.user, "req.user");
    const data = JSON.parse(req.user);
    console.log(data, "data");

    const user = await mongofunctions.find_one("User", {
      userid: data.userid,
    });

    if (!user) {
      return res.status(400).send({ message: "User not found" });
    }
    console.log(user, "user");

    if (user.address) {
      return res.status(200).send(
        crypto.encryptobj({
          keys: {
            API_KEY: user.address.API_keys.api_key,
            SECRECT_KEY: user.address.API_keys.secrect_key,
          },
        })
      );
    }
    var API_keys = {
      api_key: crypto.APIencryption({
        userid: user.userid,
      }),
      secrect_key: crypto.APIencryption({
        userid: user.userid,
        email: user.email,
      }),
    };
    console.log(API_keys, "API_keys");
    var update_user = await mongofunctions.findoneandupdate(
      "User",
      { userid: user.userid },
      { "address.API_keys": API_keys },
      { new: true }
    );
    await rediscon.UserData(update_user.userid);

    return res.status(200).send(
      crypto.encryptobj({
        success: `API Keys Generated Successfull.`,
        keys: {
          API_KEY: API_keys.api_key,
          SECRECT_KEY: API_keys.secrect_key,
        },
      })
    );
  })
);
//generate crypto address
router.post(
  "/cryptoaddress",
  auth,
  ratelimiter,
  errhandler(async (req, res) => {
    const user = await mongofunctions.find_one("User", {
      userid: req.user.userid,
    });

    console.log(user, "user");

    if (!user) {
      return res.status(400).send({ message: "User not found" });
    }

    if (
      user.cryptoaddress.bitcoin !== "0" &&
      user.cryptoaddress.usdt !== "0" &&
      user.cryptoaddress.busd !== "0"
    ) {
      return res.status(200).send(
        crypto.encryptobj({
          bitcoin: user.cryptoaddress.bitcoin,
          usdt: user.cryptoaddress.usdt,
          busd: user.cryptoaddress.busd,
        })
      );
    }
    var cryptoaddress = {
      bitcoin: func.bitcoin(),
      usdt: func.usdt(),
      busd: func.busd(),
    };

    var update_user = await mongofunctions.findoneandupdate(
      "User",
      { userid: user.userid },
      { cryptoaddress: cryptoaddress },
      { new: true }
    );
    const redisuser = await rediscon.UserData(update_user.userid);
    console.log(redisuser, "redisuser");

    return res.status(200).send(
      crypto.encryptobj({
        bitcoin: update_user.cryptoaddress.bitcoin,
        usdt: update_user.cryptoaddress.usdt,
        busd: update_user.cryptoaddress.busd,
      })
    );
  })
);

router.post(
  "/userscheck",
  ratelimiter,
  errhandler(async (req, res) => {
    try {
      const adminControlsCheck = await rediscon.redisexistshash(
        "adminTransactions",
        "adminControls"
      );
      if (adminControlsCheck === 0 || adminControlsCheck === false)
        return res.status(400).send("Admin Controls Not Added in Redis.");
      const admin = await rediscon.redisgethash(
        "adminTransactions",
        "adminControls"
      );
      console.log(admin, "admin");
      if (admin.register !== "Enable")
        return res.status(400).send("Registration Suspended by Admin");

      var { error } = await validations.registrations(req.body);
      if (error) {
        return res.status(400).send(error.details[0].message);
      }
      console.log(req.body, "req.body");

      const userid = func.userid();
      console.log(userid, "userid");

      const user = await mongofunctions.findone(
        (collectionName = "User"),
        (condition = {
          user_email: tiger.encrypt(req.body.user_email),
        })
      );
      console.log(user, "user");
      if (user) {
        return res.status(400).send("User already exists");
      }
      const salt = await bcrypt.genSalt(10);
      const hashpassword = await bcrypt.hash(req.body.password, salt);

      const newuser = await mongofunctions.insert(
        (collectionName = "User"),
        (condition = {
          userid: userid,
          fullName: req.body.fullName,
          user_email: tiger.encrypt(req.body.user_email),
          password: hashpassword,
          status: "disabled",
        })
      );
      console.log(newuser, "newuser");
      const redisuser = await rediscon.redisinserthash(
        "CPGUSERS",
        newuser.userid,
        JSON.stringify(newuser)
      );
      console.log(redisuser, "redisuser");

      teleg.alert_Dev(`New User Registered in CPG🦧:
      Name : ${newuser.fullName},
      userid:${newuser.userid},
      user_email:${tiger.decrypt(newuser.user_email)}`);
      const otp = func.generateOTP(false);
      // const setotp = await rediscon.otpredis(newuser.user_email, 123456);
      const setotp = await rediscon.otpredis(newuser.user_email, otp);
      console.log(setotp, "setotp");

      res.status(200).send("Otp Sent Successfully");
    } catch (err) {
      res.status(500).send("Server error");
    }
  })
);
router.post(
  "/Registrationotpverifications",
  ratelimiter,
  errhandler(async (req, res) => {
    var { error } = validations.Otpverify(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const user = await mongofunctions.find_one(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(req.body.user_email) })
    );
    if (!user) {
      return res.status(400).send("No User Exists With Given email");
    }

    const getotp = await rediscon.otpget(user.user_email);
    console.log(getotp, req.body.otp, "getotp");
    if (!getotp) {
      return res.status(400).send("otp expired");
    }
    if (Number(getotp) !== Number(req.body.otp)) {
      return res.status(400).send("Invalid otp");
    }
    const userstatus = await mongofunctions.findoneandupdate(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(req.body.user_email) }),
      (update = { status: "enabled" }),
      (options = { new: true })
    );
    const token = jwt.sign(
      {
        userid: userstatus.userid,
        fullName: userstatus.fullName,
        user_email: userstatus.user_email,
        status: userstatus.status,

        //cryptoaddress: userstatus.cryptoaddress,
      },
      process.env.jwtPrivateKey,
      { expiresIn: "90d" }
    );
    return res.status(200).send(token);
  })
);
router.post(
  "/logins",
  ratelimiter,
  errhandler(async (req, res) => {
    const adminControlsCheck = await rediscon.redisexistshash(
      "adminTransactions",
      "adminControls"
    );
    if (adminControlsCheck === 0 || adminControlsCheck === false)
      return res.status(400).send("Admin Controls Not Added in Redis.");
    const admin = await rediscon.redisgethash(
      "adminTransactions",
      "adminControls"
    );
    console.log(admin, "admin");
    if (admin.login !== "Enable")
      return res.status(400).send("Login Suspended by Admin");

    var { error } = validations.LoginOtps(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const user = await mongofunctions.find_one(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(req.body.user_email) })
    );
    if (!user) {
      return res.status(400).send("No User Exists With Given Email");
    }

    const valpass = await bcrypt.compare(req.body.password, user.password);
    if (!valpass) return res.status(400).send("Incorrect Password");
    const setotp = await rediscon.otpredis(user.user_email, 123456);
    console.log(setotp, "setotp");

    res.status(200).send("Otp Sent Successfully");
  })
);
router.post(
  "/otpverifications",
  ratelimiter,
  errhandler(async (req, res) => {
    var { error } = validations.Otpverify(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const user = await mongofunctions.find_one(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(req.body.user_email) })
    );
    if (!user) {
      return res.status(400).send("No User Exists With Given email");
    }

    const getotp = await rediscon.otpget(user.user_email);
    console.log(getotp, req.body.otp, "getotp");
    if (!getotp) {
      return res.status(400).send("otp expired");
    }
    if (Number(getotp) !== Number(req.body.otp)) {
      return res.status(400).send("Invalid otp");
    }

    const token = jwt.sign(
      {
        userid: user.userid,
        fullName: user.fullName,
        user_email: user.user_email,
        status: user.status,

        //cryptoaddress: user.cryptoaddress,
      },
      process.env.jwtPrivateKey,
      { expiresIn: "90d" }
    );
    await rediscon.mark_otp_used(user.user_email);
    return res.status(200).send(token);
  })
);
router.post(
  "/resendotp",
  ratelimiter,
  errhandler(async (req, res) => {
    var { error } = validations.resend(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const resend = await mongofunctions.find_one(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(req.body.user_email) })
    );

    if (!resend) return res.status(400).send("User Not Found.");

    await rediscon.otpredis(resend.user_email, 1234567);
    return res.status(200).send("Otp Sent Successfully");
  })
);
router.post(
  "/PasswordChanges",
  auth,
  ratelimiter,
  errhandler(async (req, res) => {
    var { error } = validations.changePassword(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const user_email = tiger.encrypt(req.body.user_email);
    var user = await mongofunctions.find_one("User", {
      user_email: user_email,
    });
    if (!user) return res.status(400).send("User Email Does Not Exists.");
    const setotp = await rediscon.otpredis(user.user_email, 123456);
    console.log(setotp, "setotp");

    return res
      .status(200)
      .send(`Otp Sent Successfully to this ${req.body.user_email}`);
  })
);
router.post(
  "/chngpswdotpverifications",
  ratelimiter,
  errhandler(async (req, res) => {
    var { error } = validations.chngpswdOtpverify(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const user = await mongofunctions.find_one(
      (collection = "User"),
      (condition = { user_email: tiger.encrypt(req.body.user_email) })
    );
    if (!user) {
      return res.status(400).send("No User Exists With Given email");
    }

    const getotp = await rediscon.otpget(user.user_email);
    console.log(getotp, req.body.otp, "getotp");
    if (!getotp) {
      return res.status(400).send("otp expired");
    }
    if (Number(getotp) !== Number(req.body.otp)) {
      return res.status(400).send("Invalid otp");
    }

    const salt = await bcrypt.genSalt(10);
    password = await bcrypt.hash(req.body.password, salt);
    const updtuser = await mongofunctions.findoneandupdate(
      "User",
      {
        user_email: tiger.encrypt(req.body.user_email),
      },
      { password: password },
      { new: true }
    );
    const redisuser = await rediscon.redisinserthash(
      "CPGUSERS",
      user.userid,
      JSON.stringify(updtuser)
    );
    teleg.alert_Dev(` User updated password in CPG🦧 for ${tiger.decrypt(
      updtuser.user_email
    )} by
     ${updtuser.fullName}`);
    const token = jwt.sign(
      {
        userid: updtuser.userid,
        fullName: updtuser.fullName,
        user_email: updtuser.user_email,
        status: updtuser.status,
        balances: updtuser.balances,
        cryptoaddress: updtuser.cryptoaddress,
      },
      process.env.jwtPrivateKey,
      { expiresIn: "90d" }
    );
    return res.status(200).send(token);
  })
);
router.post(
  "/getusersdetail",
  auth,
  ratecutter,
  errhandler(async (req, res) => {
    console.log(req.user, "requser");
    const user = JSON.parse(req.user);
    console.log(user.userid, "user");
    const redisusercheck = await rediscon.redisexistshash(
      "CPGUSERS",
      user.userid
    );
    if (!redisusercheck) {
      return res.status(400).send("User not found in redis ");
    }
    const redisgetuser = await rediscon.redisgethash("CPGUSERS", user.userid);
    const userObj = JSON.parse(redisgetuser);
    delete userObj.createdAt;
    delete userObj.updatedAt;
    delete userObj.password;
    delete userObj.__v;
    delete userObj._id;

    userObj.user_email = tiger.decrypt(userObj.user_email);
    console.log(userObj, "userObj");

    return res.status(200).send(userObj);
  })
);
router.post("/generateapikeys", auth, async (req, res) => {
  try {
    console.log(req.user, "req.user");

    const user = await mongofunctions.find_one("User", {
      userid: req.user.userid,
    });

    console.log(user, "user");

    if (!user) {
      return res.status(400).send({ message: "User not found" });
    }
    console.log(user, "user");

    if (user.address.API_keys) {
      return res.status(200).send({
        keys: {
          API_KEY: user.address.API_keys.api_key,
          SECRECT_KEY: user.address.API_keys.secrect_key,
        },
      });
    }
    var API_keys = {
      api_key: crypto.APIencryption({
        userid: user.userid,
      }),
      secrect_key: crypto.APIencryption({
        userid: user.userid,
        email: user.email,
      }),
    };
    console.log(API_keys, "API_keys");
    var update_user = await mongofunctions.findoneandupdate(
      "User",
      { userid: user.userid },
      { "address.API_keys": API_keys },
      { new: true }
    );
    const redisuser = await rediscon.UserData(update_user.userid);
    console.log(redisuser, "redisuser");
    return res.status(200).send({
      success: `API Keys Generated Successfull.`,
      keys: {
        API_KEY: API_keys.api_key,
        SECRECT_KEY: API_keys.secrect_key,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});
router.post("/cryptoaddresses", auth, async (req, res) => {
  try {
    const user = await mongofunctions.find_one("User", {
      userid: req.user.userid,
    });

    console.log(user, "user");

    if (!user) {
      return res.status(400).send({ message: "User not found" });
    }
    console.log(user, "user");

    if (
      user.cryptoaddress.bitcoin !== "0" &&
      user.cryptoaddress.usdt !== "0" &&
      user.cryptoaddress.busd !== "0"
    ) {
      return res.status(200).send({
        bitcoin: user.cryptoaddress.bitcoin,
        usdt: user.cryptoaddress.usdt,
        busd: user.cryptoaddress.busd,
      });
    } else {
      var cryptoaddress = {
        bitcoin: func.bitcoin(),
        usdt: func.usdt(),
        busd: func.busd(),
      };

      var update_user = await mongofunctions.findoneandupdate(
        "User",
        { userid: user.userid },
        { cryptoaddress: cryptoaddress },
        { new: true }
      );

      return res.status(200).send({
        bitcoin: update_user.cryptoaddress.bitcoin,
        usdt: update_user.cryptoaddress.usdt,
        busd: update_user.cryptoaddress.busd,
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
