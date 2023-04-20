// router.post(
//   "/usercheck",
//   errhandler(async (req, res) => {
//     try {
//       const admin = await rediscon.redisgethash(
//         "adminTransactions",
//         "adminControls"
//       );
//       console.log(admin, "admin");
//       if (admin.register !== "Enable")
//         return res.status(400).send("Registration Suspended by Admin");
//       var { error } = validate.getenc(req.body);
//       if (error) return res.status(400).send(error.details[0].message);
//       const data = crypto.decryptobj(req.body.enc);
//       if (data === "tberror") return res.status(400).send("Invalid Parameter");

//       var { error } = await validations.registration(data);
//       if (error) {
//         return res.status(400).send(error.details[0].message);
//       }

//       const userid = functions.userid();
//       const email = tiger.encrypt(user_email);
//       data.user_email = email;
//       const user = await mongofunctions.findone(
//         (collectionName = "User"),
//         (condition = {
//           user_email: email,
//         })
//       );
//       console.log(user, "user");
//       if (user) {
//         return res.status(400).send("User already exists");
//       }
//       const salt = await bcrypt.genSalt(10);
//       const hashpassword = await bcrypt.hash(data.password, salt);

//       const newuser = await mongofunctions.insert(
//         (collectionName = "User"),
//         (condition = {
//           userid: userid,
//           user_name: data.user_name,
//           user_email: data.user_email,
//           password: hashpassword,
//           balances: data.balances,
//           cryptoaddress: data.cryptoaddress,
//         })
//       );
//       console.log(newuser, "newuser");

//       teleg.alert_Dev(`New User Registered in CPG🦧:
//       Name : ${newuser.user_name},
//       userid:${newuser.userid},
//       user_email:${newuser.user_email}`);

//       res.status(200).json(newuser);
//     } catch (err) {
//       teleg.alert_Dev(
//         `👎❌❌❌❌ \n err in route 👉🏻👉🏻👉🏻--> ${req.originalUrl} \n\n ${err.stack}  \n ❌❌❌❌❌❌`
//       );
//       res.status(500).send("Server error");
//     }
//   })
// );
const otpGenerator = require("otp-generator");

router.post(
  "/usercheck",
  verifyRecaptcha,
  errhandler(async (req, res) => {
    try {
      const admin = await rediscon.redisgethash(
        "adminTransactions",
        "adminControls"
      );
      console.log(admin, "admin");
      if (admin.register !== "Enable")
        return res.status(400).send("Registration Suspended by Admin");

      var { error } = await validations.registration(req.body);
      if (error) {
        return res.status(400).send(error.details[0].message);
      }
      console.log(req.body, "req.body");

      const userid = functions.userid();
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

      // Generate OTP and send it to the user's email
      const otp = otpGenerator.generate(6, {
        digits: true,
        alphabets: false,
        upperCase: false,
        specialChars: false,
      });
      console.log(otp, "OTP");

      // TODO: Send the OTP to the user's email using a third-party email service like nodemailer

      // Check if the sent OTP matches the one provided in the request
      if (req.body.otp !== otp) {
        return res.status(400).send("Invalid OTP");
      }

      const salt = await bcrypt.genSalt(10);
      const hashpassword = await bcrypt.hash(req.body.password, salt);

      const newuser = await mongofunctions.insert(
        (collectionName = "User"),
        (condition = {
          userid: userid,
          user_name: req.body.user_name,
          user_email: tiger.encrypt(req.body.user_email),
          password: hashpassword,
        })
      );

      teleg.alert_Dev(`New User Registered in CPG🦧:
      Name : ${newuser.user_name},
      userid:${newuser.userid},
      user_email:${tiger.decrypt(newuser.user_email)}`);

      res.status(200).json(newuser);
    } catch (err) {
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻👉🏻👉🏻--> ${req.originalUrl} \n\n ${err.stack}  \n ❌❌❌❌❌❌`
      );
      res.status(500).send("Server error");
    }
  })
);
router.post(
  "/usercheck",
  verifyRecaptcha,
  errhandler(async (req, res) => {
    try {
      const admin = await rediscon.redisgethash(
        "adminTransactions",
        "adminControls"
      );
      console.log(admin, "admin");
      if (admin.register !== "Enable")
        return res.status(400).send("Registration Suspended by Admin");

      var { error } = await validations.registration(req.body);
      if (error) {
        return res.status(400).send(error.details[0].message);
      }
      console.log(req.body, "req.body");

      const userid = functions.userid();
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

      // Generate OTP
      const otp = generateOTP();

      // Store OTP in Redis with user_email as key
      await rediscon.redisclient.set(req.body.user_email, otp);

      // Send OTP to user_email
      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.EMAIL_USERNAME,
          pass: process.env.EMAIL_PASSWORD,
        },
      });

      const mailOptions = {
        from: process.env.EMAIL_USERNAME,
        to: req.body.user_email,
        subject: "Your OTP for registration",
        text: `Your OTP is: ${otp}`,
      };

      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          console.log(error);
        } else {
          console.log("Email sent: " + info.response);
        }
      });

      const salt = await bcrypt.genSalt(10);
      const hashpassword = await bcrypt.hash(req.body.password, salt);

      const newuser = await mongofunctions.insert(
        (collectionName = "User"),
        (condition = {
          userid: userid,
          user_name: req.body.user_name,
          user_email: tiger.encrypt(req.body.user_email),
          password: hashpassword,
        })
      );

      teleg.alert_Dev(`New User Registered in CPG🦧:
      Name : ${newuser.user_name},
      userid:${newuser.userid},
      user_email:${tiger.decrypt(newuser.user_email)}`);

      res.status(200).json(newuser);
    } catch (err) {
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻👉🏻👉🏻--> ${req.originalUrl} \n\n ${err.stack}  \n ❌❌❌❌❌❌`
      );
      res.status(500).send("Server error");
    }
  })
);
// OTP: (dev) => {
//   if (dev) {
//     return 654321;
//   }
//   return Math.floor(100000 + Math.random() * 900000);
// },
// genOtp: async (key, value) => {
//   //const otp = JSON.stringify(value);
//   await client.setEx(key, 180, value.toString(), (err, res) => {});
// },
// const rp = require("request-promise");
// //const qs = require("querystring");

// const verifyRecaptcha = async (req, res, next) => {
//   try {
// const recaptchaResponse = req.body.recaptcha;
// const secretKey = process.env.SECRET_KEY;

// const options = {
//   method: "POST",
//   uri: "https://www.google.com/recaptcha/api/siteverify",
//   form: {
//     secret: secretKey,
//     response: recaptchaResponse,
//     remoteip: req.ip,
//   },
//   json: true,
// };

// const response = await rp(options);

//     if (response.success) {
//       // reCAPTCHA verification successful, proceed to the next middleware/route handler
//       next();
//     } else {
//       // reCAPTCHA verification failed, return an error response
//       res.status(400).send("reCAPTCHA verification failed");
//     }
//   } catch (error) {
//     console.error(error);
//     res.status(500).send("Server error");
//   }
// };

// module.exports = verifyRecaptcha;
// const rp = require("request-promise");

// module.exports = async function (datatosend) {
//   const recaptchaResponse = datatosend;
//   const secretKey = process.env.SECRET_KEY;

//   const options = {
//     method: "POST",
//     uri: "https://www.google.com/recaptcha/api/siteverify",
//     form: {
//       secret: secretKey,
//       response: recaptchaResponse,
//       //remoteip: req.ip,
//     },
//     json: true,
//   };

//   const response = await rp(options);
//   return response;
// };
//Regitration without enc
router.post(
  "/userscheck",
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

      var { error } = await validations.registration(req.body);
      if (error) {
        return res.status(400).send(error.details[0].message);
      }
      console.log(req.body, "req.body");

      // const validcap = await verifyRecaptcha(req.body.captcha);

      // if (validcap.success !== true) {
      //   return res.status(400).send(" Invalid Captcha");
      // }
      const userid = functions.userid();
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
          user_name: req.body.user_name,
          user_email: tiger.encrypt(req.body.user_email),
          password: hashpassword,
        })
      );

      teleg.alert_Dev(`New User Registered in CPG🦧:
      Name : ${newuser.user_name},
      userid:${newuser.userid},
      user_email:${tiger.decrypt(newuser.user_email)}`);
      const setotp = await rediscon.otpredis(
        tiger.decrypt(newuser.user_email),
        123456
      );
      console.log(setotp, "setotp");

      res.status(200).json("Otp Sent Successfully");
    } catch (err) {
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻👉🏻👉🏻--> ${req.originalUrl} \n\n ${err.stack}  \n ❌❌❌❌❌❌`
      );
      res.status(500).send("Server error");
    }
  })
);
// //Regitration with enc
// router.post(
//   "/userregistration",
//   errhandler(async (req, res) => {
//     try {
//       const admin = await rediscon.redisgethash(
//         "adminTransactions",
//         "adminControls"
//       );
//       console.log(admin, "admin");
//       if (admin.register !== "Enable")
//         return res.status(400).send("Registration Suspended by Admin");
//       var { error } = validations.getenc(req.body);
//       if (error) return res.status(400).send(error.details[0].message);
//       console.log(req.body.enc, "FE");
//       const data = crypto.decryptobj(req.body.enc);
//       console.log(data, "data");
//       if (data === "tberror") return res.status(400).send("Invalid Parameter");

//       var { error } = await validations.registration(data);
//       if (error) {
//         return res.status(400).send(error.details[0].message);
//       }

//       if (data.captcha) {
//         const validcap = await verifyRecaptcha(data.captcha);

//         if (validcap.success !== true)
//           return res.status(400).send(" Invalid Captcha");
//       }
//       const userid = functions.userid();

//       const user = await mongofunctions.findone(
//         (collectionName = "User"),
//         (condition = {
//           user_email: tiger.encrypt(data.user_email),
//         })
//       );

//       if (user) {
//         return res.status(400).send("User already exists");
//       }
//       const salt = await bcrypt.genSalt(10);
//       const hashpassword = await bcrypt.hash(data.password, salt);

//       const newuser = await mongofunctions.insert(
//         (collectionName = "User"),
//         (condition = {
//           userid: userid,
//           user_name: data.user_name,
//           user_email: tiger.encrypt(data.user_email),
//           password: hashpassword,
//         })
//       );
//       const redisuser = await rediscon.redisinserthash(
//         "CPGUsers",
//         newuser.user_email
//       );
//       console.log(redisuser, "redisuser");

//       teleg.alert_Dev(`New User Registered in CPG🦧:
//       Name : ${newuser.user_name},
//       userid:${newuser.userid},
//       user_email:${tiger.decrypt(newuser.user_email)}`);
//       const setotp = await rediscon.genOtp(newuser.user_email, 123456);
//       console.log(setotp, "setotp");

//       res.status(200).json(crypto.encrypt("OTP sent Successfully"));
//     } catch (err) {
//       teleg.alert_Dev(
//         `👎❌❌❌❌ \n err in route 👉🏻👉🏻👉🏻--> ${req.originalUrl} \n\n ${err.stack}  \n ❌❌❌❌❌❌`
//       );
//       res.status(500).send("Server error");
//     }
//   })
// );
// //Regitration without enc
// router.post(
//   "/userscheck",
//   errhandler(async (req, res) => {
//     try {
//       const adminControlsCheck = await rediscon.redisexistshash(
//         "adminTransactions",
//         "adminControls"
//       );
//       if (adminControlsCheck === 0 || adminControlsCheck === false)
//         return res.status(400).send("Admin Controls Not Added in Redis.");
//       const admin = await rediscon.redisgethash(
//         "adminTransactions",
//         "adminControls"
//       );
//       console.log(admin, "admin");
//       if (admin.register !== "Enable")
//         return res.status(400).send("Registration Suspended by Admin");

//       var { error } = await validations.registrations(req.body);
//       if (error) {
//         return res.status(400).send(error.details[0].message);
//       }
//       console.log(req.body, "req.body");

//       const userid = functions.userid();
//       console.log(userid, "userid");

//       const user = await mongofunctions.findone(
//         (collectionName = "User"),
//         (condition = {
//           user_email: tiger.encrypt(req.body.user_email),
//         })
//       );
//       console.log(user, "user");
//       if (user) {
//         return res.status(400).send("User already exists");
//       }
//       const salt = await bcrypt.genSalt(10);
//       const hashpassword = await bcrypt.hash(req.body.password, salt);

//       const newuser = await mongofunctions.insert(
//         (collectionName = "User"),
//         (condition = {
//           userid: userid,
//           user_name: req.body.user_name,
//           user_email: tiger.encrypt(req.body.user_email),
//           password: hashpassword,
//           status: "disabled",
//         })
//       );
//       console.log(newuser, "newuser");
//       const redisuser = await rediscon.redisinserthash(
//         "CPGUsers",
//         newuser.user_email,
//         JSON.stringify(newuser)
//       );
//       console.log(redisuser, "redisuser");

//       teleg.alert_Dev(`New User Registered in CPG🦧:
//       Name : ${newuser.user_name},
//       userid:${newuser.userid},
//       user_email:${tiger.decrypt(newuser.user_email)}`);
//       const setotp = await rediscon.otpredis(newuser.user_email, 123456);
//       console.log(setotp, "setotp");

//       res.status(200).json(crypto.encrypt("Otp Sent Successfully"));
//     } catch (err) {
//       teleg.alert_Dev(
//         `👎❌❌❌❌ \n err in route 👉🏻👉🏻👉🏻--> ${req.originalUrl} \n\n ${err.stack}  \n ❌❌❌❌❌❌`
//       );
//       res.status(500).send("Server error");
//     }
//   })
// );

// //Otp verfied route with enc
// router.post(
//   "/otpverification",
//   errhandler(async (req, res) => {
//     var { error } = validations.getenc(req.body);
//     if (error) return res.status(400).send(error.details[0].message);
//     console.log(req.body.enc, "FE");
//     const data = crypto.decryptobj(req.body.enc);
//     console.log(data, "data");
//     if (data === "tberror") return res.status(400).send("Invalid Parameter");
//     var { error } = validations.Otpverify(data);
//     if (error) return res.status(400).send(error.details[0].message);
//     var user_email = tiger.encrypt(data.user_email);
//     console.log(user_email, "user_email");

//     const user = await mongofunctions.find_one(
//       (collection = "User"),
//       (condition = { user_email: user_email })
//     );
//     if (!user) {
//       return res.status(400).send("No User Exists With Given Email");
//     }

//     const getotp = await rediscon.otpget(tiger.decrypt(user.user_email));
//     console.log(getotp, data.otp, "getotp,enteredotp");
//     if (!getotp) {
//       return res.status(400).send("otp expired");
//     }
//     if (Number(getotp) !== Number(data.otp)) {
//       return res.status(400).send("Invalid otp");
//     }
//     const userstatus = await mongofunctions.findoneandupdate(
//       (collection = "User"),
//       (condition = { user_email: user_email }),
//       (update = { status: "enabled" }),
//       (options = { new: true })
//     );
//     const token = jwt.sign(
//       {
//         userid: userstatus.userid,
//         user_name: userstatus.user_name,
//         user_email: userstatus.user_email,
//         status: userstatus.status,
//         balances: userstatus.balances,
//         cryptoaddress: userstatus.cryptoaddress,
//       },
//       process.env.jwtPrivateKey,
//       { expiresIn: "90d" }
//     );
//     return res.status(200).send(crypto.encrypt(token));
//   })
// );
// //Otp verified route without enc
// router.post(
//   "/otpverifications",
//   errhandler(async (req, res) => {
//     var { error } = validations.Otpverify(req.body);
//     if (error) return res.status(400).send(error.details[0].message);
//     var user_email = tiger.encrypt(req.body.user_email);
//     console.log(user_email, "user_email");

//     const user = await mongofunctions.find_one(
//       (collection = "User"),
//       (condition = { user_email: user_email })
//     );
//     if (!user) {
//       return res.status(400).send("No User Exists With Given email");
//     }

//     const getotp = await rediscon.otpget(user.user_email);
//     console.log(getotp, req.body.otp, "getotp");
//     if (getotp == null) {
//       return res.status(400).send("otp expired");
//     }
//     if (Number(getotp) !== Number(req.body.otp)) {
//       return res.status(400).send("Invalid otp");
//     }
//     const userstatus = await mongofunctions.findoneandupdate(
//       (collection = "User"),
//       (condition = { user_email: user_email }),
//       (update = { status: "enabled" }),
//       (options = { new: true })
//     );
//     const token = jwt.sign(
//       {
//         userid: userstatus.userid,
//         user_name: userstatus.user_name,
//         user_email: userstatus.user_email,
//       },
//       process.env.jwtPrivateKey,
//       { expiresIn: "90d" }
//     );
//     return res.status(200).send(crypto.encrypt(token));
//   })
// );
// //login with enc
// router.post(
//   "/login",
//   errhandler(async (req, res) => {
//     const adminControlsCheck = await rediscon.redisexistshash(
//       "adminTransactions",
//       "adminControls"
//     );
//     if (adminControlsCheck === 0 || adminControlsCheck === false)
//       return res.status(400).send("Admin Controls Not Added in Redis.");
//     const admin = await rediscon.redisgethash(
//       "adminTransactions",
//       "adminControls"
//     );
//     console.log(admin, "admin");
//     if (admin.login !== "Enable")
//       return res.status(400).send("Login Suspended by Admin");
//     var { error } = validations.getenc(req.body);
//     if (error) return res.status(400).send(error.details[0].message);
//     const data = crypto.decryptobj(req.body.enc);
//     if (data === "tberror") return res.status(400).send("Invalid Parameter");
//     var { error } = validations.LoginOtp(data);
//     if (error) return res.status(400).send(error.details[0].message);
//     var user_email = tiger.encrypt(data.user_email);
//     console.log(user_email, "user_email");

//     const user = await mongofunctions.find_one(
//       (collection = "User"),
//       (condition = { user_email: user_email })
//     );
//     if (!user) {
//       return res.status(400).send("No User Exists With Given email");
//     }

//     const valpass = await bcrypt.compare(data.password, user.password);
//     if (!valpass) return res.status(400).send("Incorrect Password");

//     if (data.captcha) {
//       const validcap = await verifyRecaptcha(data.captcha);

//       if (validcap.success !== true)
//         return res.status(400).send(" Invalid Captcha");
//     }

//     const token = jwt.sign(
//       {
//         userid: user.userid,
//         user_name: user.user_name,
//         user_email: user.user_email,
//       },
//       process.env.jwtPrivateKey,
//       { expiresIn: "90d" }
//     );
//     return res.status(200).send(crypto.encrypt(token));
//   })
// );

// //login withot enc
// router.post(
//   "/logins",
//   errhandler(async (req, res) => {
//     const adminControlsCheck = await rediscon.redisexistshash(
//       "adminTransactions",
//       "adminControls"
//     );
//     if (adminControlsCheck === 0 || adminControlsCheck === false)
//       return res.status(400).send("Admin Controls Not Added in Redis.");
//     const admin = await rediscon.redisgethash(
//       "adminTransactions",
//       "adminControls"
//     );
//     console.log(admin, "admin");
//     if (admin.login !== "Enable")
//       return res.status(400).send("Registration Suspended by Admin");

//     var { error } = validations.LoginOtps(req.body);
//     if (error) return res.status(400).send(error.details[0].message);
//     var user_email = tiger.encrypt(req.body.user_email);
//     console.log(user_email, "user_email");

//     const user = await mongofunctions.find_one(
//       (collection = "User"),
//       (condition = { user_email: user_email })
//     );
//     if (!user) {
//       return res.status(400).send("No User Exists With Given email");
//     }

//     const valpass = await bcrypt.compare(req.body.password, user.password);
//     if (!valpass) return res.status(400).send("Incorrect Password");

//     const token = jwt.sign(
//       {
//         userid: user.userid,
//         user_name: user.user_name,
//         user_email: user.user_email,
//       },
//       process.env.jwtPrivateKey,
//       { expiresIn: "90d" }
//     );
//     return res.status(200).send(token);
//   })
// );

// router.post("/update-balances", async (req, res) => {
//   try {
//     const updateResult = await User.updateMany(
//       {},
//       { $set: { "balances.bitcoin": "100" } }
//     );
//     res.status(200).json({ success: true, updateResult });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ success: false, error: error.message });
//   }
// });
// get all users
router.post(
  "/getuser",
  amw(async (req, res) => {
    const user = await redisfunc.getusers();
    console.log(user, "user");
    return res.status(200).send(user);
  })
);

// insertusers: async () => {
//   const users = await Register.find({});
//   const array = JSON.stringify(users);
//   var data = client.set("users", array);
//   return data;
// },
// getusers: async () => {
//   var get = await client.get("users");
//   if (get) {
//     return get;
//   }
// },
