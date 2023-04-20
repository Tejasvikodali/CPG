const Joi = require("joi");

module.exports = {
  registration: (data) => {
    const schema = Joi.object({
      fullName: Joi.string().trim().min(5).max(50).required(),
      user_email: Joi.string().email(),
      password: Joi.string()
        .min(8)
        .max(20)
        .required()
        .pattern(
          new RegExp(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})"
          )
        )
        .messages({
          "string.pattern.base":
            "Password must contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character (!@#$%^&*)",
        }),
      captcha: Joi.string().required(),

      // balances: Joi.object().required(),
      // cryptoaddress: Joi.object().required(),
    });
    //.options({ convert: false });
    return schema.validate(data);
  },
  registrations: (data) => {
    const schema = Joi.object({
      fullName: Joi.string().trim().min(5).max(50).required(),
      user_email: Joi.string().email(),
      password: Joi.string()
        .min(8)
        .max(20)
        .required()
        .pattern(
          new RegExp(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})"
          )
        )
        .messages({
          "string.pattern.base":
            "Password must contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character (!@#$%^&*)",
        }),
      //captcha: Joi.string().required(),

      // balances: Joi.object().required(),
      // cryptoaddress: Joi.object().required(),
    });
    //.options({ convert: false });

    return schema.validate(data);
  },
  getenc: (data) => {
    const schema = Joi.object({
      enc: Joi.string().required(),
    });
    return schema.validate(data);
  },
  LoginOtp: (data) => {
    const schema = Joi.object({
      user_email: Joi.string().email(),
      password: Joi.string()
        .min(8)
        .max(20)
        .required()
        .pattern(
          new RegExp(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})"
          )
        )
        .messages({
          "string.pattern.base":
            "Password must contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character (!@#$%^&*)",
        }),
      //otp: Joi.string().required(),

      captcha: Joi.string(),
    });
    return schema.validate(data);
  },
  LoginOtps: (data) => {
    const schema = Joi.object({
      user_email: Joi.string().email(),
      password: Joi.string().min(8).max(20).required().messages({
        "string.pattern.base":
          "Password must contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character (!@#$%^&*)",
      }),
      //otp: Joi.string().required(),

      //captcha: Joi.string(),
    });
    return schema.validate(data);
  },
  Otpverify: (data) => {
    const schema = Joi.object({
      otp: Joi.string().required(),
      user_email: Joi.string().required().email(),
      // password: Joi.string()
      //   .min(8)
      //   .max(20)
      //   .required()
      //   .pattern(
      //     new RegExp(
      //       "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})"
      //     )
      //   ),
    });
    return schema.validate(data);
  },
  resend: (data) => {
    const schema = Joi.object({
      user_email: Joi.string().email(),
    });
    return schema.validate(data);
  },
  changePassword: (data) => {
    const schema = Joi.object({
      user_email: Joi.string().email(),
      captcha: Joi.string().required(),
    });
    return schema.validate(data);
  },
  chngpswdOtpverify: (data) => {
    const schema = Joi.object({
      otp: Joi.string().required(),
      user_email: Joi.string().email(),
      password: Joi.string()
        .min(8)
        .max(20)
        .required()
        .pattern(
          new RegExp(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})"
          )
        )
        .messages({
          "string.pattern.base":
            "Password must contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character (!@#$%^&*)",
        }),
    });
    return schema.validate(data);
  },
  getdetails: (data) => {
    const schema = Joi.object({
      userid: Joi.string().required(),
    });
    return schema.validate(data);
  },
  generateapi: (data) => {
    const schema = Joi.object({
      //email: Joi.string().email(),
      userid: Joi.string().required(),
    });
    return schema.validate(data);
  },
};
