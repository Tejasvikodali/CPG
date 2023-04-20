const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    userid: { type: String, required: true },
    // user_name: { type: String, required: true },
    fullName: { type: String, required: true },
    user_email: { type: String, required: true, unique: true },
    password: { type: String, required: true },

    balances: {
      bitcoin: { type: String, required: true, default: "0" },
      usdt: { type: String, required: true, default: "0" },
      //peso: { type: String, required: true, default: "0" },
      busd: { type: String, required: true, default: "0" },
    },

    cryptoaddress: {
      bitcoin: { type: String, required: true, default: "0" },
      usdt: { type: String, required: true, default: "0" },
      busd: { type: String, required: true, default: "0" },
    },
    user_status: { type: String, default: "enabled" },
    email_status: { type: String, default: "disabled" },
    address: { type: Object, required: true, default: {} },

    others: { type: Object },
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model("User", userSchema);
exports.User = User;
