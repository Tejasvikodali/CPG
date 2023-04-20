const mongoose = require("mongoose");
// admin controls
const admin_controlSchema = new mongoose.Schema(
  {
    register: { type: String, required: true, default: "Enable" },
    login: { type: String, required: true, default: "Enable" },
    // isActive: { type: Boolean, required: true, default: true },
    // fees: {
    //   percentage: { type: Number },
    //   fixed: { type: Number },
    // },
    transfer: { type: String, required: true, default: "Enable" },
  },
  {
    timestamps: true,
  }
);

const Admin_control = mongoose.model("Admin_control", admin_controlSchema);

exports.Admin_control = Admin_control;
// withdraw;
// userwise;
