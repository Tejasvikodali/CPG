const express = require("express");
const router = express.Router();
const rediscon = require("../../redis/rediscon");
const mongofunctions = require("../../helpers/mongofunctions");
const crypto = require("../../helpers/cryp");
//add admin controls
router.post("/addadmincontrols", async (req, res) => {
  var obj = {
    register: "Enable",
    login: "Enable",

    transfer: "Enable",
  };
  const admin = await mongofunctions.insert(
    (collection = "Admin_control"),
    (data = obj)
  );
  console.log(admin, "admin");
  //await rediscon.AdminControls();
  await rediscon.redisinserthash(
    "AdminControls",
    "Admincontrols",
    JSON.stringify(admin)
  );
  return res.status(200).send(crypto.encrypt("Admin controls added"));
});
//get admin controls from redis
router.post("/getadmincontrols", async (req, res) => {
  const adminexists = await rediscon.redisexistshash(
    "AdminControls",
    "Admincontrols"
  );
  if (!adminexists) {
    return res.status(400).send("admincontrols not found");
  }
  const getadmin = await rediscon.redisgethash(
    "AdminControls",
    "Admincontrols"
  );
  return res.status(200).send(crypto.encryptobj(getadmin));
});

module.exports = router;
