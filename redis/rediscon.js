const redis = require("redis");
const teleg = require("../helpers/telegram");
const mongofunctions = require("../helpers/mongofunctions");
const { User } = require("../models/users");

const client = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  auth: process.env.REDIS_AUTH,
});

client.connect();

client.on("connect", () => {
  console.log("Connected to redis!🌹");
});

client.on("error", (err) => {
  console.log("Error in the Connection");
});
module.exports = {
  // redisinsert
  redisInsert: async (hash, data) => {
    const result = JSON.stringify(data);
    var reply = await client.set(hash, result);
    return reply;
  },
  //redisget
  redisGet: async (hash) => {
    try {
      const result = await client.get(hash);
      const reply = JSON.parse(result);

      return reply;
    } catch (err) {
      console.log(err);
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻👉🏻👉🏻--> ${req.originalUrl} \n\n ${ex.stack}  \n ❌❌❌❌❌❌`
      );
      throw err;
    }
  },
  //redisexists
  redisexists: async (key) => {
    var result = await client.exists(key);
    return result;
  },
  //redisinsert hash
  redisinserthash: async (hash, key, data) => {
    const result = JSON.stringify(data);
    var reply = await client.hSet(hash, key, result);
    return reply;
  },
  //redisget hash
  redisgethash: async (hash, key) => {
    const result = await client.hGet(hash, key);
    var reply = JSON.parse(result);
    return reply;
  },
  //redisexists hash
  redisexistshash: async (hash, key) => {
    const result = await client.hExists(hash, key);
    return result;
  },
  //redis delete hash
  redisdelete: async (hash, key) => {
    const result = await client.hDel(hash, key);
    return result;
  },
  //redis delete
  redisdel: async (hash) => {
    const result = await client.del(hash);
    return result;
  },
  //add admin controls
  AdminControls: async () => {
    const AdminControls = await mongofunctions.find_one(
      (collection = "Admin_control"),
      (condition = {})
    );
    await client.hSet(
      "adminTransaction",
      "adminControls",
      JSON.stringify(AdminControls)
    );
  },

  otpredis: async (key, value) => {
    const str = JSON.stringify(value);
    var data = await client.setEx(key, 60, str);
    console.log(data);
    return data;
  },

  genOtp: async (key, value) => {
    try {
      const response = await client.setEx(key, 60, JSON.stringify(value));
      return response;
    } catch (error) {
      console.log("ex-->", error);
      throw error;
    }
  },
  otpget: async (key) => {
    var object = await client.get(key);
    console.log(object);
    return JSON.parse(object);
  },
  mark_otp_used: async (email) => {
    try {
      await client.del(email);
      return true;
    } catch (error) {
      console.log(error);
      return false;
    }
  },
  UserData: async (userid) => {
    const data = await mongofunctions.find_one(
      (collection = "User"),
      (condition = { userid: userid })
    );
    if (data) {
      await client.hSet(
        "CPGUSERS",
        data.userid,
        JSON.stringify(data),
        (err, res) => {}
      );
    }
  },
};
