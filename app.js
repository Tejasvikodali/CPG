const express = require("express");
const app = express();
require("dotenv").config();
require("./helpers/mongodb")();
require("./redis/rediscon");
const { User } = require("./models/users");
const user = require("./routes/user");
const { Admin_control } = require("./models/admin/admincontrols");
const admin = require("./routes/admin/admin");

const port = process.env.PORT || 8090;

const server = app.listen(port, () =>
  console.log(`Listening on port ${port}...🚁`)
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/api/user", user);
app.use("/api/admin", admin);

module.exports = server;

app.get("/", (req, res) => {
  res.send("Hello, CPG!");
});
