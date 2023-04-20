const mongoose = require("mongoose");
const teleg = require("../helpers/telegram");

module.exports = function () {
  mongoose.set("strictQuery", false);

  const connectionstring = process.env.MONGO_CONNECTION_STRING;

  mongoose
    .connect(connectionstring, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      autoIndex: true,
    })

    .then(() => {
      console.log("Connected to MongoDB 🍁...");
    })
    .catch((err) => {
      console.error("Could not connect to MongoDB"), console.log(err);
    });
};
