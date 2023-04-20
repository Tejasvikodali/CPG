const axios = require("axios");
module.exports = async function (captchadata) {
  const rawResponse = await axios({
    method: "post",
    url: "https://www.google.com/recaptcha/api/siteverify",
    data: `secret=${process.env.SECRET_KEY}&response=` + captchadata,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
  });
  console.log(rawResponse.data, "rawResponse.data");
  return rawResponse.data;
};
