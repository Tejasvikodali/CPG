const axios = require("axios");

sendMessage = async (chatID, messaggio, token) => {
  try {
    var url =
      "https://api.telegram.org/" + token + "/sendMessage?chat_id=" + chatID;
    url = url + "&text=" + encodeURI(messaggio);
    const data = await axios(url);
  } catch (err) {
    console.log("error", err);
  }
};

module.exports = {
  alert_Developers: async (message) => {
    //var token = "bot5744075477:AAEACfXf1jlKmTIZGmFTyTqa0Y3-Nrj-ST8";
    var token = process.env.TELEGRAM_TOKEN;
    var array = Array("1162661322");
    //console.log(array);
    for (var i = 0; i < array.length; i++) {
      await sendMessage(array[i], message, token);
    }
  },
  alert_Dev: async (message) => {
    // var token = "bot5744075477:AAEACfXf1jlKmTIZGmFTyTqa0Y3-Nrj-ST8";
    var token = process.env.TELEGRAM_TOKEN;
    var array = Array("1162661322");
    //console.log(array);
    for (var i = 0; i < array.length; i++) {
      await sendMessage(array[i], message, token);
    }
  },
};

