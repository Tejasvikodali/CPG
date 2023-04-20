const teleg = require("../helpers/telegram");
module.exports = (handler) => {
  return async (req, res, next) => {
    try {
      await handler(req, res);
      // next();
    } catch (ex) {
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${ex.stack}  \n ❌❌❌❌❌❌👎`
      );
      next(ex);
    }
  };
};
