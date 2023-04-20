const mongoose = require("mongoose");
const teleg = require("../helpers/telegram");
const { User } = require("../models/users");
const { Admin_control } = require("../models/admin/admincontrols");

module.exports = {
  //insert data
  insert: async (collectionName, condition) => {
    try {
      var result = await eval(collectionName);

      const reply = await result.create(condition);

      return reply;
    } catch (error) {
      console.error(error);
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${error.stack}  \n ❌❌❌❌❌❌👎`
      );
      return "Error finding document";
    }
  },
  //find query
  find: async (collection) => {
    try {
      const result = await eval(collection);
      const reply = await result.find({});
      return reply;
    } catch (error) {
      console.error(error);
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${error.stack}  \n ❌❌❌❌❌❌👎`
      );
      return "Error finding document";
    }
  },
  //distinct
  distinct: async (collection, condition) => {
    try {
      const result = await eval(collection);
      const reply = await result.distinct(condition);
      return reply;
    } catch (error) {
      console.error(error);
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${error.stack}  \n ❌❌❌❌❌❌👎`
      );
      return "Error finding document";
    }
  },
  //find
  find_one: async (collection, condition, select, sort) => {
    return await eval(collection).findOne(condition).select(select).sort(sort);
  },
  //findone with sort
  findonesort: async (collection, sort) => {
    try {
      const result = await eval(collection);
      const reply = await result.findOne().sort(sort);
      return reply;
    } catch (error) {
      console.error(error);
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${error.stack}  \n ❌❌❌❌❌❌👎`
      );
      return "Error finding document";
    }
  },
  //find with sort
  findandsort: async (collection, sort, select) => {
    try {
      const result = await eval(collection);
      const reply = await result.find({}).sort(sort).select(select);
      return reply;
    } catch (error) {
      console.error(error);
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${error.stack}  \n ❌❌❌❌❌❌👎`
      );
      return "Error finding document";
    }
  },
  //findone
  findone: async (collection, condition) => {
    try {
      const result = await eval(collection);
      const reply = await result.findOne(condition);
      return reply;
    } catch (error) {
      console.error(error);
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${error.stack}  \n ❌❌❌❌❌❌👎`
      );
      return "Error finding document";
    }
  },
  //findoneandupdate
  findoneandupdate: async (collectionName, condition, update, options) => {
    try {
      const result = await eval(collectionName);
      console.log(result, "resultasdfgh");
      const reply = await result.findOneAndUpdate(condition, update, options);
      console.log(reply, "replyzxcvb");
      return reply;
    } catch (error) {
      console.error(error);
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${error.stack}  \n ❌❌❌❌❌❌👎`
      );
      return "Error finding document";
    }
  },
  //findoneand delete
  findoneanddelete: async (collectionName, condition) => {
    try {
      const result = await eval(collectionName);
      console.log(result, "resultasdfgh");
      const reply = await result.findOneAndDelete(condition);
      console.log(reply, "replyzxcvb");
      return reply;
    } catch (error) {
      console.error(error);
      teleg.alert_Dev(
        `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${error.stack}  \n ❌❌❌❌❌❌👎`
      );
      return "Error finding document";
    }
  },
  find_with_projection: async (
    collection,
    condition,
    projection,
    sort,
    select,
    limit,
    skip
  ) => {
    // await Chat.find({},)
    teleg.alert_Dev(
      `👎❌❌❌❌ \n err in route 👉🏻🙆‍♀️👉🏻🙆‍♀️👉🏻--> ${req.originalUrl} \n\n ${error.stack}  \n ❌❌❌❌❌❌👎`
    );
    return await eval(collection)
      .find(condition, projection)
      .select(select)
      .sort(sort)
      .limit(limit)
      .skip(skip);
  },
};
