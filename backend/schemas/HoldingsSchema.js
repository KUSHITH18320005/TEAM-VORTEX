const { Schema } = require("mongoose");

const HoldingsSchema = new Schema({
  userId: {
    type: String,
    default: "guest",
  },
  name: String,
  qty: Number,
  avg: Number,
  price: Number,
  net: String,
  day: String,
});

module.exports = { HoldingsSchema };