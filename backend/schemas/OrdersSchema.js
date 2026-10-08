const { Schema } = require("mongoose");

const OrdersSchema = new Schema({
  userId: {
    type: String,
    default: "guest",
  },
  name: String,
  qty: Number,
  price: Number,
  mode: String,
  notes: String,
});

module.exports = { OrdersSchema };