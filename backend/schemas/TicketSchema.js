const { Schema } = require("mongoose");

const TicketSchema = new Schema({
  topic: String,
  email: String,
  message: String,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = { TicketSchema };
