const { Schema } = require("mongoose");

const LogSchema = new Schema({
  timestamp: {
    type: Date,
    default: Date.now,
  },
  ip: String,
  endpoint: String,
  method: String,
  payload: Schema.Types.Mixed,
  category: {
    type: String,
    default: "general",
  },
});

module.exports = { LogSchema };
