const { model } = require("mongoose");

const { LogSchema } = require("../schemas/LogSchema");

const LogModel = new model("log", LogSchema);

module.exports = { LogModel };
