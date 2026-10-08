const { model } = require("mongoose");

const { TicketSchema } = require("../schemas/TicketSchema");

const TicketModel = new model("ticket", TicketSchema);

module.exports = { TicketModel };
