const { EventEmitter } = require("events");

const telemetryEmitter = new EventEmitter();
let ioInstance = null;
let sseClientsList = [];

function setTelemetryIo(io) {
  ioInstance = io;
  if (ioInstance) {
    ioInstance.on("connection", (socket) => {
      socket.emit("trace:connected", {
        status: "ready",
        timestamp: new Date().toISOString(),
        message: "Live Trace Terminal telemetry channel active",
      });
    });
  }
}

function registerSseClient(res) {
  sseClientsList.push(res);
  res.on("close", () => {
    sseClientsList = sseClientsList.filter((client) => client !== res);
  });
}

function emitTraceLine(entry) {
  const formattedEntry = {
    id: "trace-" + Date.now() + "-" + Math.random().toString(36).substr(2, 5),
    timestamp: new Date().toISOString(),
    time: new Date().toLocaleTimeString(),
    layer: entry.layer || "backend", // 'frontend' | 'backend' | 'mongodb' | 'response' | 'vuln' | 'storage' | 'token'
    activeLayer: entry.activeLayer || entry.layer || "backend", // 'frontend' | 'backend' | 'mongodb' | 'none'
    text: entry.text || "",
    category: entry.category || "general",
    details: entry.details || null,
  };

  // 1. Emit via internal Node.js EventEmitter
  telemetryEmitter.emit("trace:line", formattedEntry);

  // 2. Broadcast via Socket.io
  if (ioInstance) {
    try {
      ioInstance.emit("trace:line", formattedEntry);
      ioInstance.emit("theater:log", {
        timestamp: formattedEntry.time,
        level: formattedEntry.layer.toUpperCase(),
        text: formattedEntry.text,
        detail: formattedEntry.details,
      });
    } catch (err) {}
  }

  // 3. Broadcast to all active SSE subscribers
  const sseData = `data: ${JSON.stringify(formattedEntry)}\n\n`;
  sseClientsList.forEach((client) => {
    try {
      client.write(sseData);
    } catch (e) {}
  });

  return formattedEntry;
}

module.exports = {
  telemetryEmitter,
  setTelemetryIo,
  registerSseClient,
  emitTraceLine,
};
