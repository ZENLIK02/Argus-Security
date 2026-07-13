"use strict";

const fs = require("fs");
const http = require("http");
const path = require("path");

const root = path.resolve(__dirname, "..", "test-site");
const port = Math.max(1024, Math.min(65535, Number(process.env.ARGUS_TEST_PORT) || 4173));

http.createServer((request, response) => {
  const pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  if (pathname === "/argus-test-sink") {
    response.writeHead(204, { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "POST, OPTIONS" });
    response.end();
    return;
  }
  const file = path.resolve(root, pathname.replace(/^\/+/, "") || "safe-site.html");
  if (!file.startsWith(`${root}${path.sep}`) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    response.writeHead(404);
    response.end("Not found");
    return;
  }
  response.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  fs.createReadStream(file).pipe(response);
}).listen(port, "0.0.0.0", () => {
  console.log(`Project Argus test server: http://127.0.0.1:${port}/verified-network-exfil-demo.html`);
});
