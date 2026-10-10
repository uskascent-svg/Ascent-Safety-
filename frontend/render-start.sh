#!/bin/sh
set -e

# If API_INTERNAL_URL is set at runtime, rewrite standalone Next.js API proxy destinations.
if [ -n "${API_INTERNAL_URL:-}" ]; then
  node <<'NODE'
const fs = require("fs");
const target = (process.env.API_INTERNAL_URL || "").trim().replace(/\/+$/, "");
if (target) {
  const files = ["server.js", ".next/routes-manifest.json", ".next/required-server-files.json"];
  for (const file of files) {
    if (fs.existsSync(file)) {
      let text = fs.readFileSync(file, "utf8");
      text = text.replace(/https?:\/\/[^"\\]+\/api\/:path\*/g, target + "/api/:path*");
      fs.writeFileSync(file, text, "utf8");
    }
  }
}
NODE
fi

exec node server.js
