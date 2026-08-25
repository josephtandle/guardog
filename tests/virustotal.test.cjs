"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

test("VirusTotal remains wired with the configured API key", async () => {
  const { VirusTotalScanner } = await import("../src/virustotal-scanner.js");
  const originalFetch = global.fetch;
  let request;

  global.fetch = async (url, options) => {
    request = { url, options };
    return {
      ok: true,
      status: 200,
      async json() {
        return {
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 2,
                suspicious: 1,
                harmless: 7,
                undetected: 10,
              },
            },
          },
        };
      },
    };
  };

  try {
    const scanner = new VirusTotalScanner({
      virustotal: {
        apiKey: "synthetic-test-key",
        baseUrl: "https://www.virustotal.com/api/v3",
        timeoutMs: 1000,
      },
    });
    const result = await scanner.getFileReport("synthetic-hash");

    assert.equal(request.options.headers["x-apikey"], "synthetic-test-key");
    assert.equal(result.maliciousVotes, 2);
    assert.equal(result.suspiciousVotes, 1);
    assert.equal(result.totalEngines, 20);
  } finally {
    global.fetch = originalFetch;
  }
});
