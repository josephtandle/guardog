"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

test("Craig-style npm install arguments become OSV scan targets", async () => {
  const { parseInstallRequest } = await import("../src/install-request.js");
  const request = parseInstallRequest(["npm", "install", "@scope/pkg@1.2.3", "lodash@4.17.21", "--save-dev"]);

  assert.equal(request.tool, "npm");
  assert.deepEqual(request.commandArgs, ["install", "@scope/pkg@1.2.3", "lodash@4.17.21", "--save-dev"]);
  assert.deepEqual(request.packages, [
    { name: "@scope/pkg", ecosystem: "npm", version: "1.2.3" },
    { name: "lodash", ecosystem: "npm", version: "4.17.21" },
  ]);
});

test("legacy Guardog install syntax remains npm-compatible", async () => {
  const { parseInstallRequest } = await import("../src/install-request.js");
  const request = parseInstallRequest(["express"]);

  assert.equal(request.tool, "npm");
  assert.deepEqual(request.commandArgs, ["install", "express"]);
  assert.deepEqual(request.packages, [{ name: "express", ecosystem: "npm", version: null }]);
});

test("Craig-style pip install arguments become PyPI OSV scan targets", async () => {
  const { parseInstallRequest } = await import("../src/install-request.js");
  const request = parseInstallRequest(["pip", "install", "requests==2.31.0", "flask>=3", "--upgrade"]);

  assert.equal(request.tool, "pip");
  assert.deepEqual(request.commandArgs, ["install", "requests==2.31.0", "flask>=3", "--upgrade"]);
  assert.deepEqual(request.packages, [
    { name: "requests", ecosystem: "pypi", version: "2.31.0" },
    { name: "flask", ecosystem: "pypi", version: null },
  ]);
});
