const REQUIRED_NODE_MAJOR = 24;

export function assertSupportedNodeVersion(version = process.versions.node) {
  const major = Number.parseInt(String(version).split('.')[0], 10);
  if (major === REQUIRED_NODE_MAJOR) return;
  const error = new Error(`Node.js 24.x is required; current runtime is ${version}. Use the pinned .nvmrc or .node-version before running MyOS Guard Dog.`);
  error.code = 'ERR_UNSUPPORTED_NODE_VERSION';
  throw error;
}
