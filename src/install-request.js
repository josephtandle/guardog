const INSTALL_ACTIONS = new Set(['install', 'i', 'add']);
const PIP_OPTIONS_WITH_VALUES = new Set([
  '-c',
  '--constraint',
  '-r',
  '--requirement',
  '--index-url',
  '--extra-index-url',
  '--find-links',
  '--target',
  '--prefix',
  '--root',
]);

function parseNpmSpec(input) {
  const spec = input.includes('@npm:') ? input.split('@npm:').pop() : input;
  if (!spec || /^(?:file:|git\+|https?:)/i.test(spec)) return null;
  if (spec.includes('/') && !spec.startsWith('@')) return null;

  const versionIndex = spec.startsWith('@') ? spec.indexOf('@', 1) : spec.indexOf('@');
  const name = versionIndex > 0 ? spec.slice(0, versionIndex) : spec;
  const version = versionIndex > 0 ? spec.slice(versionIndex + 1) || null : null;
  return name ? { name, ecosystem: 'npm', version } : null;
}

function parsePipSpec(spec) {
  if (!spec || /^(?:\.|\/|file:|git\+|https?:)/i.test(spec)) return null;
  const match = spec.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(?:(===|==|~=|!=|<=|>=|<|>)\s*([^;\s]+))?/);
  if (!match) return null;
  return {
    name: match[1],
    ecosystem: 'pypi',
    version: match[2] === '==' || match[2] === '===' ? match[3] : null,
  };
}

function packageArguments(args, tool) {
  const packages = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg || INSTALL_ACTIONS.has(arg)) continue;
    if (arg.startsWith('-')) {
      if (tool === 'pip' && PIP_OPTIONS_WITH_VALUES.has(arg)) index += 1;
      continue;
    }
    const parsed = tool === 'pip' ? parsePipSpec(arg) : parseNpmSpec(arg);
    if (parsed) packages.push(parsed);
  }
  return packages;
}

export function parseInstallRequest(args) {
  const explicitTool = args[0] === 'npm' || args[0] === 'pip' || args[0] === 'pip3';
  const tool = explicitTool && args[0] !== 'npm' ? 'pip' : 'npm';
  const suppliedArgs = explicitTool ? args.slice(1) : [...args];
  const commandArgs = suppliedArgs.length > 0 && INSTALL_ACTIONS.has(suppliedArgs[0])
    ? suppliedArgs
    : ['install', ...suppliedArgs];

  return {
    tool,
    ecosystem: tool === 'pip' ? 'pypi' : 'npm',
    commandArgs,
    packages: packageArguments(commandArgs, tool),
  };
}
