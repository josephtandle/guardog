import { resolve } from 'path';
import { pathToFileURL } from 'url';

export async function importModuleFromPath(modulePath) {
  const moduleUrl = pathToFileURL(resolve(modulePath)).href;
  return import(moduleUrl);
}
