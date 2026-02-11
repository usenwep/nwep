'use strict';

const path = require('path');
const fs = require('fs');

/* Load the native addon. Try cmake-js output locations. */
const addonName = 'nwep_napi.node';
const root = path.join(__dirname, '..', '..');
const candidates = [
  path.join(root, '.build', 'node', 'Release', addonName),
  path.join(root, '.build', 'node', 'Debug', addonName),
  path.join(root, 'build', 'Release', addonName),
  path.join(root, 'build', 'Debug', addonName),
  path.join(root, 'prebuilds', `${process.platform}-${process.arch}`, addonName),
];

let binding;
for (const candidate of candidates) {
  if (fs.existsSync(candidate)) {
    binding = require(candidate);
    break;
  }
}

if (!binding) {
  throw new Error(
    'nwep native addon not found. Run "npm run build" first.'
  );
}

module.exports = binding;
