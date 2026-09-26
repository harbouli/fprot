const path = require('path');
const { getDefaultConfig } = require('@react-native/metro-config');
const { withMetroConfig } = require('react-native-monorepo-config');

const root = path.resolve(__dirname, '..');

/**
 * Metro configuration
 * https://facebook.github.io/metro/docs/configuration
 *
 * @type {import('metro-config').MetroConfig}
 */
const config = withMetroConfig(getDefaultConfig(__dirname), {
  root,
  dirname: __dirname,
  conditions: ['fprot-source'],
});

const defaultResolveRequest = config.resolver.resolveRequest;

config.resolver = {
  ...config.resolver,
  extraNodeModules: {
    ...config.resolver?.extraNodeModules,
    'fprot': root,
    '@harbouli/fprot': root,
  },
  resolveRequest: (context, moduleName, platform) => {
    if (
      moduleName === 'fprot' ||
      moduleName.startsWith('fprot/') ||
      moduleName === '@harbouli/fprot' ||
      moduleName.startsWith('@harbouli/fprot/')
    ) {
      context = {
        ...context,
        mainFields: ['fprot-source', ...context.mainFields],
        unstable_conditionNames: [
          'fprot-source',
          ...context.unstable_conditionNames,
        ],
      };
    }
    return defaultResolveRequest(context, moduleName, platform);
  },
};

module.exports = config;
