const path = require('path');
const pkg = require('../package.json');

const project = (() => {
  try {
    const { configureProjects } = require('react-native-test-app');
    return configureProjects({
      android: {
        sourceDir: 'android',
      },
      ios: {
        sourceDir: 'ios',
      },
      macos: {
        sourceDir: 'macos',
      },
      visionos: {
        sourceDir: 'visionos',
      },
      windows: {
        sourceDir: 'windows',
        solutionFile: 'windows/FprotExample.sln',
      },
    });
  } catch {
    return undefined;
  }
})();

module.exports = {
  ...(project
    ? {
        project: {
          ...project,
          ios: project.ios
            ? { ...project.ios, automaticPodsInstallation: false }
            : undefined,
        },
      }
    : undefined),
  dependencies: {
    [pkg.name]: {
      root: path.join(__dirname, '..'),
    },
  },
};
