module.exports = {
  dependency: {
    platforms: {
      android: {
        sourceDir: './android',
        packageImportPath: 'import com.fprot.FprotPackage;',
        packageInstance: 'new FprotPackage()',
      },
      ios: {},
    },
  },
};
