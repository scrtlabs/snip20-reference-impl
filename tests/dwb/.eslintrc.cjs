
module.exports = {
	extends: '@blake.regalia/eslint-config-elite',
	parserOptions: {
		ecmaVersion: 2022,
		sourceType: 'module',
		tsconfigRootDir: __dirname,
		project: 'tsconfig.json',
	},
	rules: {
		'no-console': 'off',
		'@typescript-eslint/naming-convention': 'off',
	},
};
