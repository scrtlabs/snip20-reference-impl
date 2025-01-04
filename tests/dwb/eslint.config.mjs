import elite from '@blake.regalia/eslint-config-elite';

export default [
	...elite,
	{
		languageOptions: {
			ecmaVersion: 2022,
			sourceType: 'module',

			parserOptions: {
				tsconfigRootDir: import.meta.dirname,
				project: 'tsconfig.json',
			},
		},
		rules: {
			'no-console': 'off',
			'@typescript-eslint/naming-convention': 'off',
		},
	},
];
