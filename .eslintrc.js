// module.exports = {
//   root: true,
//   parser: '@typescript-eslint/parser',
//   plugins: ['@typescript-eslint', 'react', 'react-hooks', 'react-native'],
//   extends: [
//     'eslint:recommended',
//     'plugin:@typescript-eslint/recommended',
//     'plugin:react/recommended',
//     'plugin:react-hooks/recommended',
//     'plugin:react-native/all',
//     'prettier', // Integrate Prettier with ESLint
//   ],
//   env: {
//     browser: true,
//     node: true,
//     es6: true,
//   },
//   settings: {
//     react: {
//       version: 'detect', // Automatically detects the React version
//     },
//   },
//   // rules: {
//   //   '@typescript-eslint/no-explicit-any': 'warn', // Warn on 'any' usage
//   //   '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
//   //   'react/react-in-jsx-scope': 'off', // Not needed for React 17+
//   //   'react-native/no-color-literals': 'warn', // Warn about inline colors
//   //   'no-console': ['warn', { allow: ['warn', 'error'] }], // Warn for console.log, allow warn/error
//   //   '@typescript-eslint/explicit-function-return-type': ['warn'], // Warn on missing function return types
//   //   'react/prop-types': 'off', // Disable prop-types for TypeScript projects
//   //   '@typescript-eslint/consistent-type-definitions': ['error', 'interface'], // Enforce consistent interfaces
//   // },
//   overrides: [
//     {
//       files: ['server/**/*.ts'],
//       env: {
//         node: true, // Specific Node.js environment for server
//       },
//       parserOptions: {
//         project: './server/tsconfig.json', // TypeScript project for the server
//       },
//     },
//     {
//       files: ['client/**/*.ts', 'client/**/*.tsx'],
//       env: {
//         'react-native/react-native': true, // Specific React Native environment
//       },
//       parserOptions: {
//         project: './client/tsconfig.json', // TypeScript project for the client
//       },
//     },
//   ],
//   ignorePatterns: [
//     'node_modules/',
//     'dist/',
//     'build/',
//     '*.config.js',
//     'coverage/',
//   ], // You can add more patterns here
// };
