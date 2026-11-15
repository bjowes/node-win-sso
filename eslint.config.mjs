import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';
import n from "eslint-plugin-n"

export default defineConfig({
  plugins: {n},
  files: ['**/*.{js,ts}'],
  extends: [js.configs.recommended, tseslint.configs.recommended, 'n/recommended-module'],
});

/*
import pluginJs from "@eslint/js";
import jsdoc from "eslint-plugin-jsdoc";
import globals from "globals";
import tseslint from "typescript-eslint";

export default [
  { */
    //files: ["**/*.{js,mjs,cjs,ts}"],
    /*
    plugins: { jsdoc },
    rules: {
      "jsdoc/require-description": "warn",
      "jsdoc/require-jsdoc": [
        "warn",
        {
          publicOnly: true,
          require: {
            FunctionDeclaration: true,
            MethodDefinition: true,
            ClassDeclaration: true,
            ArrowFunctionExpression: true,
          },
        },
      ],
    },
  },
  { languageOptions: { globals: globals.browser } },
  jsdoc.configs["flat/recommended-typescript"],
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
];
*/