import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import vue from "eslint-plugin-vue";
import globals from "globals";
import tseslint from "typescript-eslint";

const PRAGMA =
  /^\s*(eslint-disable(-next-line|-line)?|eslint-enable|@ts-expect-error|@vitest-environment)\b/;
const REFERENCE = /^\/\s*<reference\s/;

function span(text, [start, end]) {
  let from = start;
  while (from > 0 && (text[from - 1] === " " || text[from - 1] === "\t")) from -= 1;
  let to = end;
  while (to < text.length && (text[to] === " " || text[to] === "\t")) to += 1;
  const ownLine =
    (from === 0 || text[from - 1] === "\n") && (to === text.length || text[to] === "\n");
  return ownLine ? [from, Math.min(to + 1, text.length)] : [from, end];
}

const noComments = {
  meta: {
    type: "suggestion",
    fixable: "code",
    schema: [],
    messages: { comment: "Remove this comment: the code carries none." },
  },
  create(context) {
    const source = context.sourceCode;
    const check = (comment) => {
      const value = comment.value ?? "";
      if (comment.type === "Shebang" || PRAGMA.test(value) || REFERENCE.test(value)) return;
      context.report({
        loc: comment.loc,
        messageId: "comment",
        fix: (fixer) => fixer.removeRange(span(source.text, comment.range)),
      });
    };
    return {
      Program() {
        for (const comment of source.getAllComments()) check(comment);
        for (const comment of source.ast.templateBody?.comments ?? []) check(comment);
      },
    };
  },
};

const HTML_KEYS = "/^(innerHTML|outerHTML|srcdoc)$/";
const SHIKI_REFUSED =
  "/^(shiki(\\u002F(?!(core|engine\\u002Fjavascript)$).*)?|@shikijs\\u002F(engine-oniguruma|langs-precompiled)(\\u002F.*)?)$/";
const SHIKI_MESSAGE = "Use shiki/core, shiki/engine/javascript and @shikijs/langs/<language>.";

export default tseslint.config(
  {
    ignores: [
      "node_modules/",
      "coverage/",
      "playwright-report/",
      "test-results/",
      "../src/gitmortem/static/",
      "src/api/schema.ts",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...vue.configs["flat/recommended"],
  {
    files: ["**/*.vue"],
    languageOptions: { parserOptions: { parser: tseslint.parser } },
  },
  { languageOptions: { globals: { ...globals.browser, ...globals.node } } },
  {
    rules: {
      "vue/no-v-html": "error",
      "vue/no-restricted-v-bind": [
        "error",
        { argument: "/^(inner|outer)-?h-?t-?m-?l$/i", message: "Render text, never HTML." },
        { argument: "/^src-?doc$/i", message: "Render text, never HTML." },
      ],
      "vue/no-restricted-syntax": [
        "error",
        {
          selector: "VDirectiveKey[name.name='bind'] > VExpressionContainer.argument",
          message: "Name what a binding sets.",
        },
        {
          selector: `VAttribute[key.argument=null] Property[key.name=${HTML_KEYS}]`,
          message: "Render text, never HTML.",
        },
        {
          selector: `VAttribute[key.argument=null] Property[key.value=${HTML_KEYS}]`,
          message: "Render text, never HTML.",
        },
      ],
      "no-restricted-syntax": [
        "error",
        {
          selector: `Property[key.name=${HTML_KEYS}]`,
          message: "Render text, never HTML.",
        },
        {
          selector: `Property[key.value=${HTML_KEYS}]`,
          message: "Render text, never HTML.",
        },
        {
          selector: `MemberExpression[computed=true][property.value=${HTML_KEYS}]`,
          message: "Render text, never HTML.",
        },
        {
          selector: `AssignmentExpression > MemberExpression.left[property.name=${HTML_KEYS}]`,
          message: "Render text, never HTML.",
        },
        {
          selector:
            "CallExpression[callee.property.name=/^(insertAdjacentHTML|createContextualFragment|setHTMLUnsafe|parseHTMLUnsafe)$/]",
          message: "Render text, never HTML.",
        },
        {
          selector:
            "CallExpression[callee.object.name='document'][callee.property.name=/^(write|writeln)$/]",
          message: "Render text, never HTML.",
        },
        {
          selector: "Identifier[name=/^(codeToHtml|codeToHast)$/]",
          message: "Highlight to tokens, never to HTML.",
        },
        {
          selector: `ImportExpression[source.value=${SHIKI_REFUSED}]`,
          message: SHIKI_MESSAGE,
        },
      ],
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              regex:
                "^(shiki(/(?!(core|engine/javascript)$).*)?|@shikijs/(engine-oniguruma|langs-precompiled)(/.*)?)$",
              message: SHIKI_MESSAGE,
            },
          ],
        },
      ],
    },
  },
  {
    plugins: { gitmortem: { rules: { "no-comments": noComments } } },
    rules: {
      "gitmortem/no-comments": "error",
      "no-empty": ["error", { allowEmptyCatch: true }],
    },
  },
  prettier,
);
