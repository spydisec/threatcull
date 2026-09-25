// SPDX-License-Identifier: AGPL-3.0-only
// Conventional Commits, subject line at most 72 characters.
export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "header-max-length": [2, "always", 72],
    "subject-case": [2, "never", ["start-case", "pascal-case", "upper-case"]],
    "body-max-line-length": [2, "always", 100],
    "footer-max-line-length": [2, "always", 100],
  },
  // Dependabot copies release notes (long lines) into its commit bodies and its message
  // format cannot be configured, so its commits are skipped wherever they appear,
  // including the dev -> main release pull request.
  ignores: [(message) => message.includes("Signed-off-by: dependabot[bot]")],
};
