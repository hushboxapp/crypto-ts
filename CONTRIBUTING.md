# Contributing to @hushboxapp/crypto

First off, thank you for considering contributing to `@hushboxapp/crypto`! It's people like you who make it such a great library.

## Code of Conduct

By participating in this project, you are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (Check `.nvmrc` for the recommended version)
- [npm](https://www.npmjs.com/)

### Setup

1.  Fork and clone the repository.
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Install browsers for Playwright (required for tests):
    ```bash
    npx playwright install chromium firefox webkit
    ```
4.  Ensure everything is working by running tests:
    ```bash
    npm run test:node
    ```

## Development Workflow

1.  **Create a Branch**: Use a descriptive name like `feat/multi-key-support` or `fix/argon2-worker-path`.
2.  **Make Your Changes**: Adhere to the existing coding style (enforced by ESLint and Prettier).
3.  **Conventional Commits**: We use [Conventional Commits](https://www.conventionalcommits.org/) to automate our versioning and changelog generation. Your commit messages should follow this format:
    - `feat: ...` for new features.
    - `fix: ...` for bug fixes.
    - `docs: ...` for documentation changes.
    - `chore: ...` for maintenance tasks.
    - `test: ...` for adding or fixing tests.
    - `refactor: ...` for code changes that neither fix a bug nor add a feature.
    - `BREAKING CHANGE: ...` in the footer for breaking changes (or `!` after the type).
4.  **Add Tests**: Every new feature or bug fix must include corresponding tests in the `tests/` directory.
5.  **Lint & Type-Check**:
    ```bash
    npm run lint
    npm run type-check
    ```
6.  **Verify Coverage**:
    ```bash
    npm run test:node -- --coverage
    ```
7.  **Submit a Pull Request**: Provide a clear description of the changes and link any related issues.

## Release Process

We use [Release Please](https://github.com/googleapis/release-please) to manage our releases. The process is automated as follows:

1.  **Release PR**: When you merge changes into the `main` branch, Release Please will automatically create or update a "Release PR". This PR includes:
    - A version bump in `package.json`.
    - An updated `CHANGELOG.md` based on your Conventional Commits.
2.  **Merging the Release PR**: When a maintainer merges the Release PR:
    - A new GitHub Release is created and tagged.
    - A GitHub Action is triggered to build the library and publish it to [npm](https://www.npmjs.com/package/@hushboxapp/crypto).

## Style Guidelines

- **TypeScript**: We use strict TypeScript. Avoid using `any` unless absolutely necessary.
- **Documentation**: Use TSDoc for all public-facing APIs.
- **Formatting**: We use Prettier. You can run `npm run format` to format your code.

## Questions?

If you have questions, feel free to open an issue or start a discussion in the repository.
