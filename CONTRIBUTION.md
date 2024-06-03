## Orochi Network Contribution Guidelines

Welcome! Orochi Network welcomes contributions from the community. Here's a guide to help you get started contributing:

## Introduction

Orochi Network is committed to creating a welcoming and inclusive environment for all contributors to its open-source projects. This code of conduct outlines our expectations for behavior and helps maintain a productive and respectful atmosphere.

## Orochi Network Open Source Code of Conduct

**Expected Behavior**

- **Be respectful:** Treat all contributors with respect and courtesy, regardless of background, experience, beliefs, or any other characteristic.
- **Communicate openly:** Use professional and constructive language in all communications.
- **Be collaborative:** Work together to resolve disagreements constructively.
- **Be professional:** Avoid personal attacks and inflammatory statements.
- **Accept feedback:** Be open to constructive criticism and willing to learn from others.
- **Respect intellectual property:** Acknowledge the contributions of others and avoid plagiarism.

**Unacceptable Behavior**

- **Harassment:** This includes any form of verbal, written, or physical abuse, intimidation, or discriminatory behavior.
- **Hate speech:** Speech that attacks a person or group on the basis of attributes such as race, religion, ethnic origin, national origin, sex, disability, sexual orientation, or gender identity.
- **Discrimination:** Treating someone differently based on their background or personal characteristics.
- **Disruption:** Activities that disrupt the project or community, such as spamming, flooding the issue tracker, or posting off-topic content.
- **Violence or threats of violence:** Threats of violence towards an individual or group are not tolerated.
- **Cheating:** Submitting code that is not your own or engaging in other deceptive practices.

**Consequences of Unacceptable Behavior**

If a contributor engages in unacceptable behavior, the Orochi Network project maintainers may take any action they deem necessary, including:

- Warnings
- Removal of comments, commits, code contributions, or other content
- Temporary or permanent bans from the project or community

**Reporting Violations**

If you experience or witness unacceptable behavior, please report it to the Orochi Network project maintainers. You can report violations privately through email or a direct message on the project's communication platform [contact@orochi.network](contact@orochi.network).

## Getting Started

1. **Fork the Repository:** Find the Orochi Network repository you'd like to contribute to on [GitHub](https://github.com/orochi-network). Click "Fork" to create your own copy of the repository.

2. **Check Current Work:** Before diving in, it's wise to get a sense of what's currently being worked on. You can find this information in the repository's issue tracker.

3. **Syncing Your Project:** Once you've forked the repository, you'll need to add the original repository as an "upstream" so you can pull the latest changes. Instructions for this can be found on [Git documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/configuring-a-remote-repository-for-a-fork).

## Making Changes

1. **New Branch:** Create a new branch for your changes. Use a descriptive naming convention that reflects your contribution (e.g., "feature/new_feature", "bug/fixing_a_bug").

- Branch name include two parts `<prefix>/<branch_name>`. Prefixes are defined below, branch name must be `snake_case` in present simple.
- Each brach should include a single purpose instead of multiple purposes
- Acceptable prefixes are:
  - `feature/`: Adding a new feature to project
  - `bug/`: Perform a bug fix for given certain issue
  - `hotfix/`: Temporary fix and which should be revamp in the future
  - `devops/`: DevOps related PRs, this PR shouldn't do any change to the source code
  - `misc/`: lint fix, format...the thing that isn't important enough

2. **Code Contributions:** Orochi Network uses naming conventions and prefers merging when incorporating changes.

3. **Commit Messages:** Write clear and concise commit messages that describe your changes and reference any relevant issues (e.g., "Use higher gas fees for speeding up transactions (#11936)").

## Naming Convention

**TypeScript**

- Variables must be in `camelCase`
- Constant must be in `CAPITAL_SNAKE_CASE`
- Export methods, classes must ben in `PascalCase`
- Interface start with `I`
- Type start with `T`
- Enum start with `E`, all enums member must be in `PascalCase`
- Common parts should be used as prefix (eg. buttonTest, buttonLogin, serviceEndpoint, serviceProxy)

**Rust**

All must follow rust standard guideline

## Creating a Pull Request

1. **Push Your Changes:** Once you're happy with your work, push your branch to your forked repository.

2. **Pull Request:** Create a pull request to submit your changes for review.

- Link your pull request to any related issues.
- If your work is in progress, prefix the pull request title with `[WIP]`

We appreciate your interest in contributing to Orochi Network!

_build with ❤️ and 🦀_
