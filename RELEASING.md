# Releasing Panoptes

Panoptes is published to PyPI as `panoptes-observe`. The Python package and the
command are both named `panoptes`.

## One-time PyPI setup

1. Create a PyPI account. Verify its email address and turn on two-factor
   authentication.
2. In the PyPI publishing settings, add a pending trusted publisher with these
   values:

   | Field | Value |
   |---|---|
   | PyPI project | `panoptes-observe` |
   | GitHub owner | `miggy-code` |
   | Repository | `Panoptes` |
   | Workflow | `release.yml` |
   | Environment | `pypi` |

3. In the GitHub repository, create an environment named `pypi`. Require
   approval before deployment.

The first successful trusted-publishing run creates the PyPI project. You need
no API token and no repository secret.

## Release checklist

1. Update `version` in `pyproject.toml`. In `CHANGELOG.md`, move the notes from
   `Unreleased` into a new dated section.
2. Run the local release checks:

   ```bash
   python -m pytest -q
   python -m build
   python -m twine check --strict dist/*
   ```

3. Merge the release commit after CI passes.
4. Create a GitHub release with the tag `v<version>`, for example `v0.1.0`.
   Use a new version number each time.
5. Approve the `pypi` environment deployment. The release workflow checks the
   tag, builds and validates the files again, and publishes through OIDC.
6. Install the public package in a clean environment and check its version:

   ```bash
   python -m venv /tmp/panoptes-release-check
   /tmp/panoptes-release-check/bin/pip install panoptes-observe
   /tmp/panoptes-release-check/bin/panoptes --version
   ```

PyPI release files cannot be replaced. If publishing fails, fix the release
process and publish a new version.
