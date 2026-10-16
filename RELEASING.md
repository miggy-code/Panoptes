# Releasing Panoptes

Panoptes is published to PyPI as `panoptes-observe`. The Python import package
and installed command are both named `panoptes`.

## One-time PyPI setup

1. Create a PyPI account, verify its email address, and enable two-factor
   authentication.
2. In PyPI's publishing settings, add a pending trusted publisher with these
   values:

   | Field | Value |
   |---|---|
   | PyPI project | `panoptes-observe` |
   | GitHub owner | `miggy-code` |
   | Repository | `Panoptes` |
   | Workflow | `release.yml` |
   | Environment | `pypi` |

3. In the GitHub repository, create an environment named `pypi` and require
   approval before deployment.

The first successful trusted-publishing run creates the PyPI project. No API
token or repository secret is required.

## Release checklist

1. Update `version` in `pyproject.toml` and move the release notes from
   `Unreleased` into a dated section in `CHANGELOG.md`.
2. Run the local release checks:

   ```bash
   python -m pytest -q
   python -m build
   python -m twine check --strict dist/*
   ```

3. Merge the release commit after CI passes.
4. Create a GitHub release whose tag is exactly `v<version>`, such as
   `v0.1.0`. Do not reuse a version already uploaded to PyPI.
5. Approve the `pypi` environment deployment. The release workflow verifies
   the tag, rebuilds and validates the artifacts, and publishes through OIDC.
6. Verify the public package from a clean environment:

   ```bash
   python -m venv /tmp/panoptes-release-check
   /tmp/panoptes-release-check/bin/pip install panoptes-observe
   /tmp/panoptes-release-check/bin/panoptes --version
   ```

If publishing fails, fix the release process and publish a new version. PyPI
release files are immutable and should never be silently replaced.
