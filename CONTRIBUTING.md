# Contributing

Thanks for considering contributing to flutter_secure_storage!

## Getting started

This is a [Melos](https://melos.invertase.dev/) monorepo. After cloning, bootstrap once before doing any other work:

```bash
dart pub global activate melos
melos bootstrap
```

`melos bootstrap` links all packages together via pubspec overrides so that local changes to one package are immediately visible across the others without publishing.

## Pull requests

* Open feature/fix PRs against `develop`.
* PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/) (e.g. `feat: ...`, `fix: ...`, `chore: ...`) — this is enforced by CI.
* Run `melos analyze` and `melos format --output none --set-exit-if-changed` before pushing; both run in CI.
* Add or update tests for the packages you touch where applicable.

## Versioning

Each package in this repo (`flutter_secure_storage`, `flutter_secure_storage_platform_interface`, `flutter_secure_storage_darwin`, `flutter_secure_storage_linux`, `flutter_secure_storage_web`, `flutter_secure_storage_windows`) is versioned independently, and releases are handled automatically by [Release Please](https://github.com/googleapis/release-please). **Please don't bump a `pubspec.yaml` version or add a `CHANGELOG.md` entry yourself** — Release Please generates both from your commit messages after merge.

1. Scope your commit/PR title to the package(s) you actually changed, e.g. `fix(darwin): ...`, `feat(windows): ...`. Release Please uses the Conventional Commit type (and scope) to decide which package(s) get a version bump and what the changelog entry says.
2. Try not to mix changes to multiple packages in a single commit — Release Please attributes a commit, including any `!` breaking-change marker, to every package whose files it touches, so an unrelated multi-package commit can trigger an unintended version bump elsewhere.
3. Once merged, Release Please opens a `chore(develop): release <package> X.Y.Z` PR for each affected package. Merging that PR cuts the release, tags it `<package-directory>-vX.Y.Z` (this applies to all six packages, including the main `flutter_secure_storage`), and publishes it to pub.dev via CI.
4. If you bumped a platform package (darwin/linux/web/windows), also check whether the `^` constraint on it in `flutter_secure_storage/pubspec.yaml` needs updating — that's still a manual step.
