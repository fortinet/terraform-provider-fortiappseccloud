# Releasing the provider

GitHub releases combine two sources:

1. The matching version section in `CHANGELOG.md` supplies the curated release
   highlights.
2. GitHub generates the categorized pull-request list, contributor credits,
   and comparison link according to `.github/release.yml`.

GoReleaser joins those sections and uploads the signed provider artifacts.

## Prepare a release

1. Replace the `## Unreleased` heading in `CHANGELOG.md` with the release
   version and date. The version must match the tag without its leading `v`:

   ```markdown
   ## 2.0.0 (August 7, 2026)
   ```

2. Add a new empty `## Unreleased` section above the versioned section for
   future changes.
3. Commit and merge the changelog together with the release-ready code.
4. Verify the curated header locally:

   ```shell
   release_header=$(mktemp)
   ./scripts/extract-release-header.sh v2.0.0 CHANGELOG.md "$release_header"
   sed -n '1,120p' "$release_header"
   ```

5. Tag the release-ready commit with `vMAJOR.MINOR.PATCH` and push that tag.

The release workflow fails before publishing when the tag is malformed, the
matching changelog section is missing, or that section is empty. Do not create
a release tag while its notes are still under `## Unreleased`.

## Pull-request categories

GitHub assigns each merged pull request to the first matching category:

- `enhancement` becomes **Enhancements**;
- `bug` becomes **Bug Fixes**;
- `documentation` becomes **Documentation**; and
- every remaining pull request becomes **Other Changes**.

Apply the appropriate label before merging a pull request when its generated
release-note category matters. The curated `CHANGELOG.md` section remains the
source for user-facing highlights and upgrade guidance.
