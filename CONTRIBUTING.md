# Contributing to  www

First and foremost, thank you! We appreciate that you want to contribute to
**www**, your time is valuable, and your contributions mean a lot to us.

## Important!

By contributing to this project, you:

* Agree that you have authored 100% of the content
* Agree that you have the necessary rights to the content
* Agree that you have received the necessary permissions from your employer to make the contributions (if applicable)
* Agree that the content you contribute may be provided under the Project license(s)

## Getting started

**What does "contributing" mean?**

Creating an issue is the simplest form of contributing to a project. But there
are many ways to contribute, including the following:

- Updating or correcting documentation
- Feature requests
- Bug reports

**Showing support for www**

Please keep in mind that open source software is built by people like you, who
spend their free time creating things the rest the community can use.

Don't have time to contribute? No worries, here are some other ways to show your
support for **www**:

- star :star: the [project](https://github.com/nbari/www)
- tweet your support for **www**

## Issues

### Before creating an issue

Please try to determine if the issue is caused by an underlying library, and if
so, create the issue there. Sometimes this is difficult to know. We only ask
that you attempt to give a reasonable attempt to find out. Oftentimes the readme
will have advice about where to go to create issues.

Try to follow these guidelines

- **Investigate the issue**
- **Check the readme** - oftentimes you will find notes about creating issues, and where to go depending on the type of issue.
- Create the issue in the appropriate repository.

### Creating an issue

Please be as descriptive as possible when creating an issue. Give us the information we need to successfully answer your question or address your issue by answering the following in your issue:

- **version**: please note the version of **www** are you using
- **extensions, plugins, helpers, etc** (if applicable): please list any extensions you're using
- **error messages**: please paste any error messages into the issue, or a [gist](https://gist.github.com/)

### Closing issues

The original poster or the maintainer's of **www** may close an issue at
any time. Typically, but not exclusively, issues are closed when:

- The issue is resolved
- The project's maintainers have determined the issue is out of scope
- An issue is clearly a duplicate of another issue, in which case the duplicate issue will be linked.
- A discussion has clearly run its course


## Pull Request Process

- Target **main** when opening a pull request.
- Run `just check` and the relevant integration checks before submitting changes.

## Releases

`release.yml` runs on every pushed tag and through **Run workflow**. A branch run is a dry run:
it tests, builds all release architectures and packages, and checks `cargo publish --dry-run`.
A tag run publishes only when the tag matches `Cargo.toml`, for example `3.0.0` or `v3.0.0`.
All tests, builds, and crate validation must pass before either publication job runs.

Configure [crates.io Trusted Publishing](https://crates.io/docs/trusted-publishing) before
using tag releases:

1. Make the initial crate publication locally using an API token. crates.io requires an existing
   crate before Trusted Publishing can be configured. Publish from a clean checkout of the
   commit you intend to release, using `cargo publish --locked`.
2. In the crate's **Settings → Trusted Publishing**, add GitHub with repository owner `nbari`,
   repository name `www`, workflow filename `release.yml`, and environment `crates-io`.
3. In GitHub repository settings, create the matching `crates-io` environment. Any deployment
   restrictions must permit your release tags. Required reviewers are optional.

The workflow obtains a short-lived OIDC token only for the final upload; no crates.io token
secret is needed in GitHub. An identical, non-yanked crate version already on crates.io is
accepted after checking its SHA-256 checksum. Different contents under the same version fail;
bump the version rather than reusing it. GitHub release creation precedes the crates.io upload,
so an upload failure leaves the GitHub assets available and the failed job can be rerun.

For subsequent releases, update the Cargo version and lockfile, commit the changes, wait for
CI, then push a matching tag. Manually dispatching on a matching tag also publishes; select
`main` for validation without publication.


[so]: http://stackoverflow.com/questions/tagged/www
