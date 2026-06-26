# Contributing to NexisCore

First off, thank you for considering contributing to NexisCore! It's people like you that make NexisCore such a great tool for enterprise AI security.

## Where do I go from here?

If you've noticed a bug or have a feature request, make sure to check the [Issues](https://github.com/rdxkeerthi/NexisCore/issues) to see if someone else has already created one. If not, feel free to open one!

## Fork & create a branch

If this is something you think you can fix, then fork NexisCore and create a branch with a descriptive name.

A good branch name would be (where issue #325 is the ticket you're working on):

```sh
git checkout -b 325-add-new-dlp-pattern
```

## Get the test suite running

Make sure you have Go 1.24+ and the required eBPF tools (`clang`, `llvm`, `libelf-dev`, `linux-headers-$(uname -r)`) installed.

To build and run tests:

```sh
make generate-pki
make build-ebpf
make build-antitamper-ebpf
make test
```

## Implement your fix or feature

At this point, you're ready to make your changes! Feel free to ask for help; everyone is a beginner at first.

## Code formatting & style

Please ensure your code follows standard Go formatting guidelines. Run `go fmt` and `go vet` before committing:

```sh
./local_go/go/bin/go fmt ./...
./local_go/go/bin/go vet ./...
```

## Make a Pull Request

At this point, you should switch back to your master branch and make sure it's up to date with NexisCore's master branch:

```sh
git remote add upstream https://github.com/rdxkeerthi/NexisCore.git
git checkout main
git pull upstream main
```

Then update your feature branch from your local copy of main, and push it!

```sh
git checkout 325-add-new-dlp-pattern
git rebase main
git push --set-upstream origin 325-add-new-dlp-pattern
```

Finally, go to GitHub and make a Pull Request.

## Keeping your Pull Request updated

If a maintainer asks you to "rebase" your PR, they're saying that a lot of code has changed, and that you need to update your branch so it's easier to merge.

Thank you for contributing!
