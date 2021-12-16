#!/usr/bin/env bash

set -e # exit when a command fails
set -u # exit when script tries to use undeclared variables
set -x # trace what gets executed (useful for debugging)

trap "echo SOMETHING WENT WRONG - please read the logs above and see if it helps you figure out what is wrong - and also ask an engineer help" ERR

assert_openssl_present() {
  if [[ "$(uname)" = "Darwin" ]]; then
    OPENSSL_DIR=/usr/local/Cellar/openssl@1.1
    if [ ! -d $OPENSSL_DIR ]; then
      echo "It appears that OpenSSL 1.1 is not installed - please install it via Homebrew and try again" 2>&1
      exit 1
    else
      # Pick out the most recent minor OpenSSL 1.1 version that is installed
      OPENSSL_PATH=$(find $OPENSSL_DIR/* -type d -maxdepth 0 | sort | tail -n 1)
      export LDPATH=$OPENSSL_PATH/lib
      export OPENSSL_INCLUDES=$OPENSSL_PATH/include
    fi
  fi
}

subproject_build() {
  assert_openssl_present
  mix deps.get
  mix compile
}

subproject_setup() {
  asdf install
  mix local.hex --force
}

subproject_test() {
  shellcheck "${0}"
  shfmt -ci -i 2 -d "${0}"
  # TODO: these tests aren't running successfully on Lindsay's machine and we
  # suspect that it is because of missing CPU instrinsics under Rosetta
  mix test
}

subproject_clean() {
  mix clean
}

subproject_rebuild() {
  subproject_clean
  subproject_build
}

subcommand="${1:-build}"

case $subcommand in
  setup)
    subproject_setup
    ;;

  clean)
    subproject_clean
    ;;

  test)
    subproject_test
    ;;

  rebuild)
    subproject_rebuild
    ;;

  build)
    subproject_build
    ;;

  *)
    echo "Unknown build subcommand '$subcommand'"
    exit 1
    ;;
esac
