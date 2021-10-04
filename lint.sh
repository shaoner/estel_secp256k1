#! /bin/sh

cargo clippy -- \
      -A clippy::identity_op \
      -A clippy::branches_sharing_code \
      -A clippy::wrong-self-convention \
      -A clippy::collapsible-else-if \
      -D warnings
