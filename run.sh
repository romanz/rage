#!/bin/bash
set -eux
cargo fmt --all && cargo build --all --examples 

export PATH=$PATH:./target/debug:./target/debug/examples
age-plugin-trezor -i foobar > trezor.id
R=$(grep age1trezor trezor.id | cut -f 3 -d ' ')
I=$(grep AGE-PLUGIN trezor.id)

date > msg
cat msg | rage -r $R -a > enc.asc
rage -d -i trezor.id < enc.asc