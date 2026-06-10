#!/bin/bash

set -eu

mkdir artifacts/binaries
mv x86_64-unknown-linux-musl/* artifacts/binaries
