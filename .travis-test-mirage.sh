#!/bin/sh -x

eval `opam config env`

opam install mirage

cd mirage/example
export BUILD=client && mirage clean && mirage configure && mirage build && ./mir-tls-client
