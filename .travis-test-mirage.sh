#!/bin/sh -x

eval `opam config env`

opam install mirage

cd mirage/example

mirage clean && mirage configure && mirage build
export BUILD=client && mirage clean && mirage configure && mirage build && ./mir-tls-client

cd ../example2
mirage clean && mirage configure && mirage build
