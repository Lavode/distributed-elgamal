# Introduction

This is a textbook implementation of a distributed hashed ElGamal Cryptosystem.
It utilizes a t-out-of-n secret sharing based on polynomials over a finite
field to distribute the private key, and reconstruct the ciphertext.

This library was made for an assignment in class, and should not be used
productively as it has not been reviewed.

# Getting started

Take a look at `demo.go` to see the library in use. If you've got a running
Golang setup, you may build & run it as follows:
```
go build demo.go && ./demo
```

# Project structure

The project structure is as follows:

* The `demo.go` application shows the library in use
* The `elgamal` package implements the distributed hashed ElGamal cryptosystem

# Unit tests

Unit tests use the standard `testing` library of Go, and may be run using the
`go test` tool. To run all tests, execute `go test ./...`.
