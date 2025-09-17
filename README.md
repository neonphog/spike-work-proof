# spike on work proof

<!-- cargo-rdme start -->

Argon2-based proof of work generation and validation system.

Asymetric keypairs are trivial to generate. If you want to make this more
difficult, you can add proof-of-work that must be supplied with a public
key (or any other data) to add a requirement of cpu / memory making it
more difficult to generate large numbers of public keys.

This platform takes a 32 byte hash (either the public key directly,
or, for example, a sha256 of the public key), and generates a proof
that when hashed with argon2 will generate a set of bytes interpreted
as a number. The closer those bytes are to the maximum number, the
more difficult (read unlikely) it is that you were able to generate
that hash. This difficulty is expressed as a log10 for ease of use
in human reasoning. I.e. if a difficulty of 1.0 takes on average 1 second
of hashing to reach, then a difficulty of 2.0 takes on average of
10 seconds to reach.

### How

Password hashing and proof-of-work are similar problem domains.

We can take the Argon2 algorithm and adapt it for proof of work.

- Use a 20 byte "password" that is the search space for the proof,
  - the first 16 bytes are incremented as a wrapping u128
  - the final 4 are used as a "node" id so parallel processing
    doesn't ever duplicate working on the same space
- Use the "hash" as the argon2 salt.

The recommendation here is to use the folowing params:

- mem limit: 16777216 bytes
- cpu limit: 1 iteration
- parallel count: 1
- output bytes: 16
- difficulty: log10(1.0 / (1.0 - (output bytes as LE u128 / u128::MAX)))

The argon2 parameters were chosen to require an amount of work to be done
(the whole point of this excercise), while also making it not too onerous
to validate the proofs on whatever process is doing the validation.

<!-- cargo-rdme end -->

### Timing Test

It's best to run this in release mode, to get a proper idea of how fast your system runs this code:

```
cargo run --release --example timing
```

### Wasm Test

First, install `wasm-pack`.

```
cargo install wasm-pack
```

Then, build the wasm

```
make wasm
```

Then, run a web server

```
python3 -m http.server 8080
```

Finally, navigate there in your browser:

http://127.0.0.1:8080/index.html
