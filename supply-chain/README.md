# Cargo Vet

Following a Cargo dependency update, run:

 ```
cargo vet regenerate imports
cargo vet regenerate exemptions
cargo vet regenerate unpublished
```
 
to update the vetted dependencies based on trusted authors.

See the [Cargo Vet book](https://mozilla.github.io/cargo-vet/commands.html) for 
more information.