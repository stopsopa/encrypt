# Test keys — never use for anything real

These ssh keys exist only so the test suite and the known-answer vectors are reproducible.
The private keys are public (they are in this repository) and protected with the
passphrase `ssenc-test`, which exercises the same "unlock into ssh-agent" path a real key
uses. `test_absent.pub` has no private key here on purpose: it stands for a key that is
not loaded in the agent.
