# BitcoBoost Proof - independent verification tools

[BitcoBoost Proof](https://bitcoboost.com/proof/) writes the SHA-256 fingerprint of a file on the BitcoBoost (BCBO) blockchain:
a transaction with a data output `OP_RETURN "BBPF" 0x01 <32-byte SHA-256>`. The certificate you get shows the transaction id.

These tools let anyone check that record **without trusting the BitcoBoost website**: the fingerprint is computed on your
machine, and the transaction is read from the chain (public explorer, or your own node). Python 3 standard library only.

## Command line

```
python3 bbproof_verify.py contract.pdf --txid 9b7f570c5388cc314f02a677a844a25f20a2a48de2b99453778ae4a0a9ce2ae5
python3 bbproof_verify.py contract.pdf                         # txid looked up through the BitcoBoost API, then checked on the chain
python3 bbproof_verify.py --hash 480fea7b...8317 --txid 9b7f...  # a fingerprint you already have: the file never leaves you
python3 bbproof_verify.py contract.pdf --txid ... --rpc http://user:password@127.0.0.1:18332   # against your own node
```

Output: `VERIFIED` (exit 0) with block height, block time (UTC) and confirmations; `NOT VERIFIED` / `NOT REGISTERED` / `PENDING`
(exit 1); `ERROR` (exit 2). Add `--json` for machine-readable output.

What "independent" means here: with `--txid` the only thing read from BitcoBoost servers is the public block explorer's copy of the
transaction (`/api/tx/<txid>`), which anyone can compare with any other node of the network; with `--rpc` nothing is read from us at all.
Without `--txid` the tool first asks `bitcoboost.com/api/proof/<fingerprint>` which transaction to look at (lookup only), then still
verifies that transaction on the chain.

## GitHub Action

Verify, in your release workflow, that an artifact is registered:

```yaml
- name: Verify the release archive with BitcoBoost Proof
  uses: Bitcoboost/bitcoboost-proof-tools@main
  with:
    file: dist/release.tar.gz
    txid: ${{ vars.PROOF_TXID }}
```

The step fails (exit 1) if the fingerprint is not on the chain. Inputs: `file` or `hash`, optional `txid` (recommended), `explorer`, `rpc`.
Output `result`: VERIFIED, NOT VERIFIED, NOT REGISTERED, PENDING or ERROR.

## First registration

The first file ever registered (13 October 2026) is `BitcoBoost-Proof-prima-registrazione.txt` (https://bitcoboost.com/proof/):
fingerprint `480fea7b2dd43da41b5e57ca5b9f35c233e63d57fe243b70f5a41625d0788317`, transaction
`9b7f570c5388cc314f02a677a844a25f20a2a48de2b99453778ae4a0a9ce2ae5`, block 24,530.
