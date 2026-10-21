#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# riuso-verificato: non esiste in casa un verificatore INDIPENDENTE di Proof (la pagina /proof/ verifica fidandosi del nostro server);
# questo controlla la transazione sulla catena da fuori (explorer pubblico o nodo proprio). Solo libreria standard: nessuna dipendenza.
"""bbproof_verify.py - independent verifier for BitcoBoost Proof records (https://bitcoboost.com/proof/).

A Proof record is a BitcoBoost (BCBO) transaction with a data output:  OP_RETURN "BBPF" 0x01 <32-byte SHA-256 of the file>.
This tool checks that record ON THE CHAIN, without trusting the BitcoBoost website:

  python3 bbproof_verify.py <file> --txid <txid>                 the txid is on your certificate: fully independent check
  python3 bbproof_verify.py <file>                               no txid: it is looked up through the BitcoBoost API, then the
                                                                 transaction itself is still checked on the chain
  python3 bbproof_verify.py --hash <64 hex> --txid <txid>        verify a fingerprint you already have (the file never leaves you)

Where the chain is read from (pick one; default = public explorer):
  --explorer https://explorer.bitcoboost.com                      public block explorer API (/api/tx/<txid>)
  --rpc http://user:password@127.0.0.1:18332                      your OWN BitcoBoost node (getrawtransaction): the most independent

Exit codes: 0 = VERIFIED, 1 = NOT registered / fingerprint does not match the transaction, 2 = error (network, bad input).
Only the Python standard library is used. Idea: Sam (ticket BB-2026-0041), 22/10/2026."""
import argparse, base64, hashlib, json, re, sys, time, urllib.error, urllib.request

PREFIX_HEX = '4242504601'        # "BBPF" + version 01
SCRIPT_RE = re.compile(r'^6a25' + PREFIX_HEX + r'([0-9a-f]{64})$')
API_PROOF = 'https://bitcoboost.com/api/proof/'
UA = 'bbproof-verify/1.0'


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def http_json(url, data=None, headers=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers={'User-Agent': UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8'))


def lookup_txid(fingerprint):
    """Asks the BitcoBoost API which transaction carries the fingerprint. NOT independent: only used to find the txid."""
    try:
        d = http_json(API_PROOF + fingerprint)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, {'stato': 'non_registrata'}      # the API answers 404 for a fingerprint it has never seen
        raise
    if d.get('stato') == 'non_registrata' or not d.get('txid'):
        return None, d
    return d['txid'], d


def tx_from_explorer(base, txid):
    t = http_json(base.rstrip('/') + '/api/tx/' + txid)
    if not isinstance(t, dict) or t.get('txid') != txid:
        raise RuntimeError('explorer did not return transaction ' + txid)
    height = None
    if t.get('blockhash'):
        try:
            b = http_json(base.rstrip('/') + '/api/block/' + t['blockhash'])
            height = b.get('height')
        except Exception:
            height = None
    return {'vout': t.get('vout', []), 'confirmations': t.get('confirmations'), 'blockhash': t.get('blockhash'),
            'blocktime': t.get('blocktime') or t.get('time'), 'height': height}


def tx_from_rpc(url, txid):
    m = re.match(r'^(https?://)(?:([^:@/]+):([^@/]*)@)?(.+)$', url)
    if not m:
        raise RuntimeError('--rpc must look like http://user:password@host:port')
    scheme, user, pw, rest = m.groups()
    headers = {'Content-Type': 'application/json'}
    if user is not None:
        headers['Authorization'] = 'Basic ' + base64.b64encode(('%s:%s' % (user, pw or '')).encode()).decode()
    body = json.dumps({'jsonrpc': '1.0', 'id': 'bbproof', 'method': 'getrawtransaction', 'params': [txid, True]}).encode()
    d = http_json(scheme + rest, data=body, headers=headers)
    if d.get('error'):
        raise RuntimeError('node error: %s' % d['error'])
    t = d['result']
    height = None
    if t.get('blockhash'):
        body = json.dumps({'jsonrpc': '1.0', 'id': 'bbproof', 'method': 'getblockheader', 'params': [t['blockhash']]}).encode()
        h = http_json(scheme + rest, data=body, headers=headers)
        height = (h.get('result') or {}).get('height')
    return {'vout': t.get('vout', []), 'confirmations': t.get('confirmations'), 'blockhash': t.get('blockhash'),
            'blocktime': t.get('blocktime') or t.get('time'), 'height': height}


def fingerprints_in_tx(tx):
    found = []
    for v in tx.get('vout', []):
        spk = v.get('scriptPubKey') or {}
        hexs = (spk.get('hex') or '').lower()
        m = SCRIPT_RE.match(hexs)
        if m:
            found.append(m.group(1))
    return found


def main():
    ap = argparse.ArgumentParser(description='Independent verifier for BitcoBoost Proof records.')
    ap.add_argument('file', nargs='?', help='the file to verify (its SHA-256 is computed locally)')
    ap.add_argument('--hash', help='a SHA-256 fingerprint (64 hex) instead of a file')
    ap.add_argument('--txid', help='transaction id from the certificate (fully independent check)')
    ap.add_argument('--explorer', default='https://explorer.bitcoboost.com', help='block explorer base URL (default: the public one)')
    ap.add_argument('--rpc', help='your own node: http://user:password@host:port (overrides --explorer)')
    ap.add_argument('--json', action='store_true', help='machine-readable output')
    a = ap.parse_args()
    if not a.file and not a.hash:
        ap.error('give a file or --hash')
    try:
        fp = a.hash.lower() if a.hash else sha256_file(a.file)
        if not re.match(r'^[0-9a-f]{64}$', fp):
            raise RuntimeError('a SHA-256 fingerprint is 64 hexadecimal characters')
        out = {'fingerprint': fp, 'txid': a.txid, 'source': 'own node' if a.rpc else 'explorer ' + a.explorer, 'txid_from': 'certificate' if a.txid else None}
        txid = a.txid
        if not txid:
            txid, info = lookup_txid(fp)
            out['txid'] = txid; out['txid_from'] = 'bitcoboost.com API (lookup only; the transaction is still checked on the chain)'
            if not txid:
                out['result'] = 'NOT REGISTERED'; out['detail'] = 'the BitcoBoost API has no record for this fingerprint (state: %s)' % info.get('stato')
                return report(out, a.json, 1)
        tx = tx_from_rpc(a.rpc, txid) if a.rpc else tx_from_explorer(a.explorer, txid)
        found = fingerprints_in_tx(tx)
        out.update({'confirmations': tx.get('confirmations'), 'block_height': tx.get('height'), 'block_hash': tx.get('blockhash'),
                    'block_time_utc': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(tx['blocktime'])) if tx.get('blocktime') else None,
                    'proof_outputs_in_tx': found})
        if fp not in found:
            out['result'] = 'NOT VERIFIED'
            out['detail'] = ('transaction %s carries no BitcoBoost Proof output' % txid) if not found else ('transaction %s carries a different fingerprint' % txid)
            return report(out, a.json, 1)
        if not tx.get('confirmations'):
            out['result'] = 'PENDING'; out['detail'] = 'the record is in the transaction but not yet in a block'
            return report(out, a.json, 1)
        out['result'] = 'VERIFIED'
        out['detail'] = 'the fingerprint is written on the BitcoBoost chain in transaction %s' % txid
        return report(out, a.json, 0)
    except urllib.error.HTTPError as e:
        return report({'result': 'ERROR', 'detail': 'HTTP %d from %s' % (e.code, e.url)}, a.json, 2)
    except Exception as e:
        return report({'result': 'ERROR', 'detail': str(e)}, a.json, 2)


def report(out, as_json, code):
    if as_json:
        print(json.dumps(out, indent=1))
    else:
        print('%s - %s' % (out.get('result'), out.get('detail', '')))
        for k in ('fingerprint', 'txid', 'txid_from', 'source', 'block_height', 'block_time_utc', 'confirmations', 'block_hash'):
            if out.get(k) is not None:
                print('  %-16s %s' % (k + ':', out[k]))
    return code


if __name__ == '__main__':
    sys.exit(main())
