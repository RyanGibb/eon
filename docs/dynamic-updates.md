
### Dynamic Updates

The server uses [TSIG](https://www.rfc-editor.org/rfc/rfc2845) resources records (RRs) to authenticate queries. For example, [DNS UPDATE](https://www.rfc-editor.org/rfc/rfc2136) queries can be authenticated to provide secure dynamic updates.

We pass [HMAC](https://www.rfc-editor.org/rfc/rfc2104) keys to the server through a zonefile representation that is in a file eon `<zonefile>._keys`, e.g. [`example.org._keys`](./example/example.org._keys). These are secret keys, and should not be published.

A DNSKEY RR domain name in this file must be of the format `<name>.<operation>.<domain>`, where `<operation>` can be `_update`, `_transfer`, or `_notify`.

To generate these keys we can use:
```
$ cat /dev/random | head -c 32 | base64
FGwot7AqiDIthEv6TippJm35DaRpRac5NSLd/wSp9go=
```

Then to perform a dynamic update we can use use the BIND utility `nsupdate`:
```
$ echo "update add test.example.org 86400 A 203.0.113.1\n" | nsupdate -l -y hmac-sha256:client._update.example.org:FGwot7AqiDIthEv6TippJm35DaRpRac5NSLd/wSp9go=
$ dig test.example.org @localhost
203.0.113.1
```

The TSIG key name, `client._update.example.org` here, must match the name in the zonefile.

See also the [capability interface](./cap.md).

