@0xf8f86fb5561e3599;

interface Cert {
  request @0 (email :Text, org :Text, domain :Text, account_key :Data, private_key :Data)
    -> (success :Bool, error :Text, cert :Data);
}
