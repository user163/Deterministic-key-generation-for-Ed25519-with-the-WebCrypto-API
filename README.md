# Deterministic key generation for Ed25519 with the WebCrypto API

Using PBKDF2 (or HKDF), a 32 byte sequence is deterministically generated, which acts as raw private key. This is converted into a PKCS#8 key and imported.

Since the WebCrypto API has no function to extract the public key from a private key, the private key is exported as JWK. Private JWK keys must by definition contain the public key component.  
In the exported key, the private key component is removed and the remaining key is re-imported. In this way, a *purely* public CryptoKey is generated, which can be exported as e.g. an X.509/SPKI key.

Browser compatibility: This works for Chrome and Chrome-based browsers such as Edge and Opera (all use the Blink browser engine). Other browsers such as Safari or Firefox fail because they either cannot import a PKCS#8 key without a public key component or cannot export the key as JWK (a private key in JWK format contains by definition the public key component, which presumably is not derived from the private key in these browsers).  

For Chrome/Edge 113 and opera 99, the `#enable-experimental-web-platform-features` flag must be set to make Ed25519 available.
