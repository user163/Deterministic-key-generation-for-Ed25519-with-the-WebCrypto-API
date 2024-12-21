(async () => {

const prefixHex = '302e020100300506032b657004220420'
const size = 256
const kdfHash = 'SHA-256'
const kdfIterations = 100000

async function genDetEd25519KeyPair(passphrase, salt) {   
    const textEncoder = new TextEncoder()
    const passphraseAB = textEncoder.encode(passphrase) 
    const saltAB = textEncoder.encode(salt) 
    // derive raw private key via PBKDF2
    const passphraseCK = await crypto.subtle.importKey('raw', passphraseAB, { name: 'PBKDF2' }, false, ['deriveBits'])
    const rawPrivateEcKeyAB = await deriveRawPrivate(saltAB, passphraseCK)
    // convert to PKCS#8
    const pkcs8AB = new Uint8Array([ ...hex2ab(prefixHex), ...new Uint8Array(rawPrivateEcKeyAB)]) 
    const privateKeyCK = await crypto.subtle.importKey('pkcs8', pkcs8AB, { name: 'Ed25519' }, true, ['sign'] )
    // get public key 
    const publicKeyCK = await getPublic(privateKeyCK)
    const spkiAB = await crypto.subtle.exportKey('spki', publicKeyCK)
    return { pkcs8AB, spkiAB };
}

async function deriveRawPrivate(saltAB, passphraseCK){
    return await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltAB, iterations: kdfIterations, hash: kdfHash }, passphraseCK, size)
}

async function getPublic(privateKeyCK){
    const privatKeyJWK = await crypto.subtle.exportKey('jwk', privateKeyCK)    
    delete privatKeyJWK.d
    privatKeyJWK.key_ops = ['verify']
    return crypto.subtle.importKey('jwk', privatKeyJWK, { name: 'Ed25519' }, true, ['verify'])
}

function ab2hex(ab) { 
    return Array.prototype.map.call(new Uint8Array(ab), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function hex2ab(hex){
    return new Uint8Array(hex.match(/[\da-f]{2}/gi).map(function (h) { return parseInt(h, 16) }));
}

// Use case: Sigan and verify a message with Ed25519 -----------------------------------------------------------

// 1. Determinstic key generation
var keys =  await genDetEd25519KeyPair('a passphrase', 'some salt')
console.log('PKCS#8:', ab2hex(keys.pkcs8AB))
console.log('SPKI:', ab2hex(keys.spkiAB))

// 2. key import
var privateKeyCK = await crypto.subtle.importKey('pkcs8', keys.pkcs8AB, { name: 'Ed25519' }, true,  ['sign'])
var publicKeyCK = await crypto.subtle.importKey('spki', keys.spkiAB, { name: 'Ed25519' }, true,  ['verify'])

// 3. sign message
var messageAB = new TextEncoder().encode('The quick brown fox jumps over the lazy dog')
var signatureAB = await window.crypto.subtle.sign({ name: 'Ed25519' }, privateKeyCK, messageAB)

// 4. verify message
var verified = await window.crypto.subtle.verify({ name: 'Ed25519' }, publicKeyCK, signatureAB, messageAB)

console.log('Signature:', ab2hex(signatureAB)) 
console.log('Verification:', verified)

})();
