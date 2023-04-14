/*!
 * Copyright (c) 2020-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as ed25519 from './ed25519.js';
import {createSigner, createVerifier} from './factory.js';
import {exportKeyPair, importKeyPair} from './serialize.js';
import {mbEncodeKeyPair} from './helpers.js';
import {MULTIKEY_CONTEXT_V1_URL} from './constants.js';
import {toMultikey} from './keyPairTranslator.js';

export async function generate({id, controller, seed} = {}) {
  let key;
  if(seed) {
    key = await ed25519.generateKeyPairFromSeed(seed);
  } else {
    key = await ed25519.generateKeyPair();
  }

  const {publicKeyMultibase, secretKeyMultibase} = mbEncodeKeyPair({
    keyPair: key
  });
  if(controller && !id) {
    id = `${controller}#${publicKeyMultibase}`;
  }
  const keyPair = {
    id,
    controller,
    publicKeyMultibase,
    secretKeyMultibase,
    ...key,
  };
  return _createKeyPairInterface({keyPair});
}

// import key pair from JSON Multikey
export async function from(key) {
  let multikey = {...key};
  if(multikey.type && multikey.type !== 'Multikey') {
    multikey = await toMultikey({keyPair: multikey});
    return _createKeyPairInterface({keyPair: multikey});
  }
  if(!multikey.type) {
    multikey.type = 'Multikey';
  }
  if(!multikey['@context']) {
    multikey['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }

  _assertMultikey(multikey);
  return _createKeyPairInterface({keyPair: multikey});
}

async function _createKeyPairInterface({keyPair}) {
  if(!keyPair.publicKey) {
    keyPair = await importKeyPair(keyPair);
  }
  keyPair = {
    ...keyPair,
    async export({
      publicKey = true, secretKey = false, includeContext = true
    } = {}) {
      return exportKeyPair({keyPair, publicKey, secretKey, includeContext});
    },
    signer() {
      const {id, secretKey} = keyPair;
      return createSigner({id, secretKey});
    },
    verifier() {
      const {id, publicKey} = keyPair;
      return createVerifier({id, publicKey});
    }
  };

  return keyPair;
}

function _assertMultikey(key) {
  if(!(key && typeof key === 'object')) {
    throw new TypeError('"key" must be an object.');
  }
  if(key.type !== 'Multikey') {
    throw new Error('"key" must be a Multikey with type "Multikey".');
  }
  if(key['@context'] !== MULTIKEY_CONTEXT_V1_URL) {
    throw new Error('"key" must be a Multikey with context ' +
      `"${MULTIKEY_CONTEXT_V1_URL}".`);
  }
}
