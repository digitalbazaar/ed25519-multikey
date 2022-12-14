/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {mbDecodeKeyPair} from './helpers.js';
import {MULTIKEY_CONTEXT_V1_URL} from './constants.js';

export async function exportKeyPair({
  keyPair, secretKey, publicKey, includeContext
} = {}) {
  if(!(publicKey || secretKey)) {
    throw new TypeError(
      'Export requires specifying either "publicKey" or "secretKey".');
  }

  // export as Multikey
  const exported = {
    '@context': undefined,
    id: undefined,
    controller: undefined,
    type: 'Multikey',
    publicKeyMultibase: undefined,
    secretKeyMultibase: undefined,
    revoked: undefined
  };

  if(keyPair.id) {
    exported.id = keyPair.id;
  }

  if(keyPair.controller) {
    exported.controller = keyPair.controller;
  }

  if(keyPair.revoked) {
    exported.revoked = keyPair.revoked;
  }

  if(includeContext) {
    exported['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }

  if(publicKey) {
    exported.publicKeyMultibase = keyPair.publicKeyMultibase;
  }

  if(secretKey) {
    exported.secretKeyMultibase = keyPair.secretKeyMultibase;
  }

  return exported;
}

export async function importKeyPair({
  id, controller, secretKeyMultibase, publicKeyMultibase, revoked
}) {
  if(!publicKeyMultibase) {
    throw new TypeError('The "publicKeyMultibase" property is required.');
  }

  const {
    publicKey, secretKey
  } = mbDecodeKeyPair({publicKeyMultibase, secretKeyMultibase});

  if(controller && !id) {
    id = `${controller}#${publicKeyMultibase}`;
  }

  return {
    id,
    controller,
    publicKey,
    secretKey,
    publicKeyMultibase,
    secretKeyMultibase,
    revoked,
  };
}
