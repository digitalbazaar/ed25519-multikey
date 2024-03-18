/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58btc from 'base58-universal';
import {mockKey, seed} from './mock-data.js';
import chai from 'chai';
import multibase from 'multibase';
import multicodec from 'multicodec';
const should = chai.should();
const {expect} = chai;

import * as Ed25519Multikey from '../lib/index.js';
import {
  Ed25519VerificationKey2018
} from '@digitalbazaar/ed25519-verification-key-2018';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';

// multibase base58-btc header
const MULTIBASE_BASE58BTC_HEADER = 'z';

describe('Ed25519Multikey', () => {
  describe('module', () => {
    it('should have "generate" and "from" properties', async () => {
      expect(Ed25519Multikey).to.have.property('generate');
      expect(Ed25519Multikey).to.have.property('from');
    });
  });

  describe('generate', () => {
    it('should generate a key pair', async () => {
      let ldKeyPair;
      let error;
      try {
        ldKeyPair = await Ed25519Multikey.generate();
      } catch(e) {
        error = e;
      }

      should.not.exist(error);
      expect(ldKeyPair).to.have.property('publicKeyMultibase');
      expect(ldKeyPair).to.have.property('secretKeyMultibase');
      expect(ldKeyPair).to.have.property('publicKey');
      expect(ldKeyPair).to.have.property('secretKey');
      expect(ldKeyPair).to.have.property('export');
      expect(ldKeyPair).to.have.property('signer');
      expect(ldKeyPair).to.have.property('verifier');
      const secretKeyBytes = base58btc
        .decode(ldKeyPair.secretKeyMultibase.slice(1));
      const publicKeyBytes = base58btc
        .decode(ldKeyPair.publicKeyMultibase.slice(1));
      secretKeyBytes.length.should.equal(66);
      publicKeyBytes.length.should.equal(34);
    });

    it('should generate the same key from the same seed', async () => {
      const seed = new Uint8Array(32);
      seed.fill(0x01);
      const keyPair1 = await Ed25519Multikey.generate({seed});
      const keyPair2 = await Ed25519Multikey.generate({seed});
      expect(keyPair1.publicKeyMultibase).to.equal(keyPair2.publicKeyMultibase);
      expect(keyPair1.secretKeyMultibase).to
        .equal(keyPair2.secretKeyMultibase);
    });
  });

  describe('export', () => {
    it('should export id, type and key material', async () => {
      // Encoding returns a 64 byte uint8array, seed needs to be 32 bytes
      const seedBytes = (new TextEncoder()).encode(seed).slice(0, 32);
      const keyPair = await Ed25519Multikey.generate({
        seed: seedBytes, controller: 'did:example:1234'
      });
      const pastDate = new Date(2020, 11, 17).toISOString()
        .replace(/\.[0-9]{3}/, '');
      keyPair.revoked = pastDate;

      const exported = await keyPair.export({
        publicKey: true, secretKey: true
      });

      const properties = [
        'id', 'type', 'controller', 'publicKeyMultibase', 'secretKeyMultibase',
        'revoked'
      ];
      for(const property of properties) {
        expect(exported).to.have.property(property);
        expect(exported[property]).to.exist;
      }

      expect(exported.controller).to.equal('did:example:1234');
      expect(exported.type).to.equal('Multikey');
      expect(exported.id).to.equal('did:example:1234#' +
        'z6Mkpw72M9suPCBv48X2Xj4YKZJH9W7wzEK1aS6JioKSo89C');
      expect(exported).to.have.property('publicKeyMultibase',
        'z6Mkpw72M9suPCBv48X2Xj4YKZJH9W7wzEK1aS6JioKSo89C');
      expect(exported).to.have.property('secretKeyMultibase',
        'zrv1mHUXWkWUpThaapTt8tkxSotE1iSRRuPNarhs3vTn2z61hQESuKXG7zGQsePB7JHd' +
        'jaCzPZmBkkqULLvoLHoD82a');
      expect(exported).to.have.property('revoked', pastDate);
    });

    it('should only export public key if specified', async () => {
      const keyPair = await Ed25519Multikey.generate({
        id: 'did:ex:123#test-id'
      });
      const exported = await keyPair.export({publicKey: true});

      expect(exported).to.have.property('publicKeyMultibase');
      expect(exported).to.have.property('id', 'did:ex:123#test-id');
      expect(exported).to.have.property('type', 'Multikey');
    });
  });

  describe('from', () => {
    it('should auto-set key.id based on controller', async () => {
      const {publicKeyMultibase} = mockKey;
      const controller = 'did:example:1234';

      const keyPair = await Ed25519Multikey.from(
        {controller, publicKeyMultibase});

      _ensurePublicKeyEncoding({keyPair, publicKeyMultibase});
      expect(keyPair.id).to.equal(
        'did:example:1234#z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T');
    });
    // eslint-disable-next-line max-len
    it('should error if publicKeyMultibase property is missing', async () => {
      let error;
      try {
        await Ed25519Multikey.from({});
      } catch(e) {
        error = e;
      }
      expect(error).to.be.an.instanceof(TypeError);
      expect(error.message)
        .to.equal('The "publicKeyMultibase" property is required.');
    });
    it('should round-trip load exported keys', async () => {
      // Encoding returns a 64 byte uint8array, seed needs to be 32 bytes
      const seedBytes = (new TextEncoder()).encode(seed).slice(0, 32);
      const keyPair = await Ed25519Multikey.generate({
        seed: seedBytes, controller: 'did:example:1234'
      });
      const exported = await keyPair.export({
        publicKey: true, secretKey: true
      });
      const imported = await Ed25519Multikey.from(exported);

      expect(await imported.export({publicKey: true, secretKey: true}))
        .to.eql(exported);
    });
    it('should load `publicKeyJwk`', async () => {
      const jwk = {
        crv: 'Ed25519',
        kty: 'OKP',
        x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
      };
      const imported1 = await Ed25519Multikey.from({
        publicKeyJwk: jwk
      });
      const imported2 = await Ed25519Multikey.from({
        type: 'JsonWebKey',
        publicKeyJwk: jwk
      });
      const exported1 = await Ed25519Multikey.toJwk({keyPair: imported1});
      const exported2 = await Ed25519Multikey.toJwk({keyPair: imported2});
      expect(exported1).to.eql(jwk);
      expect(exported2).to.eql(jwk);
    });
  });

  describe('Backwards compat with Ed25519VerificationKey2018', () => {
    const seedBytes = (new TextEncoder()).encode(seed).slice(0, 32);

    it('Multikey should import from 2018', async () => {
      const keyPair2018 = await Ed25519VerificationKey2018.generate({
        seed: seedBytes, controller: 'did:example:1234'
      });

      const keyPairMultikey = await Ed25519Multikey.from(keyPair2018);

      // Both should sign and verify the same
      const data = (new TextEncoder()).encode('test data goes here');
      const signatureBytes2018 = await keyPair2018.signer().sign({data});

      const signatureBytesMultikey = await keyPairMultikey.signer()
        .sign({data});

      expect(signatureBytes2018).to.eql(signatureBytesMultikey);
      expect(
        await keyPairMultikey.verifier()
          .verify({data, signature: signatureBytes2018})
      ).to.be.true;
    });

    it('Multikey should generate the same from seed as 2018', async () => {
      const keyPair2018 = await Ed25519VerificationKey2018.generate({
        seed: seedBytes, controller: 'did:example:1234'
      });
      const keyPairMultikey = await Ed25519Multikey.generate({
        seed: seedBytes, controller: 'did:example:1234'
      });

      const data = (new TextEncoder()).encode('test data goes here');
      const signatureBytes2018 = await keyPair2018.signer().sign({data});
      const signatureBytesMultikey = await keyPairMultikey.signer()
        .sign({data});
      expect(signatureBytes2018).to.eql(signatureBytesMultikey);
    });
  });

  describe('Backwards compat with Ed25519VerificationKey2020', () => {
    const seedBytes = (new TextEncoder()).encode(seed).slice(0, 32);

    it('Multikey should import from 2020', async () => {
      const keyPair2020 = await Ed25519VerificationKey2020.generate({
        seed: seedBytes, controller: 'did:example:1234'
      });
      const keyPairMultikey = await Ed25519Multikey.from(keyPair2020);

      // Both should sign and verify the same
      const data = (new TextEncoder()).encode('test data goes here');
      const signatureBytes2020 = await keyPair2020.signer().sign({data});
      const signatureBytesMultikey = await keyPairMultikey.signer()
        .sign({data});
      expect(signatureBytes2020).to.eql(signatureBytesMultikey);
      expect(
        await keyPairMultikey.verifier()
          .verify({data, signature: signatureBytes2020})
      ).to.be.true;
    });

    it('Multikey should generate the same from seed as 2020', async () => {
      const keyPair2020 = await Ed25519VerificationKey2020.generate({
        seed: seedBytes, controller: 'did:example:1234'
      });
      const keyPairMultikey = await Ed25519Multikey.generate({
        seed: seedBytes, controller: 'did:example:1234'
      });

      const data = (new TextEncoder()).encode('test data goes here');
      const signatureBytes2020 = await keyPair2020.signer().sign({data});
      const signatureBytesMultikey = await keyPairMultikey.signer()
        .sign({data});
      expect(signatureBytes2020).to.eql(signatureBytesMultikey);
    });
  });
});

function _ensurePublicKeyEncoding({keyPair, publicKeyMultibase}) {
  keyPair.publicKeyMultibase.startsWith('z').should.be.true;
  const mcPubkeyBytes = multibase.decode(publicKeyMultibase);
  const mcType = multicodec.getCodec(mcPubkeyBytes);
  mcType.should.equal('ed25519-pub');
  const pubkeyBytes =
    multicodec.addPrefix('ed25519-pub', multicodec.rmPrefix(mcPubkeyBytes));
  const encodedPubkey = MULTIBASE_BASE58BTC_HEADER +
    base58btc.encode(pubkeyBytes);
  encodedPubkey.should.equal(keyPair.publicKeyMultibase);
}
