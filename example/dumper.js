'use strict';

const crypto = require('crypto');
const fs = require('fs');

const WarbirdCrypto = require('./warbird-crypto.js');

/*
let key = Buffer.from('FEAFFECAEFBEADDE', 'hex');
let params = [
  [0x07, 0x27, 0xF6, 0x85],
  [0x15, 0x15, 0xAD, 0x1D],
  [0x04, 0x94, 0xDD, 0xC4],
  [0x1B, 0x19, 0x39, 0x31],
  [0x11, 0xAD, 0xB5, 0x58],
  [0x17, 0x97, 0x32, 0x19],
  [0x16, 0xD1, 0xC0, 0xFD],
  [0x08, 0x8E, 0x4E, 0x48],
  [0x12, 0x0B, 0xF5, 0x3B],
  [0x01, 0xA8, 0x63, 0x5D]
];
let ctx = new WarbirdCrypto(key, params);
*/

// Malware sample SHA256: b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3
let buf = fs.readFileSync('ConsoleApplication2.virus');

let ctx = WarbirdCrypto.from_buffer(buf.subarray(0x15A88, 0x15B30));
let enc = buf.subarray(0x15B30, 0x15ED0);

let dec = ctx.decrypt(enc);
fs.writeFileSync('stager.sc', dec);

console.log('Done!');
