'use strict';

const CIPHER_ROUNDS = 10;
const KEY_LENGTH = 8;
const KEY_CNT_16 = KEY_LENGTH / 2;
const KEY_CNT_32 = KEY_LENGTH / 4;

function rot32(x, r)
{
  x >>>= 0;
  r = (r >>> 0) & 0x1F;
  x = (x >>> (32 - r)) | (x << r);
  return x >>> 0;
}

function fold(x, n)
{
  return 1 + x % (n - 1);
}

function is_array(arr)
{
  if (Array.isArray(arr))
  {
    return true;
  }

  if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(arr))
  {
    return true;
  }

  return false;
}

class WarbirdCrypto
{
  #key;
  #parameters;
  #iv;

  constructor(_k, _p, _iv)
  {
    this.#key = Buffer.from(_k);
    if(this.#key.length !== KEY_LENGTH)
    {
      throw new Error('Invalid warbird key!');
    }

    if(!Array.isArray(_p) || _p.length !== CIPHER_ROUNDS)
    {
      throw new Error('Invalid warbird cipher parameters!');
    }

    this.#parameters = Array(CIPHER_ROUNDS);
    for(let i = 0 ; i < this.#parameters.length ; i++)
    {
      if(!is_array(_p[i]) || _p[i].length !== 4)
      {
        throw new Error('Invalid warbird cipher parameters!');
      }

      this.#parameters[i] = new Uint32Array(4);
      for(let j = 0 ; j < 4 ; j++)
      {
        let x = parseInt(_p[i][j]);
        if(!isFinite(x) || x !== Number(_p[i][j]))
        {
          throw new Error('Invalid warbird cipher parameters!');
        }

        // Round function ID
        if(!j && (x < 0 || x > 30))
        {
          throw new Error('Invalid warbird cipher parameters!');
        }

        this.#parameters[i][j] = x;
      }
    }

    if(typeof(_iv) === 'undefined')
    {
      _iv = 0xF0;
    }
    let x = parseInt(_iv);
    if(!isFinite(x) || x !== Number(_iv))
    {
      throw new Error('Invalid warbird IV!');
    }
    this.#iv = x;

    this.#init_round_functions();
  }

  #k16a(idx)
  {
    let n = idx % KEY_CNT_16;
    return this.#key.readUInt16LE(n << 1);
  }

  #k16b(idx, rnd)
  {
    let n = (idx + fold(rnd, KEY_CNT_16)) % KEY_CNT_16;
    return this.#key.readUInt16LE(n << 1);
  }

  #k32a(idx)
  {
    let n = idx % KEY_CNT_32;
    return this.#key.readUInt32LE(n << 2);
  }

  #k32b(idx)
  {
    let n = (idx + 1) % KEY_CNT_32;
    return this.#key.readUInt32LE(n << 2);
  }

  #k32c(idx)
  {
    let n = ((idx >>> 1) + 1) % KEY_CNT_32;
    return this.#key.readUInt32LE(n << 2);
  }

  #round_functions;
  #init_round_functions()
  {
    let round_templates = Array(31);
    round_templates[0] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(in32 ^ this.#k16b(idx, rnd[1]), this.#k16a(idx)) + (in32 >>> fold(rnd[2], 16))) >>> 0;
    }
    round_templates[1] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(in32 - this.#k16b(idx, rnd[1]), this.#k16a(idx)) - (in32 >>> fold(rnd[2], 16))) >>> 0;
    }
    round_templates[2] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(in32 ^ this.#k16b(idx, rnd[1]), this.#k16a(idx)) ^ (in32 >>> fold(rnd[2], 16))) >>> 0;
    }
    round_templates[3] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(in32 ^ this.#k16b(idx, rnd[1]), this.#k16a(idx)) + rot32(in32, -fold(rnd[2], 16))) >>> 0;
    }
    round_templates[4] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(in32 ^ this.#k16b(idx, rnd[1]), this.#k16a(idx)) - rot32(in32, -fold(rnd[2], 16))) >>> 0;
    }
    round_templates[5] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(in32 ^ this.#k16b(idx, rnd[1]), this.#k16a(idx)) ^ rot32(in32, -fold(rnd[2], 16))) >>> 0;
    }
    round_templates[6] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(in32 ^ this.#k16b(idx, rnd[1]), fold(rnd[2], 8)), this.#k16a(idx)) + (in32 >>> fold(rnd[3], 16))) >>> 0;
    }
    round_templates[7] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(in32 ^ this.#k32c(idx), fold(rnd[2], 8)), this.#k16a(idx)) - (in32 >>> fold(rnd[3], 16))) >>> 0;
    }
    round_templates[8] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(in32 - this.#k16b(idx, rnd[1]), fold(rnd[2], 8)), this.#k16a(idx)) ^ (in32 >>> fold(rnd[3], 16))) >>> 0;
    }
    round_templates[9] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(in32 ^ this.#k16b(idx, rnd[1]), fold(rnd[2], 8)), this.#k16a(idx)) + rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[10] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(in32 ^ this.#k16b(idx, rnd[1]), fold(rnd[2], 8)), this.#k16a(idx)) - rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[11] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(in32 ^ this.#k16b(idx, rnd[1]), fold(rnd[2], 8)), this.#k16a(idx)) ^ rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[12] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(this.#k32c(idx) + in32, -fold(rnd[2], 32)), this.#k16a(idx)) + rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[13] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(this.#k32c(idx) - in32, -fold(rnd[2], 32)), this.#k16a(idx)) + rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[14] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(this.#k32c(idx) ^ in32, -fold(rnd[2], 32)), this.#k16a(idx)) + rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[15] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(this.#k32c(idx) + in32, -fold(rnd[2], 32)), this.#k16a(idx)) - rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[16] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(this.#k32c(idx) - in32, -fold(rnd[2], 32)), this.#k16a(idx)) - rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[17] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(this.#k32c(idx) ^ in32, -fold(rnd[2], 32)), this.#k16a(idx)) - rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[18] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(in32 - this.#k32c(idx), -fold(rnd[2], 32)), this.#k16a(idx)) ^ rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[19] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(this.#k32c(idx) - in32, -fold(rnd[2], 32)), this.#k16a(idx)) ^ rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[20] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(this.#k32c(idx) ^ in32, -fold(rnd[2], 32)), this.#k16a(idx)) ^ rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[21] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(in32 - this.#k32c(idx), -fold(rnd[2], 32)), this.#k16a(idx)) + rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[22] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(in32 - this.#k32c(idx), -fold(rnd[2], 32)), this.#k16a(idx)) - rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[23] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return (Math.imul(rot32(in32 - this.#k32c(idx), -fold(rnd[2], 32)), this.#k16a(idx)) ^ rot32(in32, -fold(rnd[3], 32))) >>> 0;
    }
    round_templates[24] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return Math.imul(rot32(~in32, -fold(rnd[1], 16)) + this.#k16a(idx), this.#k16b(idx, rnd[2])) >>> 0;
    }
    round_templates[25] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return Math.imul(rot32(in32, -fold(rnd[1], 16)) - this.#k16a(idx), this.#k16b(idx, rnd[2])) >>> 0;
    }
    round_templates[26] = (idx, in32) => {
      let rnd = this.#parameters[idx];
      return Math.imul(rot32(in32, -fold(rnd[1], 16)) ^ this.#k16a(idx), this.#k16b(idx, rnd[2])) >>> 0;
    }
    round_templates[27] = (idx, in32) => {
      return (this.#k32b(idx) - (this.#k32a(idx) ^ in32)) >>> 0;
    }
    round_templates[28] = (idx, in32) => {
      return (this.#k32b(idx) ^ (this.#k32a(idx) ^ in32)) >>> 0;
    }
    round_templates[29] = (idx, in32) => {
      return ((in32 - this.#k16a(idx)) ^ this.#k32c(idx)) >>> 0;
    }
    round_templates[30] = (idx, in32) => {
      return ((in32 - this.#k16a(idx)) - this.#k32c(idx)) >>> 0;
    }

    this.#round_functions = Array(CIPHER_ROUNDS);
    for(let i = 0 ; i < CIPHER_ROUNDS ; i++)
    {
      this.#round_functions[i] = round_templates[this.#parameters[i][0]];
      if(!this.#round_functions[i])
      {
        throw new Error('Round function ID out of bound!');
      }
    }
  }

  static from_buffer(key_pos_buf)
  {
    if(key_pos_buf.length < 0xA8)
    {
      throw new Exception('Invalid key buffer');
    }

    let k = key_pos_buf.subarray(0, 8);
    let arr = Array(10);
    let x = 8;
    for(let i = 0 ; i < arr.length ; i++)
    {
      arr[i] = new Uint32Array(4);
      for(let j = 0 ; j < arr[i].length ; j++)
      {
        arr[i][j] = key_pos_buf.readUInt32LE(x);
        x += 4;
      }
    }

    return new WarbirdCrypto(k, arr);
  }

  #encrypt_block(ctx)
  {
    for(let i = 0 ; i < CIPHER_ROUNDS ; i += 2)
    {
      let j = i + 1;

      ctx[1] ^= this.#round_functions[i](i, ctx[0]);
      ctx[0] ^= this.#round_functions[j](j, ctx[1]);
    }
  }

  #decrypt_block(ctx)
  {
    for(let i = 0 ; i < CIPHER_ROUNDS ; i += 2)
    {
      let i1 = CIPHER_ROUNDS - 1 - i;
      let i2 = CIPHER_ROUNDS - 2 - i;

      ctx[0] ^= this.#round_functions[i1](i1, ctx[1]);
      ctx[1] ^= this.#round_functions[i2](i2, ctx[0]);
    }
  }

  encrypt(data)
  {
    let buf = Buffer.from(data);
    if(!buf.length)
    {
      throw new Error('Invalid input data!');
    }

    let prev = new Uint32Array(2);
    prev._ptr = Buffer.from(prev.buffer);

    let cache = new Uint32Array(2);
    cache._ptr = Buffer.from(cache.buffer);

    cache[0] = ~this.#iv;
    cache[1] = this.#iv;

    let offset = buf.length % KEY_LENGTH;
    if(offset)
    {
      this.#decrypt_block(cache);

      buf.copy(prev._ptr, 0, 0, offset);

      cache[0] ^= prev[0];
      cache[1] ^= prev[1];

      cache._ptr.copy(buf, 0, 0, offset);
    }

    for( ; offset < buf.length ; offset += KEY_LENGTH)
    {
      cache[0] ^= buf.readUInt32LE(offset);
      cache[1] ^= buf.readUInt32LE(offset + 4);

      this.#encrypt_block(cache);

      cache[0] ^= prev[0];
      cache[1] ^= prev[1];

      buf.copy(prev._ptr, 0, offset);
      cache._ptr.copy(buf, offset);
    }

    return buf;
  }

  decrypt(data)
  {
    let buf = Buffer.from(data);
    if(!buf.length)
    {
      throw new Error('Invalid input data!');
    }

    let prev = new Uint32Array(2);
    prev._ptr = Buffer.from(prev.buffer);

    let cache = new Uint32Array(2);
    cache._ptr = Buffer.from(cache.buffer);

    let offset = buf.length % KEY_LENGTH;
    if(offset)
    {
      cache[0] = ~this.#iv;
      cache[1] = this.#iv;

      this.#decrypt_block(cache);

      buf.copy(prev._ptr, 0, 0, offset);

      cache[0] ^= prev[0];
      cache[1] ^= prev[1];

      cache._ptr.copy(buf, 0, 0, offset);
    }
    else
    {
      prev[0] = ~this.#iv;
      prev[1] = this.#iv;
    }

    for( ; offset < buf.length ; offset += KEY_LENGTH)
    {
      cache[0] ^= buf.readUInt32LE(offset);
      cache[1] ^= buf.readUInt32LE(offset + 4);

      this.#decrypt_block(cache);

      cache[0] ^= prev[0];
      cache[1] ^= prev[1];

      buf.copy(prev._ptr, 0, offset);
      cache._ptr.copy(buf, offset);
    }

    return buf;
  }
}

module.exports = WarbirdCrypto;
