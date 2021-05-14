const {
  createDecipheriv,
  createCipheriv,
  randomBytes
} = require('crypto')
const { Transform } = require('stream')
const { createReadStream } = require('fs')
const { pad } = require('../set2/pkcs7')
const { xorTwoBuffers } = require('./xor_utils')

/**
 * Decrypts the contents of the encipheredBuffer using the provided
 * keyBuffer. 
 * 
 * @param {Buffer} encipheredBuffer A buffer holding the enciphered bytes.
 * @param {Buffer} keyBuffer A buffer holding the bytes of the key.
 * @param {boolean} autoPadding If the encipheredBuffer is already padded
 * then set this to false.
 * @returns {Buffer} A buffer containing the decrypted bytes.
 */
function decryptAes128Ecb (encipheredBuffer, keyBuffer, autoPadding = true) {
  const algorithm = 'aes-128-ecb'
  const initVector = null // ECB doesn't use an init vector

  const decipher = createDecipheriv(algorithm, keyBuffer, initVector)
  decipher.setAutoPadding(autoPadding)
  const decryptedBuffer = decipher.update(encipheredBuffer)
  const finalBuffer = decipher.final()
  return Buffer.concat([decryptedBuffer, finalBuffer])
}

/**
 *
 * @param {Buffer} plainTextBuffer Buffer holding the plain text bytes
 * @param {Buffer} keyBuffer Buffer holding the key bytes
 * @param {boolean} autoPadding whether to enable autopadding, default true
 * @returns a Buffer containing the bytes of the encrypted data
 */
function encryptAes128Ecb (plainTextBuffer, keyBuffer, autoPadding = true) {
  const algorithm = 'aes-128-ecb'
  const initVector = null // ECB doesn't use an init vector

  const cipher = createCipheriv(algorithm, keyBuffer, initVector)
  cipher.setAutoPadding(autoPadding)
  return Buffer.concat([cipher.update(plainTextBuffer), cipher.final()])
}

function decoder (encoding) {
  return new Transform({
    objectMode: true,
    transform: (data, _, done) => {
      const encoded = Buffer.from(data, encoding)
      done(null, encoded)
    }
  })
}

async function decryptAes128EcbStreamed (filePath, key, encoding = 'base64') {
  const algorithm = 'aes-128-ecb'
  const initVector = null // ECB doesn't use an init vector
  const keyBuffer = Buffer.from(key)
  const decipher = createDecipheriv(algorithm, keyBuffer, initVector)

  createReadStream(filePath, { encoding: 'utf-8' })
    .pipe(decoder(encoding))
    .pipe(decipher)

  const results = []
  for await (const decryptedChunk of decipher) {
    results.push(decryptedChunk)
  }
  return results.toString()
}

/**
 *  Encrypts the plainText with the provided key and returns the bytes in a
 *  buffer along with the randoly choosen initialization vector.
 * @param {Buffer} plainText
 * @param {Buffer} key
 * @returns {Buffer encryptedBuffer, Buffer IV} 
 */
function encryptAes128Cbc (plainText, key) {
  const blockSize = 16
  const IV = randomBytes(blockSize)
  const plainTextBuffer = Buffer.from(plainText)
  let previousBlock = IV
  const encryptedBlocks = []
  for (let i = 0; i < plainTextBuffer.length; i += blockSize) {
    const block = plainTextBuffer.slice(i, i + blockSize)
    const paddedBlock = pad(block, blockSize)
    const xorBlock = xorTwoBuffers(previousBlock, paddedBlock)
    const encryptedBlock = encryptAes128Ecb(xorBlock, key, false)
    encryptedBlocks.push(encryptedBlock)
    previousBlock = encryptedBlock
  }
  return {
    encryptedBuffer: Buffer.concat(encryptedBlocks),
    IV
  }
}

/**
 * Strips the padding from the last block of decrypted blocks
 * @param {Array of Buffers} blocks the decrypted blocks
 * @param {Number} blockSize the original block size
 * used when applying the padding
 * @returns an Array of Buffers
 */
function stripPadding (blocks, blockSize = 16) {
  const lastBlock = blocks[blocks.length - 1]
  const lastBlockNoPadding = lastBlock.filter(byte => {
    return byte > blockSize
  })

  return [...blocks.slice(0, blocks.length - 1), lastBlockNoPadding]
}

/**
 * Returns the plain text after performing CBC decryption.
 * @param {base64 encoded String} encrytedText
 * @param {utf-8 encoded String} key
 * @param {base64 encoded String} IV The initilization vector
 * @param {number} blockSize
 * @return {String} The decrypted plain text
 */
function decryptAes128Cbc (encrytedText, key, IV) {
  const blockSize = 16
  const encryptedBytes = Buffer.from(encrytedText, 'base64')
  const IVBuffer = Buffer.from(IV, 'base64')
  const keyBuffer = Buffer.from(key)

  let previousBlock = IVBuffer
  const decryptedBlocks = []
  for (let i = 0; i < encryptedBytes.length; i += blockSize) {
    const block = encryptedBytes.slice(i, i + blockSize)
    const decryptedBlock = decryptAes128Ecb(block, keyBuffer, false)
    const xorBlock = xorTwoBuffers(previousBlock, decryptedBlock)
    decryptedBlocks.push(xorBlock)
    previousBlock = block
  }
  return Buffer.concat(stripPadding(decryptedBlocks)).toString()
}

/**
 * Provided a Buffer of bytes this function attempts to detect ECB
 * mode encryption by looking for a reapting sequence of bytes of
 * blockLength size. If a repeating block is found then it returns
 * the buffer of bytes as a hex String, otherwise returns undefined.
 *
 * @param {Buffer} buffer A buffer containing the encrypted bytes.
 * @param {Number} blockLength The length of repeating byte 
 * sequences to search for.
 * @returns  {String} the hex encoded buffer as a String if ECB
 * encryption is detected else return undefined.
 */
function detectAesEcb (buffer, blockLength = 16) {
  const frequencyOfBlockValues = {}
  for (let i = 0; i + blockLength < buffer.length; i += blockLength) {
    const blockHex = buffer.slice(i, i + blockLength).toString('hex')
    if (blockHex in frequencyOfBlockValues) {
      frequencyOfBlockValues[blockHex] += 1
    } else {
      frequencyOfBlockValues[blockHex] = 1
    }
  }
  for (const frequency of Object.values(frequencyOfBlockValues)) {
    if (frequency > 1 ) {
      return buffer.toString('hex')
    }
  }
}


/** Returns a random integer between the min (inclusive) and
 * max (exclusive).
 *
 * @param {number} min - inclusive
 * @param {number} max - exclusive
 * @returns  number
 */
function randomNumberBetween (min, max) {
  return Math.floor(Math.random() * (max - min) + min)
}

/**
 * Returns true or false randomly
 */
function fiftyFifty () {
  return Math.random() < 0.5
}

/** Encrypts plainText with a randomly generated key using either
 * ECB or CBC mode choosen at random (randonly generated IV is used
 * for CBC mode). Prepends 5-10 bytes (count chosen at random) and
 * appends 5-10 bytes (count chosen at random) to the plainText before
 * encryption.
 *
 * @param {String} plainText
 * @returns {String: encryption method, Buffer: encrypted plainText}
 */
function encryptEitherECBorCBC (plainText) {
  const keyBuffer = randomBytes(16)
  const prependedBytes = randomBytes(randomNumberBetween(5, 11))
  const appendedBytes = randomBytes(randomNumberBetween(5, 11))
  const inputBuffer = Buffer.concat([
    prependedBytes,
    Buffer.from(plainText),
    appendedBytes])

  let encryptedBuffer, encryptionMethod
  if (fiftyFifty()) {
    encryptedBuffer = encryptAes128Ecb(inputBuffer, keyBuffer)
    encryptionMethod = 'ECB'
  } else {
    encryptedBuffer = encryptAes128Cbc(inputBuffer, keyBuffer).encryptedBuffer
    encryptionMethod = 'CBC'
  }

  return {
    encryptedBuffer,
    encryptionMethod
  }
}

const RANDOM_KEY = randomBytes(16)

function oracleFunction(plainBuffer) {
  const unknownBuffer = Buffer.from(`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
  aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
  dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
  YnkK`, 'base64')

  return encryptAes128Ecb(Buffer.concat([plainBuffer, unknownBuffer]), RANDOM_KEY)
}

/**
 * Keeps adding a single byte 'A' to be encrypted until the first n bytes
 * start repeating. Returns n as the predicted block size. 
 * @returns Number predicted block size
 */
function findOracleBlockSize() {
  let previousResult = oracleFunction(Buffer.alloc(1, 'A'))
  for (let i = 2; i < 64; i++) {
    const currentResult = oracleFunction(Buffer.alloc(i, 'A'))
    if (currentResult.slice(0, 4).toString('hex') === previousResult.slice(0, 4).toString('hex')) {
      return i - 1
    }
    previousResult = currentResult
  }
}

function crackOracle() {
  const predictedBlockSize = 16//findBlockSizeForEcb()

  if (detectECBorCBC(oracleFunction(Buffer.alloc(33, 'A'))) !== 'ECB') {
    throw new Error('Encryption method is not ECB')
  }

  const payloadLength = oracleFunction(Buffer.alloc(0)).length - 7 // need to sort this out :)

  let result = ""
  for(let i = 0; i < payloadLength; i++) {
    const blockNumber = Math.floor(i / predictedBlockSize)
    const numberOfAs = (predictedBlockSize - (i % predictedBlockSize) - 1)
    const As = Buffer.alloc(numberOfAs, 'A')
    const encryptionResult = oracleFunction(As)
    const targetBlock = encryptionResult.slice(blockNumber * predictedBlockSize, (blockNumber + 1) * predictedBlockSize)
    for (let x = 0; x < 255; x++){
      const input = Buffer.concat([As, Buffer.from(result), Buffer.from([x])])
      const encrypted = oracleFunction(input)
      const blockToCheck = encrypted.slice(blockNumber * predictedBlockSize, (blockNumber + 1) * predictedBlockSize)
      if (blockToCheck.toString('hex') === targetBlock.toString('hex')) {
        result += String.fromCharCode(x)
        break
      }
    }
  }
  return result
}


/**
 * When provided a buffer of bytes encrypted with either aes-128-ecb
 * of aes-128-cbc will return which mode was used.
 * @param {Buffer} encipheredBuffer Buffer holding the encrypted bytes
 * which have been encrypted with either aes-128-ecb or aes-128-cbc
 * @returns String Either 'ECB' or 'CBC'.
 */
function detectECBorCBC(encipheredBuffer) {
  if (detectAesEcb(encipheredBuffer)) {
    return 'ECB'
  }
  return 'CBC'
}


module.exports = {
  decryptAes128Ecb,
  decryptAes128EcbStreamed,
  encryptAes128Ecb,
  encryptAes128Cbc,
  decryptAes128Cbc,
  detectAesEcb,
  encryptEitherECBorCBC,
  detectECBorCBC,
  findOracleBlockSize,
  crackOracle,
  oracleFunction
}
