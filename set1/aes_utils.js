const { createDecipheriv, createCipheriv, randomBytes } = require('crypto')
const { Transform } = require('stream')
const { createReadStream } = require('fs')
const { pad } = require('../set2/pkcs7')
const { xorTwoBuffers } = require('./xor_utils')

/**
 * 
 * @param {*} enciphredBuffer 
 * @param {*} keyBuffer 
 * @returns Buffer containing the decrypted data
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

function decoder(encoding) {
  return new Transform({
      objectMode: true,
      transform: (data, _, done) => {
        const encoded = Buffer.from(data, encoding)
        done(null, encoded)
      }
    })
}

async function decryptAes128EcbStreamed(filePath, key, encoding = 'base64') {
    const algorithm = 'aes-128-ecb'
    const initVector = null // ECB doesn't use an init vector
    const keyBuffer = Buffer.from(key)
    const decipher = createDecipheriv(algorithm, keyBuffer, initVector)

    createReadStream(filePath, {encoding: 'utf-8'})
    .pipe(decoder(encoding))
    .pipe(decipher)

    const results = []
    for await(const decryptedChunk of decipher) {
      results.push(decryptedChunk)
    }
    return results.toString()
}

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
    const encryptedBlock = Buffer.from(encryptAes128Ecb(xorBlock, key), 'base64')
    encryptedBlocks.push(encryptedBlock)
    previousBlock = encryptedBlock
  }
  return {
    cipherText: Buffer.concat(encryptedBlocks).toString('base64'), 
    IV: IV.toString('base64') 
  }
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
  const buffer = Buffer.from(encrytedText, 'base64')
  const IVBuffer = Buffer.from(IV, 'base64')
  let previousBlock = IVBuffer
  let plainText = ""
  for (let i = 0; i < buffer.length; i += blockSize) {
    const block = buffer.slice(i, i + blockSize)
    if (block.length !== blockSize) {
      console.log('here')
    }
    const decryptedBlock = Buffer.from(decryptAes128Ecb(block.toString('base64'), key))
    const xorBlock = xorTwoBuffers(previousBlock, decryptedBlock)
    plainText += xorBlock.toString()
    previousBlock = block
  }
  return plainText
}


function detectAesEcb (buffer) {
  const frequencyOfBlockValues = {}
  const blockLength = 16
  for (let i = 0; i + blockLength < buffer.length; i += blockLength) {
    const blockHex = buffer.slice(i, i + blockLength).toString('hex')
    if (blockHex in frequencyOfBlockValues) {
      frequencyOfBlockValues[blockHex] += 1
    } else {
      frequencyOfBlockValues[blockHex] = 1
    }
  }
  for (const frequency of Object.values(frequencyOfBlockValues)) {
    if (frequency > 1) {
      return buffer.toString('hex')
    }
  }
}


module.exports = {
  decryptAes128Ecb,
  decryptAes128EcbStreamed,
  encryptAes128Ecb,
  encryptAes128Cbc,
  decryptAes128Cbc,
  detectAesEcb
}
