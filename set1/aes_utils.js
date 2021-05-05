const { createDecipheriv, createCipheriv, randomBytes } = require('crypto')
const { Transform } = require('stream')
const { createReadStream } = require('fs')
const { pad } = require('../set2/pkcs7')
const { xorTwoBuffers } = require('./xor_utils')

function decryptAes128Ecb (encryptedString, key, encoding = 'base64') {
  const algorithm = 'aes-128-ecb'
  const initVector = null // ECB doesn't use an init vector
  const keyBuffer = Buffer.from(key)

  const decipher = createDecipheriv(algorithm, keyBuffer, initVector)
  const decryptedBuffer = decipher.update(encryptedString, encoding)
  const finalBuffer = decipher.final()
  return Buffer.concat([decryptedBuffer, finalBuffer]).toString()
}

function encryptAes128Ecb (plainText, key) {
  const algorithm = 'aes-128-ecb'
  const initVector = null // ECB doesn't use an init vector
  let plainTextBuffer
  if (!Buffer.isBuffer(plainText)) {
    plainTextBuffer = Buffer.from(plainText)
  } else {
    plainTextBuffer = plainText
  }

  const cipher = createCipheriv(algorithm, key, initVector)
  return Buffer.concat([cipher.update(plainTextBuffer), cipher.final()]).toString("base64")
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

function encryptAes128Cbc (plainText, key, blockSize = 16) {
  const IV = randomBytes(blockSize)
  const plainTextBuffer = Buffer.from(plainText)
  let previousBlock = IV
  const encryptedBlocks = []
  for (let i = 0; i < plainTextBuffer.length; i += blockSize) {
    const block = plainTextBuffer.slice(i, i + blockSize)
    const paddedBlock = pad(block, blockSize)
    const xorBlock = xorTwoBuffers(IV, paddedBlock)
    const encryptedBlock = Buffer.from(encryptAes128Ecb(xorBlock, key))
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
 * @param {base64 encoded String} key 
 * @param {base64 encoded String} IV The initilization vector
 * @param {number} blockSize 
 * @return {String} The decrypted plain text
 */
function decryptAes128Cbc (encrytedText, key, IV, blockSize = 16) {
  const buffer = Buffer.from(encrytedText)
  const IVBuffer = Buffer.from(IV)
  let previousBlock = IVBuffer
  let plainText = ""
  for (let i = 0; i < buffer.length; i += 16) {
    const block = buffer.slice(i, i + 16)
    if (block.length !== 16) {
      console.log('here')
    }
    const decryptedBlock = Buffer.from(decryptAes128Ecb(block, key))
    const xorBlock = xorTwoBuffers(previousBlock, decryptedBlock)
    plainText += xorBlock.toString()
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
