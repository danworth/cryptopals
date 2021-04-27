const { createDecipheriv } = require('crypto')
const { createReadStream } = require('fs')
const { Writable } = require('stream')

async function decryptAes128Ecb (encryptedString, key, encoding = 'base64') {
  const algorithm = 'aes-128-ecb'
  const initVector = null // ECB doesn't use an init vector
  const keyBuffer = Buffer.from(key)

  const decipher = createDecipheriv(algorithm, keyBuffer, initVector)
  const decryptedBuffer = decipher.update(encryptedString, encoding)
  const finalBuffer = decipher.final()
  return Buffer.concat([decryptedBuffer, finalBuffer]).toString()
}

async function decryptAes128EcbPipedStreams (filePath, key, encoding = 'base64') {
  const encryptedStream = createReadStream(filePath, { encoding })
  const decryptedStream = new Writable()
  
  const algorithm = 'aes-128-ecb'
  const initVector = null // ECB doesn't use an init vector
  const keyBuffer = Buffer.from(key)
  const decipher = createDecipheriv(algorithm, keyBuffer, initVector)

  encryptedStream.pipe(decipher).pipe(decryptedStream)
  const decryptedArray = []

  decryptedStream._write = (chunk, enc, next) => {
    decryptedArray.push(chunk)
    next()
  }
  await decryptedStream

  return Buffer.from(decryptedArray).toString()
}

function detectAesEcb(buffer) {
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
  decryptAes128EcbPipedStreams,
  detectAesEcb
}
