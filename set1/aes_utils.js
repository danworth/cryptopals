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

module.exports = {
  decryptAes128Ecb,
  decryptAes128EcbPipedStreams
}
