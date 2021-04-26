const { createDecipheriv } = require('crypto')

async function decryptAes128Ecb (encryptedString, key, encoding = 'base64') {
  const algorithm = 'aes-128-ecb'
  const initVector = null // ECB doesn't use an init vector
  const keyBuffer = Buffer.from(key)

  const decipher = createDecipheriv(algorithm, keyBuffer, initVector)
  const decryptedBuffer = decipher.update(encryptedString, encoding)
  const finalBuffer = decipher.final()
  return Buffer.concat([decryptedBuffer, finalBuffer]).toString()
}

module.exports = {
  decryptAes128Ecb
}
