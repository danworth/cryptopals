const { createDecipheriv } = require('crypto')
const { Transform } = require('stream')
const { createReadStream } = require('fs')

async function decryptAes128Ecb (encryptedString, key, encoding = 'base64') {
  const algorithm = 'aes-128-ecb'
  const initVector = null // ECB doesn't use an init vector
  const keyBuffer = Buffer.from(key)

  const decipher = createDecipheriv(algorithm, keyBuffer, initVector)
  const decryptedBuffer = decipher.update(encryptedString, encoding)
  const finalBuffer = decipher.final()
  return Buffer.concat([decryptedBuffer, finalBuffer]).toString()
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
  detectAesEcb
}
