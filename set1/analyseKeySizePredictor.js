const { plot } = require('nodeplotlib')

const {
  repeatingKeyXorEncrypt,
  findKeySize
} = require('./xor.js')

const plainText =
'It is a long established fact that a reader will be distracted by the readable content of a page when looking at its layout. The point of using Lorem Ipsum is that it has a more-or-less normal distribution of letters, as opposed to using \'Content here, content here\', making it look like readable English. Many desktop publishing packages and web page editors now use Lorem Ipsum as their default model text, and a search for \'lorem ipsum\' will uncover many web sites still in their infancy. Various versions have evolved over the years, sometimes by accident, sometimes on purpose (injected humour and the like).'

function createKey (length) {
  const key = Buffer.alloc(length)
  for (let i = 0; i < key.length; i++) {
    key[i] = Math.floor(Math.random() * (126 - 35 + 1) + 35)
  }
  return key.toString()
}

const keySizes = []
const actualPositions = []

for (let keySize = 2; keySize < 40; keySize++) {
  const key = createKey(keySize)
  const encryptedInput = repeatingKeyXorEncrypt(plainText, key)
  const predictedKeySizes = findKeySize(Buffer.from(encryptedInput, 'hex'))
  const indexOfActualKeySize = predictedKeySizes.findIndex((result) => {
    if (result.keySize === keySize) {
      return true
    }
    return false
  })
  keySizes.push(keySize)
  actualPositions.push(indexOfActualKeySize)
}

const results = {
  x: keySizes,
  y: actualPositions,
  type: 'scatter',
}

const layout = {
  yaxis: {title: 'Position of actual key size within predicted key sizes'},
  xaxis: {title: 'Actual key size'}
}

plot([results], layout)
