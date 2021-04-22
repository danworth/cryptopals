const fs = require('fs')
const readline = require('readline')

const EXPECTED_CHARACTER_FREQUENCY = {
  a: 0.08167,
  b: 0.01492,
  c: 0.02782,
  d: 0.04253,
  e: 0.1270,
  f: 0.02228,
  g: 0.02015,
  h: 0.06094,
  i: 0.06966,
  j: 0.00153,
  k: 0.00772,
  l: 0.04025,
  m: 0.02406,
  n: 0.06749,
  o: 0.07507,
  p: 0.01929,
  q: 0.00095,
  r: 0.05987,
  s: 0.06327,
  t: 0.09056,
  u: 0.02758,
  v: 0.00978,
  w: 0.02360,
  x: 0.00150,
  y: 0.01974,
  z: 0.00074
}

const BIT_SET_TABLE = Buffer.alloc(256)
for (let i = 0; i < 256; i++) {
  BIT_SET_TABLE[i] = (i & 1) + BIT_SET_TABLE[Math.floor(i / 2)]
}

function xorTwoStrings (hexString1, hexString2) {
  if (hexString1.length !== hexString2.length) {
    throw new Error('both strings must be of equal length')
  }

  const bufferOne = Buffer.from(hexString1, 'hex')
  const bufferTwo = Buffer.from(hexString2, 'hex')

  const numberOfBytes = bufferOne.length
  const resultBuffer = Buffer.alloc(numberOfBytes)
  for (let i = 0; i < numberOfBytes; i++) {
    resultBuffer[i] = bufferOne[i] ^ bufferTwo[i]
  }
  return resultBuffer.toString('hex')
}

function singleByteXorEncrypt (plainText, key) {
  const buffer = Buffer.from(plainText)
  const encryptedBuffer = Buffer.alloc(buffer.length)
  for (let i = 0; i < buffer.length; i++) {
    encryptedBuffer[i] = buffer[i] ^ key
  }

  return encryptedBuffer.toString('hex')
}

function singleByteXorDecrypt (hex, key) {
  const buffer = Buffer.from(hex, 'hex')
  const decryptedBuffer = Buffer.alloc(buffer.length)
  for (let i = 0; i < buffer.length; i++) {
    decryptedBuffer[i] = buffer[i] ^ key
  }

  return decryptedBuffer.toString('utf-8')
}

// credit to https://github.com/Lukasa/cryptopals/blob/master/cryptopals/challenge_one/three.py
function englishness (sentence) {
  const aCodePoint = 'a'.codePointAt(0)
  const characterFrequency = sentence
    .split('')
    .reduce((result, curChar) => {
      if (curChar >= 'a' && curChar <= 'z') {
        result[curChar.codePointAt(0) - aCodePoint]++
      }
      return result
    }, new Array(26).fill(0))

  let score = 0
  for (let i = 0; i < characterFrequency.length; i++) {
    score += Math.sqrt(EXPECTED_CHARACTER_FREQUENCY[String.fromCharCode(i + aCodePoint)] * characterFrequency[i] / sentence.length)
  }

  return score
}

function crackSingleByteXor (hexString) {
  const bestSolution = {
    score: 0,
    solution: ''
  }

  for (let i = 0; i < 255; i++) {
    const decryptedResult = singleByteXorDecrypt(hexString, i)
    const decryptedResultScore = englishness(decryptedResult)
    if (decryptedResultScore > bestSolution.score) {
      bestSolution.score = decryptedResultScore
      bestSolution.solution = decryptedResult
    }
  }
  return bestSolution
}

async function detectSingleCharacterXor (fileName) {
  let mostLikelyLine = {
    score: 0,
    solution: ''
  }

  const readFile = readline.createInterface({
    input: fs.createReadStream(fileName),
    console: false
  })

  for await (const line of readFile) {
    const bestAttemptAtDecrypt = crackSingleByteXor(line)
    if (bestAttemptAtDecrypt.score > mostLikelyLine.score) {
      mostLikelyLine = bestAttemptAtDecrypt
    }
  }

  return mostLikelyLine
}

function repeatingKeyXorEncrypt (input, key) {
  const plainTextBuffer = Buffer.from(input)
  const keyBuffer = Buffer.from(key)
  const encryptedBuffer = Buffer.alloc(plainTextBuffer.length)

  for (let i = 0; i < plainTextBuffer.length; i++) {
    encryptedBuffer[i] = plainTextBuffer[i] ^ keyBuffer[i % keyBuffer.length]
  }
  return encryptedBuffer.toString('hex')
}

function editDistance (buffer1, buffer2) {
  let numberOfDifferentBytes = 0
  for (let i = 0; i < buffer1.length; i++) {
    const xorOfBytes = buffer1[i] ^ buffer2[i]
    numberOfDifferentBytes += BIT_SET_TABLE[xorOfBytes]
  }
  return numberOfDifferentBytes
}

function findKeySize (buffer) {
  const results = []

  for (let keySize = 2; keySize < 40; keySize++) {
    if (keySize * 4 > buffer.length) {
      break
    }

    const block1 = buffer.slice(0, keySize)
    const block2 = buffer.slice(keySize, keySize * 2)
    const block3 = buffer.slice(keySize * 2, keySize * 3)
    const block4 = buffer.slice(keySize * 3, keySize * 4)
    const distance1 = editDistance(block1, block2) / keySize
    const distance2 = editDistance(block2, block3) / keySize
    const distance3 = editDistance(block3, block4) / keySize
    const averageDistance = (distance1 + distance2 + distance3) / 3
    results.push({ averageDistance, keySize })
  }

  const sortedResults = results.sort((a, b) => {
    if (a.averageDistance < b.averageDistance) {
      return -1
    }
    return 1
  })
  return sortedResults
}

module.exports = {
  xorTwoStrings,
  singleByteXorEncrypt,
  singleByteXorDecrypt,
  crackSingleByteXor,
  detectSingleCharacterXor,
  repeatingKeyXorEncrypt,
  editDistance,
  findKeySize
}
