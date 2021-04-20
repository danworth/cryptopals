const fs = require('fs')
const readline = require('readline')

const EXPECTED_CHARACTER_FREQUENCY = {
	'a': 0.08167,
	'b': 0.01492,
	'c': 0.02782,
	'd': 0.04253,
	'e': 0.1270,
	'f': 0.02228,
	'g': 0.02015,
	'h': 0.06094,
	'i': 0.06966,
	'j': 0.00153,
	'k': 0.00772,
	'l': 0.04025,
	'm': 0.02406,
	'n': 0.06749,
	'o': 0.07507,
	'p': 0.01929,
	'q': 0.00095,
	'r': 0.05987,
	's': 0.06327,
	't': 0.09056,
	'u': 0.02758,
	'v': 0.00978,
	'w': 0.02360,
	'x': 0.00150,
	'y': 0.01974,
	'z': 0.00074,
}

function xorTwoStrings (hexString1, hexString2) {
  if (hexString1.length !== hexString2.length) {
    throw new Error('both strings must be of equal length')
  }

  const bufferOne = Buffer.from(hexString1, 'hex')
  const bufferTwo = Buffer.from(hexString2, 'hex')

  const numberOfBytes = bufferOne.length
  const resultBuffer = Buffer.alloc(numberOfBytes)
  for (i = 0; i < numberOfBytes; i++) {
    resultBuffer[i] = bufferOne[i] ^ bufferTwo[i]
  }
  return resultBuffer.toString('hex')
}

function singleByteCipherXorEncrypt (plainText, cipher) {
  const buffer = Buffer.from(plainText)
  const encryptedBuffer = Buffer.alloc(buffer.length)
  for (i = 0; i < buffer.length; i++) {
    encryptedBuffer[i] = buffer[i] ^ cipher
  }

  return encryptedBuffer.toString('hex')
}

function singleByteCipherXorDecrypt (hex, cipher) {
  const buffer = Buffer.from(hex, 'hex')
  const decryptedBuffer = Buffer.alloc(buffer.length)
  for (let i = 0; i < buffer.length; i++) {
    decryptedBuffer[i] = buffer[i] ^ cipher
  }

  return decryptedBuffer.toString('utf-8')
}

// credit to https://github.com/Lukasa/cryptopals/blob/master/cryptopals/challenge_one/three.py
function englishness (sentence) {
  const aCodePoint = 'a'.codePointAt(0)
  const characterFrequency = sentence
    .split('')
    .reduce((result, curChar) => {
      if (curChar >= 'a' && curChar <= 'z'){
        result[curChar.codePointAt(0) - aCodePoint] ++
      }
      return result
    }, new Array(26).fill(0))

  let score = 0;
  for (let i = 0; i < characterFrequency.length; i++) {
    score += Math.sqrt(EXPECTED_CHARACTER_FREQUENCY[String.fromCharCode(i + aCodePoint)] * characterFrequency[i] / sentence.length)
  }

  return score
}

function crackSingleByteXorCipher (hexString) {
  const bestSolution = {
    score: 0,
    solution: ''
  }

  for (let i = 0; i < 255; i++) {
    const decryptedResult = singleByteCipherXorDecrypt(hexString, i)
    const decryptedResultScore = englishness(decryptedResult)
    if (decryptedResultScore > bestSolution.score) {
      bestSolution.score = decryptedResultScore
      bestSolution.solution = decryptedResult
    }
  }
  return bestSolution
}

async function detectSingleCharacterXor(fileName) {
  let mostLikelyLine = {
    score: 0,
    solution: ''
  }

  const readFile = readline.createInterface({
    input: fs.createReadStream(fileName),
    console: false
  })

  for await(const line of readFile) {
    const bestAttemptAtDecrypt = crackSingleByteXorCipher(line)
    if (bestAttemptAtDecrypt.score > mostLikelyLine.score) {
      mostLikelyLine = bestAttemptAtDecrypt
    }
  }

  return mostLikelyLine
}

module.exports = {
  xorTwoStrings,
  singleByteCipherXorEncrypt,
  singleByteCipherXorDecrypt,
  crackSingleByteXorCipher,
  detectSingleCharacterXor
}
