const fsPromises = require('fs').promises
const fs = require('fs')
const path = require('path')
const readline = require('readline')

const {
  xorTwoStrings,
  singleByteXorEncrypt,
  singleByteXorDecrypt,
  crackSingleByteXor,
  findSingleCharacterXorLine,
  repeatingKeyXorEncrypt,
  repeatingKeyXorDecrypt,
  editDistance,
  breakRepeatingXor
} = require('./xor_utils.js')

const {
  decryptAes128Ecb,
  decryptAes128EcbStreamed,
  detectAesEcb
} = require('./aes_utils')

const { toBase64 } = require('./hex_utils.js')

test('Challenge 1: Convert hex to base64', () => {
  const hexString = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
  const expectedBase64 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
  expect(toBase64(hexString)).toBe(expectedBase64)
})

test('Challenge 2: Fixed XOR', () => {
  const hexString1 = '1c0111001f010100061a024b53535009181c'
  const hexString2 = '686974207468652062756c6c277320657965'
  const expectedResult = '746865206b696420646f6e277420706c6179'
  expect(xorTwoStrings(hexString1, hexString2)).toBe(expectedResult)
})

test('xor should throw exception if strings differ in length', () => {
  expect(() => {
    xorTwoStrings('123', '4')
  }).toThrow()
})

test('single byte xor encrypt should work', () => {
  const plainText = 'hello world'
  const key = 'A'.codePointAt(0)
  expect(singleByteXorEncrypt(plainText, key)).toBe('29242d2d2e61362e332d25')
})

test('single-byte XOR decrypt should work', () => {
  const encryptedHex = '29242d2d2e61362e332d25'
  const key = 'A'.codePointAt(0)
  expect(singleByteXorDecrypt(encryptedHex, key)).toBe('hello world')
})

test('Challenge 3: single-byte XOR', () => {
  const inputHex = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
  expect(crackSingleByteXor(inputHex).decryptedText).toBe("Cooking MC's like a pound of bacon")
})

test('Challenge 4: detect single-character XOR', async () => {
  const filePath = path.join(__dirname, 'resources/challenge4_input.txt')
  const result = await findSingleCharacterXorLine(filePath)
  expect(result).toBe('Now that the party is jumping\n')
})

test('Challenge 5: implement repeating key xor encryption', () => {
  const inputText =
`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

  const expectedEncryptedValue = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
  expect(repeatingKeyXorEncrypt(inputText, 'ICE')).toBe(expectedEncryptedValue)
})

test('Challenge 5: implement repeating key xor decryption', () => {
  const expectedDecryptedText =
`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
  const encryptedValue = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
  const key = 'ICE'

  expect(repeatingKeyXorDecrypt(Buffer.from(encryptedValue, 'hex'), key)).toBe(expectedDecryptedText)
})

test('Challenge 6: find the correct edit distance', () => {
  const string1 = 'this is a test'
  const string2 = 'wokka wokka!!!'
  expect(editDistance(Buffer.from(string1), Buffer.from(string2))).toBe(37)
})

test('Challenge 6: break repeating xor', () => {
  const key = 'ABCDEFGHIJ'
  const plainText =
  'It is a long established fact that a reader will be distracted by the readable content of a page when looking at its layout. The point of using Lorem Ipsum is that it has a more-or-less normal distribution of letters, as opposed to using \'Content here, content here\', making it look like readable English. Many desktop publishing packages and web page editors now use Lorem Ipsum as their default model text, and a search for \'lorem ipsum\' will uncover many web sites still in their infancy. Various versions have evolved over the years, sometimes by accident, sometimes on purpose (injected humour and the like).'
  const encodedString = repeatingKeyXorEncrypt(plainText, key)
  const decryptedText = breakRepeatingXor(encodedString)
  expect(decryptedText).toBe(plainText)
})

test('Challenge 6: decrypt file', async () => {
  const encryptedFilePath = path.join(__dirname, 'resources/challenge6_input.txt')
  const data = await fsPromises.readFile(encryptedFilePath, 'utf-8')
  const decryptedText = breakRepeatingXor(data.toString(), 'base64')
  expect(decryptedText.split('\n')[0]).toBe("I'm back and I'm ringin' the bell ")
})

test('Challenge 7: decrypt aes 128-ecb', async () => {
  const encryptedFilePath = path.join(__dirname, 'resources/challenge7_input.txt')
  const data = await fsPromises.readFile(encryptedFilePath, 'utf-8')
  const decrypted = decryptAes128Ecb(data, 'YELLOW SUBMARINE')
  expect(decrypted.split('\n')[0]).toBe("I'm back and I'm ringin' the bell ")
})

test('Challenge 7: decrypt aes 128-ecb with streams', async () => {
  const encryptedFilePath = path.join(__dirname, 'resources/challenge7_input.txt')
  const decrypted = await decryptAes128EcbStreamed(encryptedFilePath, 'YELLOW SUBMARINE')
  expect(decrypted.split('\n')[0]).toBe("I'm back and I'm ringin' the bell ")
})

test('Challenge 8: detect aes ecb encrypted line', async () => {
  const encryptedFilePath = path.join(__dirname, 'resources/challenge8_input.txt')
  const encryptedFile = readline.createInterface({
    input: fs.createReadStream(encryptedFilePath),
    console: false
  })

  const aesEcbEncryptedLines = []
  for await (const line of encryptedFile) {
    const aesEcbEncryptedLine = detectAesEcb(Buffer.from(line, 'hex'))
    if (aesEcbEncryptedLine) {
      aesEcbEncryptedLines.push(aesEcbEncryptedLine)
    }
  }

  const expectedEncryptedLine = 'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'
  expect(aesEcbEncryptedLines.length).toBe(1)
  expect(aesEcbEncryptedLines[0]).toBe(expectedEncryptedLine)
})
