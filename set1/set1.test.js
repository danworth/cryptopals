const fs = require('fs').promises
const path = require('path')

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

const { toBase64 } = require('./hexFunctions')

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
  const filePath = path.join(__dirname, 'challenge4_input.txt')
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
  const encryptedFilePath = path.join(__dirname, 'challenge6_input.txt')
  const data = await fs.readFile(encryptedFilePath, 'utf-8')
  const decryptedText = breakRepeatingXor(data.toString(), 'base64')
  expect(decryptedText.split('\n')[0]).toBe("I'm back and I'm ringin' the bell ")
})
