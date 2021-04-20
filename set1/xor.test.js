const {
  xorTwoStrings,
  singleByteCipherXorEncrypt,
  singleByteCipherXorDecrypt,
  crackSingleByteXorCipher,
  detectSingleCharacterXor
} = require('./xor.js')

test('xor two hex strings succesfully', () => {
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
  const cipher = 'A'.codePointAt(0)
  expect(singleByteCipherXorEncrypt(plainText, cipher)).toBe('29242d2d2e61362e332d25')
})

test('single byte xor decrypt should work', () => {
  const encryptedHex = '29242d2d2e61362e332d25'
  const cipher = 'A'.codePointAt(0)
  expect(singleByteCipherXorDecrypt(encryptedHex, cipher)).toBe('hello world')
})

test('cracking should work', () => {
  const inputHex = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
  expect(crackSingleByteXorCipher(inputHex).solution).toBe("Cooking MC's like a pound of bacon")
})

test('detect single character xor should work', async () => {
  const result = await detectSingleCharacterXor('/Users/danworth/learning/crypto/set1/challenge4_input.txt')
  expect(result.solution).toBe("Now that the party is jumping\n")
})
