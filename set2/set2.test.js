const { pad } = require('./pkcs7')
const { encryptAes128Ecb,
        decryptAes128Ecb } = require('../set1/aes_utils')

test('Challenge9: should pad correctly', () => {
  const plainText = "YELLOW SUBMARINE"
  const expectedPaddedText = "YELLOW SUBMARINE\x04\x04\x04\x04"
  expect(pad(plainText, 20)).toBe(expectedPaddedText)
})

test('Challenge10: AesECB encrypt should work', () => {
  const key = "YELLOW SUBMARINE"
  const plainText = "It is raining outside"
  const encryptedCipherText = encryptAes128Ecb(plainText, key)
  const decryptedText = decryptAes128Ecb(encryptedCipherText, key)
  expect(decryptedText).toBe(plainText)
})