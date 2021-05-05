const { randomBytes } = require('crypto')
const { pad } = require('./pkcs7')
const { encryptAes128Ecb,
        decryptAes128Ecb,
        encryptAes128Cbc,
        decryptAes128Cbc } = require('../set1/aes_utils')

test('Challenge9: should pad correctly', () => {
  const plainText = Buffer.from("YELLOW SUBMARINE")
  const expectedPaddedText = Buffer.from("YELLOW SUBMARINE\x04\x04\x04\x04")
  expect(pad(plainText, 20)).toStrictEqual(expectedPaddedText)
})

test('Challenge10: AesECB encrypt should work', () => {
  const key = "YELLOW SUBMARINE"
  const plainText = "It is raining outside"
  const encryptedCipherText = encryptAes128Ecb(plainText, key)
  const decryptedText = decryptAes128Ecb(encryptedCipherText, key)
  expect(decryptedText).toBe(plainText)
})

test.only('Challenge10: AES CBC mode should work', () => {
  const key = "YELLOW SUBMARINE"
  const plainText = "It is sunny today and I'm going to Legoland tomorrow"
  const { cipherText, IV } = encryptAes128Cbc(plainText, key) 
  // update these once decryption has been created...
  expect(cipherText).not.toBe(null)
  expect(IV).not.toBe(null)
  const decryptedText = decryptAes128Cbc(cipherText, key, IV)
  expect(decryptedText).toBe(plainText)
})