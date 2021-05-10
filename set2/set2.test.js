const { pad } = require('./pkcs7')
const {
  encryptAes128Ecb,
  decryptAes128Ecb,
  encryptAes128Cbc,
  decryptAes128Cbc,
  encryptionOracle
} = require('../set1/aes_utils')

test('Challenge9: should pad correctly', () => {
  const plainText = Buffer.from('YELLOW SUBMARINE')
  const expectedPaddedText = Buffer.from('YELLOW SUBMARINE\x04\x04\x04\x04')
  expect(pad(plainText, 20)).toStrictEqual(expectedPaddedText)
})

test('Challenge10: AesECB encrypt should work', () => {
  const keyBuffer = Buffer.from('YELLOW SUBMARINE')
  const plainText = 'It is raining outside'
  const encryptedCipherText = encryptAes128Ecb(Buffer.from(plainText), keyBuffer)
  const decryptedText = decryptAes128Ecb(encryptedCipherText, keyBuffer)
  expect(decryptedText.toString()).toBe(plainText)
})

test('Challenge10: AES CBC mode should work', () => {
  const key = 'YELLOW SUBMARINE'
  const plainText = "It is sunny today and I'm going to Legoland tomorrow"
  const { cipherText, IV } = encryptAes128Cbc(plainText, key)
  // update these once decryption has been created...
  expect(cipherText).not.toBe(null)
  expect(IV).not.toBe(null)
  const decryptedText = decryptAes128Cbc(cipherText.toString('base64'), key, IV.toString('base64'))
  expect(decryptedText).toBe(plainText)
})

test('Challenge 11: encryptionOracle should work', () => {
  const plainText = "Would You Still Have Broken It If I Hadn't Said Anything?"
  const result = encryptionOracle(plainText)
  for (let i = 0; i < 10; i++) {
    expect(result.encryptedBuffer).not.toBe(null)
    expect(['ECB', 'CBC']).toContain(result.encryptionMethod)
  }
})
