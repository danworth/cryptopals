const { encryptAes128Ecb, decryptAes128Ecb } = require('../set1/aes_utils')
const RANDOM_AES_KEY = Buffer.from('YELLOW SUBMARINE')

/**
 * Parse a url param like string of keys and values into an object.
 * 
 * @param {String} params A url param like String of k=v, e.g. foo=bar&baz=quiz
 * @returns {} An object representing the keys and values for each parameter
 */
function parseParams(params) {
  return params.split('&').reduce((result, keyValuePair) => {
    const [ key, value ] = keyValuePair.split('=')
    result[key] = value
    return result
  }, {})
}

/**
 * Encodes a user profile object to url like parameter string
 * 
 * @param {Object} userObject Containing 'email', 'uid' and 'role'
 * @returns String representing the object encoded as url parameters
 */
function encodeUserProfile(userObject) {
  const params = Object.keys(userObject).reduce((result, key) => {
    result += `${key}=${userObject[key]}&`
    return result
  }, "")
  return params.replace(/&$/, '')
}

/**
 * Takes a user's email address and returns a new profile with a random
 * uid and role of 'user'. The result is encoded as url parameters.
 * 
 * @param {String} emailAddress 
 * @returns {}
 */
function profileFor(emailAddress) {
  if (emailAddress.match(/[&=]/)) {
    throw new Error('Email address must not container & or =')
  }

  return encodeUserProfile({
    email: emailAddress,
    uid: 10,
    role: 'user'
  })
}

/**
 * Encrypts the encoded user profile using aes-128-ecb with a random key
 * 
 * @param {String} encodedParams A user profile encoded into url param like
 * string
 * @returns Buffer encrypted user profile
 */
function encryptEncodedParams(encodedParams) {
  return encryptAes128Ecb(Buffer.from(encodedParams), RANDOM_AES_KEY)
}

/**
 * Decrypts an encoded userProfile which has been encrypted with aes-128-ecb
 * and returns it parsed into an object.
 * 
 * @param {Buffer} encryptedProfileBuffer 
 * @returns Object representing user profile
 */
function decryptEncodedParams(encryptedProfileBuffer) {
  const decryptedProfile = decryptAes128Ecb(encryptedProfileBuffer, RANDOM_AES_KEY)
  return parseParams(decryptedProfile.toString())
}

/**
 * 
 * @param {String} emailAddress 
 * @returns A valid encoded user profile with the role of Admin which
 * has been encrypted. The value can be used with decryptEncodedParams which
 * will return the user profile with a role of Admin
 */
function createAdminRole(emailAddress) {
  return ""
}

module.exports = {
  parseParams,
  profileFor,
  encryptEncodedParams,
  decryptEncodedParams
}