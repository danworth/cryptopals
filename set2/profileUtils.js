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
 * 
 * @param {Object} userObject Containing 'email', 'uid' and 'role'
 * @returns String representing the object encoded as url parameters
 */
function parseToParams(userObject) {
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

  return parseToParams({
    email: emailAddress,
    uid: 10,
    role: 'user'
  })
}

module.exports = {
  parseParams,
  profileFor
}