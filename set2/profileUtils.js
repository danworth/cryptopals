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

module.exports = {
  parseParams
}