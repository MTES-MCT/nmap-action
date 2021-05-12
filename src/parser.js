const xml2js = require('xml2js');
const fs = require('fs');

const transform = (json) => {
  return json;
};

/**
 * Returns json nmap results from xml file
 *
 * @param {string} path The xml file path
 *
 * @returns {Promise<string>}
 */
const parse = (path) => {
  console.warn(`Parse xml results from file ${path + '/report.xml'}`);
  const parser = new xml2js.Parser();
  const xmlData = fs.readFileSync(path + '/report.xml');
  return parser.parseStringPromise(xmlData).then(transform);
};

module.exports = parse;