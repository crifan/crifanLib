/*
 * Javascript string realted functions
 * 
 * Crifan Li
 * Updated: 2017/09/28
 * 
 */

// extract single sub string from full string
// eg: extract '012345678912345' from 'www.ucows.cn/qr?id=012345678912345'
export function  extractSingleStr(curStr, pattern, flags='i') {
  let extractedStr = null;

  let rePattern = new RegExp(pattern, flags);
  console.log(rePattern);

  let matches = rePattern.exec(curStr);
  console.log(matches);

  if (matches) {
    extractedStr = matches[0];
    console.log(extractedStr);
  }

  if (extractedStr === null) {
    extractedStr = "";
  }

  console.log(`curStr=${curStr}, pattern=${pattern}, flags=${flags} -> extractedStr=${extractedStr}`);

  return extractedStr;
}
