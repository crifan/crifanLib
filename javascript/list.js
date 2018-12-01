/*
 * Javascript List related functions
 * 
 * Author: Crifan Li
 * Updated: 20181201
 * 
 */


function removeListItem(originList, itemInList) {
    // console.log("removeListItem: originList=%o, itemInList=%o", originList, itemInList)
    var foundIndex = originList.indexOf(itemInList)
    // console.log("foundIndex=%s", foundIndex)
    if (foundIndex >= 0){
      originList.splice(foundIndex, 1)
    }
    // console.log("originList=%o", originList)
    return originList
}
