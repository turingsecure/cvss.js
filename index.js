const CVSS = require("./lib/cvss.js");
const definitions = require("./lib/cvss_3_0.json");

const vetor = "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:U/RL:T/RC:R"

//adicionar um comentario explicando essa função "((((((((((AV:[NALP]|AC:[LH])|PR:[NLH])|UI:[NR])|S:[UC])|C:[NLW])|I:[NLW])|A:[NLW])|E:[XUPFH])|RL:[XOTWU])|RC:[XURC])"
const expression = definitions.definitions.reduce((accumulator, currentValue, index) => {
    const serializedAbbr = `${currentValue.abbr}:[${currentValue.metrics.reduce((accumulator2, currentValue2) => {
        return accumulator2 + currentValue2.abbr
    }, "")}]`
    if (index !== 0) {
        return `(${accumulator }|${serializedAbbr})`
    } else {
        return serializedAbbr
    }
}, "")

const totalExpressionVector = new RegExp("^CVSS:3\.0(\/" + expression + ")+$")
console.log(totalExpressionVector.test(vetor))




//explicar que a / no começo serve para não confundir com os demais
const allExpressions = definitions.definitions.map(currentValue => {
    return new RegExp(`/${currentValue.abbr}:[${currentValue.metrics.reduce((accumulator2, currentValue2) => {
        return accumulator2 + currentValue2.abbr
    }, "")}]`, "g")
})

console.log(allExpressions)

for(const regex of allExpressions) {
    if((vetor.match(regex) || []).length > 1) {
        console.log("Each parameter can only be passed once")
    }
}





const mandatoryParams = [/AV:[NALP]/g, /AC:[LH]/g, /PR:[NLH]/g, /UI:[NR]/g, /S:[UC]/g, /C:[NLW]/g, /I:[NLW]/g, /A:[NLW]/g]

for (const regex of mandatoryParams) {
    if((vetor.match(regex) || []).length < 1) {
        console.log("Pass all mandatory parameters")
    }
}

//verificar estrutura V
//verificar se não há parametros repetidos V
//verificar se tem todos os parametros obrigatorios V


module.exports = CVSS;
