(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-c049293a"],{2366:function(e,t){for(var a=[],r=0;r<256;++r)a[r]=(r+256).toString(16).substr(1);function n(e,t){var r=t||0,n=a;return[n[e[r++]],n[e[r++]],n[e[r++]],n[e[r++]],"-",n[e[r++]],n[e[r++]],"-",n[e[r++]],n[e[r++]],"-",n[e[r++]],n[e[r++]],"-",n[e[r++]],n[e[r++]],n[e[r++]],n[e[r++]],n[e[r++]],n[e[r++]]].join("")}e.exports=n},"504c":function(e,t,a){var r=a("9e1e"),n=a("0d58"),i=a("6821"),o=a("52a7").f;e.exports=function(e){return function(t){var a,s=i(t),u=n(s),c=u.length,l=0,p=[];while(c>l)a=u[l++],r&&!o.call(s,a)||p.push(e?[a,s[a]]:s[a]);return p}}},"63aa":function(e,t,a){e.exports={menuBg:"#304156",menuText:"#bfcbd9",menuActiveText:"#409eff"}},7514:function(e,t,a){"use strict";var r=a("5ca1"),n=a("0a49")(5),i="find",o=!0;i in[]&&Array(1)[i]((function(){o=!1})),r(r.P+r.F*o,"Array",{find:function(e){return n(this,e,arguments.length>1?arguments[1]:void 0)}}),a("9c6c")(i)},"7d98":function(e,t,a){"use strict";a.d(t,"a",(function(){return n}));var r=a("b32d"),n=function(){return Object(r["a"])({url:"/plugins/list",method:"get"})}},b32d:function(e,t,a){"use strict";var r=a("bc3a"),n=a.n(r),i=a("5c96"),o="edd1c9f034335f136f87ad84b625c8f1",s=n.a.create({baseURL:"/apisix/admin/",timeout:5e3,headers:{"X-API-KEY":o}});s.interceptors.request.use((function(e){return e}),(function(e){Promise.reject(e)})),s.interceptors.response.use((function(e){return e.data}),(function(e){return Object(i["Message"])({message:e.response.data.error_msg||e.message,type:"error",duration:5e3}),Promise.reject(e)}));t["a"]=s},c437:function(e,t,a){var r,n,i=a("e1f4"),o=a("2366"),s=0,u=0;function c(e,t,a){var c=t&&a||0,l=t||[];e=e||{};var p=e.node||r,d=void 0!==e.clockseq?e.clockseq:n;if(null==p||null==d){var f=i();null==p&&(p=r=[1|f[0],f[1],f[2],f[3],f[4],f[5]]),null==d&&(d=n=16383&(f[6]<<8|f[7]))}var h=void 0!==e.msecs?e.msecs:(new Date).getTime(),m=void 0!==e.nsecs?e.nsecs:u+1,b=h-s+(m-u)/1e4;if(b<0&&void 0===e.clockseq&&(d=d+1&16383),(b<0||h>s)&&void 0===e.nsecs&&(m=0),m>=1e4)throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");s=h,u=m,n=d,h+=122192928e5;var y=(1e4*(268435455&h)+m)%4294967296;l[c++]=y>>>24&255,l[c++]=y>>>16&255,l[c++]=y>>>8&255,l[c++]=255&y;var v=h/4294967296*1e4&268435455;l[c++]=v>>>8&255,l[c++]=255&v,l[c++]=v>>>24&15|16,l[c++]=v>>>16&255,l[c++]=d>>>8|128,l[c++]=255&d;for(var g=0;g<6;++g)l[c+g]=p[g];return t||o(l)}e.exports=c},c8f9:function(e,t,a){"use strict";var r=function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("div",{staticClass:"plugin-dialog"},[a("el-dialog",{attrs:{title:"Plugin "+e.name+" Edit",visible:e.showDialog},on:{"update:visible":function(t){e.showDialog=t}}},[e.schema.oneOf?a("el-form",{ref:"form",staticClass:"oneof-plugin-wrapper",attrs:{model:e.data,rules:e.rules,"show-message":!1}},[a("el-form-item",{attrs:{label:"Option",rules:{required:!0,trigger:"blur"}}},[a("el-radio-group",{on:{change:e.handleOneOfChange},model:{value:e.data["radioKey"],callback:function(t){e.$set(e.data,"radioKey",t)},expression:"data['radioKey']"}},e._l(e.schema.properties,(function(t,r){return a("el-radio",{key:r,attrs:{label:r}},[e._v("\n            "+e._s(r)+"\n          ")])})),1)],1),e._l(e.data.values,(function(t,r){return a("el-form-item",{key:r,attrs:{label:"Value"+(r+1),rules:{required:!0,trigger:"blur"}}},[a("el-input",{model:{value:e.data["values"][r],callback:function(t){e.$set(e.data["values"],r,t)},expression:"data['values'][index]"}}),1!==e.data.values.length?a("el-button",{staticClass:"remove-value-btn",attrs:{type:"danger"},on:{click:function(t){return t.preventDefault(),e.removeOneOfPropValue(r)}}},[e._v("\n          Remove\n        ")]):e._e()],1)})),a("el-form-item",[a("el-button",{attrs:{disabled:e.oneOfPropHasEmptyValue},on:{click:e.addValueInput}},[e._v("\n          "+e._s(e.$t("button.addValue"))+"\n        ")])],1)],2):e._e(),e.schema.oneOf?e._e():a("el-form",{ref:"form",attrs:{model:e.data,rules:e.rules,"show-message":!1}},e._l(e.schema.properties,(function(t,r){return a("el-form-item",{key:r,attrs:{label:r,"label-width":"160px",prop:r}},["integer"===e.schema.properties[r].type||"number"===e.schema.properties[r].type?a("el-input-number",{attrs:{min:e.schema.properties[r].minimum||-99999999999,max:e.schema.properties[r].maximum||99999999999,label:"描述文字"},on:{change:function(t){return e.onPropertyChange(r,t)}},model:{value:e.data[r],callback:function(t){e.$set(e.data,r,t)},expression:"data[key]"}}):e._e(),e.schema.properties[r].hasOwnProperty("enum")?a("el-select",{attrs:{clearable:!0,placeholder:"Select a "+r},on:{change:function(t){return e.onPropertyChange(r,t)}},model:{value:e.data[r],callback:function(t){e.$set(e.data,r,t)},expression:"data[key]"}},e._l(e.schema.properties[r]["enum"],(function(e){return a("el-option",{key:e,attrs:{label:e,value:e}})})),1):e._e(),"string"!==e.schema.properties[r].type||e.schema.properties[r].hasOwnProperty("enum")?e._e():a("el-input",{attrs:{placeholder:r},on:{input:function(t){return e.onPropertyChange(r,t)}},model:{value:e.data[r],callback:function(t){e.$set(e.data,r,t)},expression:"data[key]"}}),"boolean"!==e.schema.properties[r].type||e.schema.properties[r].hasOwnProperty("enum")?e._e():a("el-switch",{attrs:{"active-color":"#13ce66","inactive-color":"#ff4949"},model:{value:e.data[r],callback:function(t){e.$set(e.data,r,t)},expression:"data[key]"}}),"array"===e.schema.properties[r].type?a("div",{staticClass:"array-input-container"},[e._l(e.arrayPropertiesLength[r],(function(t){return a("el-input",{key:t,attrs:{placeholder:r+" ["+t+"]"},on:{input:function(t){e.isDataChanged=!0}},model:{value:e.data[r][t],callback:function(a){e.$set(e.data[r],t,a)},expression:"data[key][arrayIndex]"}})})),a("el-button",{on:{click:function(t){return e.addArrayItem(r)}}},[e._v("\n            "+e._s(e.$t("button.addValue"))+"\n          ")])],2):e._e(),"object"===e.schema.properties[r].type?a("div",{staticClass:"object-input-container"},[e._l(e.objectPropertiesArray[r],(function(t,n){return a("div",{key:n,staticClass:"object-input-item"},[a("el-input",{attrs:{placeholder:r+" [key "+n+"]"},on:{input:function(t){return e.onObjectPropertyChange(r,t,!0)}},model:{value:e.objectPropertiesArray[r][n].key,callback:function(t){e.$set(e.objectPropertiesArray[r][n],"key",t)},expression:"objectPropertiesArray[key][objectIndex].key"}}),a("el-input",{attrs:{placeholder:r+" [value "+n+"]"},on:{input:function(t){return e.onObjectPropertyChange(r,t,!1)}},model:{value:e.objectPropertiesArray[r][n].value,callback:function(t){e.$set(e.objectPropertiesArray[r][n],"value",t)},expression:"objectPropertiesArray[key][objectIndex].value"}}),a("el-button",{on:{click:function(t){return e.deleteObjectItem(r,n)}}},[e._v("\n              "+e._s(e.$t("button.delete"))+"\n            ")])],1)})),a("el-button",{on:{click:function(t){return e.addObjectItem(r)}}},[e._v("\n            "+e._s(e.$t("button.addValue"))+"\n          ")])],2):e._e()],1)})),1),a("span",{staticClass:"dialog-footer",attrs:{slot:"footer"},slot:"footer"},[a("el-button",{on:{click:e.onCancel}},[e._v("\n        "+e._s(e.$t("button.cancel"))+"\n      ")]),a("el-button",{attrs:{type:"primary",disabled:!e.isDataChanged&&e.oneOfPropHasEmptyValue},on:{click:e.onSave}},[e._v("\n        "+e._s(e.$t("button.confirm"))+"\n      ")])],1)],1)],1)},n=[],i=(a("8e6e"),a("7514"),a("7618")),o=a("75fc"),s=(a("ac6a"),a("456d"),a("6762"),a("2fdb"),a("bd86")),u=(a("96cf"),a("3b8d")),c=(a("7f7f"),a("d225")),l=a("b0b4"),p=a("308d"),d=a("6bb5"),f=a("4e2b"),h=a("9ab4"),m=a("60a3"),b=a("b32d"),y=function(e){return Object(b["a"])({url:"/schema/plugins/".concat(e),method:"get"})};function v(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,r)}return a}function g(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?v(Object(a),!0).forEach((function(t){Object(s["a"])(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):v(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}var O=a("c437"),k=function(e){function t(){var e;return Object(c["a"])(this,t),e=Object(p["a"])(this,Object(d["a"])(t).apply(this,arguments)),e.schema={properties:{}},e.rules={},e.data={},e.isDataChanged=!1,e.showDialog=!1,e.arrayPropertiesLength={},e.objectPropertiesArray={},e}return Object(f["a"])(t,e),Object(l["a"])(t,[{key:"onShowChange",value:function(e){this.resetPlugin(),e&&this.getschema(this.name),this.showDialog=e}},{key:"resetPlugin",value:function(){this.schema={properties:{}},this.rules={},this.data={},this.isDataChanged=!1}},{key:"getschema",value:function(){var e=Object(u["a"])(regeneratorRuntime.mark((function e(t){var a,r,n,i,s,u,c,l,p,d=this;return regeneratorRuntime.wrap((function(e){while(1)switch(e.prev=e.next){case 0:return e.next=2,y(t);case 2:if(a=e.sent,a.properties){e.next=6;break}return this.isDataChanged=!0,e.abrupt("return");case 6:for(n in this.schema=Object.assign({},g({},a,{name:this.name})),r=Object.assign({},a.properties),r)i=Object.assign({},r[n]),r[n]={trigger:"blur"},a.required&&(r[n].required=a.required.includes(n)),i.hasOwnProperty("type")&&(r[n]["type"]=i["type"]),i.hasOwnProperty("minimum")&&(r[n]["min"]=i["minimum"]),i.hasOwnProperty("maximum")&&(r[n]["max"]=i["maximum"]),i.hasOwnProperty("enum")&&(r[n]["type"]="enum",r[n]["enum"]=i["enum"]);this.rules=r,s={},u=function(e){if(a.properties[e].default)return s[e]=a.properties[e].default,"continue";switch(a.properties[e].type){case"array":s[e]=[],d.arrayPropertiesLength[e]=Object(o["a"])(new Array(d.pluginData[e]?d.pluginData[e].length:a.properties[e].minItems).keys());break;case"object":s[e]={},d.objectPropertiesArray[e]=[],d.pluginData[e]&&Object.keys(d.pluginData[e]).map((function(t){d.objectPropertiesArray[e].push({key:t,value:d.pluginData[e][t]})}));break;case"boolean":s[e]=!1;break;default:s[e]=""}},e.t0=regeneratorRuntime.keys(a.properties);case 13:if((e.t1=e.t0()).done){e.next=20;break}if(c=e.t1.value,l=u(c),"continue"!==l){e.next=18;break}return e.abrupt("continue",13);case 18:e.next=13;break;case 20:this.pluginData?this.data=Object.assign(s,this.pluginData):this.data=s,"key-auth"!==this.name||this.pluginData||(this.data={key:O()},this.isDataChanged=!0),"ip-restriction"===this.name&&this.pluginData&&(p=Object.keys(this.pluginData)[0],this.$nextTick((function(){d.data={radioKey:p,values:d.pluginData[p]}}))),this.schema.oneOf&&(this.data={radioKey:Object.keys(this.schema.properties)[0],values:[""]});case 24:case"end":return e.stop()}}),e,this)})));function t(t){return e.apply(this,arguments)}return t}()},{key:"onCancel",value:function(){this.$emit("hidePlugin")}},{key:"onSave",value:function(){var e=this;this.$refs.form.validate((function(t){if(!t)return!1;e.data=Object.assign({},e.data,e.reorganizeObjectProperty()),e.data=e.processOneOfProp(e.data),e.$emit("save",e.name,e.data),e.$message.warning("".concat(e.$t("message.clickSaveButton")))}))}},{key:"addArrayItem",value:function(e){this.arrayPropertiesLength[e].length<this.schema.properties[e].maxItems?(this.arrayPropertiesLength[e].push(this.arrayPropertiesLength[e].length),this.$forceUpdate()):this.$message.warning("".concat(this.$t("message.cannotAddMoreItems")))}},{key:"addObjectItem",value:function(e){this.objectPropertiesArray[e].push({key:"",value:""}),this.isDataChanged=!0,this.$forceUpdate()}},{key:"deleteObjectItem",value:function(e,t){this.objectPropertiesArray[e].splice(t,1),this.isDataChanged=!0,this.$forceUpdate()}},{key:"reorganizeObjectProperty",value:function(){var e=this,t={},a=function(a){var r={};e.objectPropertiesArray[a].map((function(e){r[e.key]=e.value})),t[a]=r};for(var r in this.objectPropertiesArray)a(r);return t}},{key:"onObjectPropertyChange",value:function(){this.isDataChanged=!0,this.$forceUpdate()}},{key:"onPropertyChange",value:function(e,t){this.data[e]=t,this.isDataChanged=!0}},{key:"handleOneOfChange",value:function(e){this.data.values=[""]}},{key:"addValueInput",value:function(){this.data.values=this.data.values.concat([""])}},{key:"removeOneOfPropValue",value:function(e){this.data.values=this.data.values.filter((function(t,a){return e!==a}))}},{key:"processOneOfProp",value:function(e){if(!this.schema.oneOf){for(var t in e)""===e[t]&&delete e[t],"object"===Object(i["a"])(e[t])&&0===Object.keys(e[t]).length&&delete e[t];return e}return Object(s["a"])({},this.data.radioKey,this.data.values)}},{key:"oneOfPropHasEmptyValue",get:function(){return!this.data.values||this.data.values.find((function(e){return""===e}))}}]),t}(m["c"]);h["a"]([Object(m["b"])({default:!1})],k.prototype,"show",void 0),h["a"]([Object(m["b"])({default:""})],k.prototype,"name",void 0),h["a"]([Object(m["b"])({default:null})],k.prototype,"pluginData",void 0),h["a"]([Object(m["d"])("show")],k.prototype,"onShowChange",null),k=h["a"]([Object(m["a"])({name:"PluginDialog"})],k);var j=k,P=j,w=(a("f02e"),a("2877")),x=Object(w["a"])(P,r,n,!1,null,null,null);t["a"]=x.exports},e1f4:function(e,t){var a="undefined"!=typeof crypto&&crypto.getRandomValues&&crypto.getRandomValues.bind(crypto)||"undefined"!=typeof msCrypto&&"function"==typeof window.msCrypto.getRandomValues&&msCrypto.getRandomValues.bind(msCrypto);if(a){var r=new Uint8Array(16);e.exports=function(){return a(r),r}}else{var n=new Array(16);e.exports=function(){for(var e,t=0;t<16;t++)0===(3&t)&&(e=4294967296*Math.random()),n[t]=e>>>((3&t)<<3)&255;return n}}},f02e:function(e,t,a){"use strict";var r=a("63aa"),n=a.n(r);n.a},ffc1:function(e,t,a){var r=a("5ca1"),n=a("504c")(!0);r(r.S,"Object",{entries:function(e){return n(e)}})}}]);