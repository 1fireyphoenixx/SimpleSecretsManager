// Pure metadata projection shared by the UI and its unit tests. Folder prefixes
// include the slash boundary: a/ never accidentally includes ab/secret.
(function(root){
 'use strict';
 function entries(secrets,prefix='',filter=''){
  const folders=new Map(),files=[];
  for(const secret of secrets){
   if(!secret.path.startsWith(prefix))continue;
   const relative=secret.path.slice(prefix.length),slash=relative.indexOf('/');
   if(slash>=0){const name=relative.slice(0,slash);folders.set(name,{name,path:prefix+name+'/',folder:true});}
   else if(relative)files.push({name:relative,path:secret.path,folder:false,secret});
  }
  const query=filter.toLocaleLowerCase();
  return [...folders.values(),...files].filter(e=>e.name.toLocaleLowerCase().includes(query)).sort((a,b)=>Number(b.folder)-Number(a.folder)||a.name.localeCompare(b.name));
 }
 root.SSMBrowse={entries};
 if(typeof module!=='undefined')module.exports={entries};
})(globalThis);
