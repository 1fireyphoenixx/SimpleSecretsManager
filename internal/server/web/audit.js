'use strict';
const $=id=>document.getElementById(id);
let generation=0;
function clearAudit(message){generation++;$('audit-rows').replaceChildren();$('audit-json').textContent='';$('audit-message').textContent=message;}
async function loadAudit(){
 const request=++generation;$('reload-audit').disabled=true;$('audit-message').textContent='Loading audit records…';
 try{
  const response=await fetch('/api/v1/admin/audit',{credentials:'same-origin',cache:'no-store'});
  if(!response.ok)throw new Error(response.status===401?'Your session has expired. Sign in through Open manager.':'Could not load audit records.');
  const records=await response.json();if(request!==generation)return;
  records.sort((a,b)=>b.timestamp.localeCompare(a.timestamp));
  $('audit-rows').replaceChildren(...records.map(record=>{
   const row=document.createElement('tr');
   for(const value of [new Date(record.timestamp).toLocaleString(),record.identity,record.operation,record.path||'—',record.success?'Succeeded':'Failed',record.source]){const cell=document.createElement('td');cell.textContent=value;row.append(cell);}
   return row;
  }));
  $('audit-json').textContent=JSON.stringify(records,null,2);$('audit-message').textContent=records.length+' audit records';
 }catch(e){if(request===generation)clearAudit(e.message);}
 finally{$('reload-audit').disabled=false;}
}
$('reload-audit').onclick=loadAudit;
// Erase retained audit output when the administrator session expires or is
// revoked in another window; never pass tokens or sessions through window URLs.
setInterval(async()=>{try{const r=await fetch('/api/v1/admin/session',{credentials:'same-origin',cache:'no-store'});if(!r.ok)clearAudit('Session unavailable. Sign in through Open manager.');}catch{clearAudit('Server unavailable. Refresh when reconnected.');}},15000);
loadAudit();
