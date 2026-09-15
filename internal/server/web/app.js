// Every server value is inserted as text, never as HTML. Browsing calls only the
// metadata listing endpoint; values are fetched exclusively by Reveal / Copy.
'use strict';
let csrf = '';
let secretMetadata = [];
let currentFolder = '';
let editorMethod = 'POST';
let editorGeneration = 0;
let authGeneration = 0;
const $ = id => document.getElementById(id);
const message = text => { $('message').textContent = text; };
async function api(path, method = 'GET', body) {
  const response = await fetch('/api/v1/' + path, {method, credentials:'same-origin', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf}, body:body === undefined ? undefined : JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) { if (response.status === 401) signedOut(); throw new Error(data.error || 'Request failed'); }
  return data;
}
function signedOut(){authGeneration++;secretMetadata=[];currentFolder='';$('secret-list').replaceChildren();$('secret-editor').close();clearEditor();csrf='';$('dashboard').hidden=true;$('login').hidden=false;$('logout').hidden=true;$('status').textContent='Authentication required';$('new-token').textContent='';$('new-write-token').textContent='';$('revealed-value').textContent='';$('reveal').close();}
async function status(){const data=await api('admin/status');$('status').textContent=data.locked?'● LOCKED':'● UNLOCKED';}
async function signedIn(session){csrf=session.csrf;$('dashboard').hidden=false;$('login').hidden=true;$('logout').hidden=false;await refresh();}
function action(label, fn){const b=document.createElement('button');b.textContent=label;b.onclick=()=>Promise.resolve().then(fn).catch(e=>message(e.message));return b;}
function table(target, headers, rows){const t=document.createElement('table');const head=t.createTHead().insertRow();headers.forEach(x=>{const th=document.createElement('th');th.textContent=x;head.append(th);});const body=t.createTBody();rows.forEach(row=>{const tr=body.insertRow();row.forEach(value=>{const td=tr.insertCell();if(Array.isArray(value))value.forEach(b=>td.append(b));else td.textContent=String(value);});});$(target).replaceChildren(t);}
const encoded = path => path.split('/').map(encodeURIComponent).join('/');
async function refresh(){const generation=authGeneration;await status();const [secrets,agents,enrollments,admins,writers]=await Promise.all(['secrets','agents','enrollment','administrators','write-credentials'].map(p=>api('admin/'+p)));
 if(!csrf || generation!==authGeneration)return;
 secretMetadata=secrets;renderFolder();
 table('agent-list',['Name / ID','Paths','State','Actions'],agents.map(a=>[a.name+' / '+a.id,(a.paths||[]).join('\n'),a.revoked?'Revoked':'Active',[action('Edit permissions',async()=>{const paths=prompt('Allowed paths, one per line',(a.paths||[]).join('\n'));if(paths!==null){await api('admin/agents/'+a.id,'PUT',{paths:paths.split('\n').map(s=>s.trim()).filter(Boolean)});await refresh();}}),action('Revoke',async()=>{if(confirm('Revoke '+a.name+'?')){await api('admin/agents/'+a.id,'DELETE');await refresh();}})]]));
 $('enrollment-agent').replaceChildren(...agents.filter(a=>!a.revoked).map(a=>{const o=document.createElement('option');o.value=a.id;o.textContent=a.name+' / '+a.id;return o;}));
 table('enrollment-list',['ID','Agent','Expires','Used','Actions'],enrollments.map(e=>[e.id,e.agent_id,e.expires_at,e.used,[action('Delete token',async()=>{await api('admin/enrollment/'+e.id,'DELETE');await refresh();})]]));
 // Names and paths are untrusted server data; table() always inserts text.
 table('writer-list',['Name / ID','Paths','Creation','State','Actions'],writers.map(c=>[c.name+' / '+c.id,(c.paths||[]).join('\n'),c.allow_create?'Allowed':'Not allowed',c.revoked?'Revoked':'Active',c.revoked?[]:[action('Edit paths',async()=>{const paths=prompt('Paths to update, one per line',(c.paths||[]).join('\n'));if(paths!==null){await api('admin/write-credentials/'+c.id,'PUT',{paths:paths.split('\n').map(s=>s.trim()).filter(Boolean)});await refresh();}}),action(c.allow_create?'Disable creation':'Allow creation',async()=>{await api('admin/write-credentials/'+c.id,'PUT',{allow_create:!c.allow_create});await refresh();}),action('Revoke',async()=>{if(confirm('Revoke '+c.name+'?')){await api('admin/write-credentials/'+c.id,'DELETE');$('new-write-token').textContent='';await refresh();}})]]));
 table('admin-list',['Administrator','Actions'],admins.map(name=>[name,[action('Delete',async()=>{if(confirm('Delete administrator '+name+'?')){await api('admin/administrators/'+encodeURIComponent(name),'DELETE');await refresh();}})]]));
}
function form(id, fn){$(id).onsubmit=async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(e.target));try{await fn(data);e.target.reset();message('Saved.');}catch(e){message(e.message);}finally{e.target.querySelectorAll('input[type=password],textarea[name=value]').forEach(x=>x.value='');}};}
form('login-form',async d=>signedIn(await api('login','POST',d)));

form('agent-form',async d=>{await api('admin/agents','POST',{name:d.name,paths:d.paths.split('\n').map(s=>s.trim()).filter(Boolean)});await refresh();});
form('enrollment-form',async d=>{const v=await api('admin/enrollment','POST',{agent_id:d.agent_id,ttl_seconds:Number(d.ttl_seconds)});$('new-token').textContent=v.token;await refresh();});
form('writer-form',async d=>{const v=await api('admin/write-credentials','POST',{name:d.name,allow_create:d.allow_create==='on',paths:d.paths.split('\n').map(s=>s.trim()).filter(Boolean)});$('new-write-token').textContent=v.token;await refresh();});
$('hide-write-token').onclick=()=>{$('new-write-token').textContent='';};
$('copy-write-token').onclick=async()=>{try{const token=$('new-write-token').textContent;if(!token)return;await navigator.clipboard.writeText(token);message('Copied write credential.');}catch(e){message(e.message);}};
form('admin-form',async d=>{await api('admin/administrators','POST',d);await refresh();});
form('unlock-form',async d=>{await api('admin/unlock','POST',d);await status();});
form('master-form',async d=>{await api('admin/master','POST',d);});
$('logout').onclick=async()=>{try{await api('admin/logout','POST',{});signedOut();}catch(e){message(e.message);}};
$('lock').onclick=async()=>{try{await api('admin/lock','POST',{});await status();}catch(e){message(e.message);}};
$('audit-refresh').onclick=()=>{window.open('/audit','_blank','noopener,width=1200,height=850');};
$('hide-token').onclick=()=>{$('new-token').textContent='';};
$('close-reveal').onclick=()=>{$('revealed-value').textContent='';$('reveal').close();};
$('reveal').addEventListener('close',()=>{$('revealed-value').textContent='';});
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab').forEach(s=>s.hidden=s.id!==b.dataset.tab);$('new-token').textContent='';$('new-write-token').textContent='';});
setInterval(()=>{if(csrf)status().catch(e=>message(e.message));},15000);
api('admin/session').then(signedIn).catch(()=>signedOut());

// Folder structure is derived only from metadata. A path may be both a secret
// and a parent of other secrets; the browser keeps both entries in that case.
function renderFolder(){
 const crumbs=[action('All secrets',()=>navigate(''))];
 let prefix='';
 for(const part of currentFolder.split('/').filter(Boolean)){
  prefix+=part+'/';const destination=prefix;
  const separator=document.createElement('span');separator.textContent=' / ';crumbs.push(separator,action(part,()=>navigate(destination)));
 }
 $('breadcrumbs').replaceChildren(...crumbs);
 const entries=SSMBrowse.entries(secretMetadata,currentFolder,$('secret-filter').value);
 table('secret-list',['Name','Type','Revision','Updated','Actions'],entries.map(entry=>{
  if(entry.folder)return [[action('📁 '+entry.name,()=>navigate(entry.path))],'Folder','—','—',[]];
  const s=entry.secret;
  return [[action('📄 '+entry.name,()=>openEditor(s.path))],'Secret',s.revision,new Date(s.updated_at).toLocaleString(),[
   action('Edit',()=>openEditor(s.path)),
   action('Reveal',async()=>{const generation=authGeneration;const v=await api('admin/secrets/'+encoded(s.path));if(!csrf||generation!==authGeneration)return;$('revealed-value').textContent=v.data.value;$('reveal').showModal();}),
   action('Copy',async()=>{const generation=authGeneration;const v=await api('admin/secrets/'+encoded(s.path));if(!csrf||generation!==authGeneration)return;await navigator.clipboard.writeText(v.data.value);message('Copied secret value.');}),
   action('Delete',async()=>{if(confirm('Delete '+s.path+'?')){await api('admin/secrets/'+encoded(s.path),'DELETE');await refresh();}})
  ]];
 }));
 $('folder-summary').textContent=entries.length?entries.length+' items · folders are derived from secret paths':($('secret-filter').value?'No matching folders or secrets.':'This folder is empty. Create a secret to get started.');
}
function navigate(folder){currentFolder=folder;$('secret-filter').value='';renderFolder();}
$('secret-filter').oninput=renderFolder;
$('create-secret').onclick=()=>openEditor();
function clearEditor(){editorGeneration++;$('secret-form').reset();$('editor-value').value='';$('editor-error').textContent='';$('load-current').disabled=false;$('save-secret').disabled=false;}
function openEditor(path){
 clearEditor();editorMethod=path?'PUT':'POST';
 $('editor-title').textContent=path?'Edit secret':'Create secret';
 $('editor-path').value=path||currentFolder;$('editor-path').readOnly=!!path;
 $('load-current').hidden=!path;
 $('editor-hint').textContent=path?'Enter a replacement value, or explicitly reveal the current value to edit it.':'Paste a certificate, private key, configuration, or other secret text.';
 $('secret-editor').showModal();(path?$('editor-value'):$('editor-path')).focus();
}
$('close-editor').onclick=$('cancel-editor').onclick=()=>{$('secret-editor').close();clearEditor();};
$('secret-editor').addEventListener('close',clearEditor);
// A cancelled reveal request must not put a value back into a closed editor,
// or into a different secret that the user opened while the request was pending.
$('load-current').onclick=async()=>{
 const generation=editorGeneration;$('load-current').disabled=true;
 try{const v=await api('admin/secrets/'+encoded($('editor-path').value));if(generation===editorGeneration&&$('secret-editor').open){$('editor-value').value=v.data.value;$('editor-value').focus();}}
 catch(e){if(generation===editorGeneration)$('editor-error').textContent=e.message;}
 finally{if(generation===editorGeneration)$('load-current').disabled=false;}
};
$('secret-form').onsubmit=async event=>{
 event.preventDefault();const generation=editorGeneration;
 const path=$('editor-path').value,value=$('editor-value').value;
 if(value===''&&!confirm('Save an empty secret value?'))return;
 $('save-secret').disabled=true;$('editor-error').textContent='';
 try{
  await api('admin/secrets/'+encoded(path),editorMethod,{value});
  if(generation!==editorGeneration)return;
  $('secret-editor').close();clearEditor();
  currentFolder=path.includes('/')?path.slice(0,path.lastIndexOf('/')+1):'';
  $('secret-filter').value='';message('Secret saved.');await refresh();
 }catch(e){if(generation===editorGeneration)$('editor-error').textContent=e.message;else message(e.message);}
 finally{if(generation===editorGeneration)$('save-secret').disabled=false;}
};
