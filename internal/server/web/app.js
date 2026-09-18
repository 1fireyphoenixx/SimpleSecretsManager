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
function signedOut(){authGeneration++;clearWorkflows();secretMetadata=[];currentFolder='';$('secret-list').replaceChildren();$('secret-editor').close();clearEditor();csrf='';$('dashboard').hidden=true;$('login').hidden=false;$('logout').hidden=true;$('status').textContent='Authentication required';$('new-token').textContent='';$('revealed-value').textContent='';$('reveal').close();}
async function status(){const generation=authGeneration;const data=await api('admin/status');if(!csrf||generation!==authGeneration)return;$('status').textContent=data.locked?'● LOCKED':'● UNLOCKED';renderLockControls(data.locked);}
async function signedIn(session){csrf=session.csrf;$('dashboard').hidden=false;$('login').hidden=true;$('logout').hidden=false;await refresh();}
function action(label, fn){const b=document.createElement('button');b.textContent=label;b.onclick=()=>Promise.resolve().then(fn).catch(e=>message(e.message));return b;}
function table(target, headers, rows){const t=document.createElement('table');const head=t.createTHead().insertRow();headers.forEach(x=>{const th=document.createElement('th');th.textContent=x;head.append(th);});const body=t.createTBody();rows.forEach(row=>{const tr=body.insertRow();row.forEach(value=>{const td=tr.insertCell();if(Array.isArray(value))value.forEach(b=>td.append(b));else td.textContent=String(value);});});$(target).replaceChildren(t);}
const encoded = path => path.split('/').map(encodeURIComponent).join('/');
async function refresh(){const generation=authGeneration;await status();const [secrets,agents,enrollments,admins,writers]=await Promise.all(['secrets','agents','enrollment','administrators','write-credentials'].map(p=>api('admin/'+p)));
 if(!csrf || generation!==authGeneration)return;
 secretMetadata=secrets;renderFolder();
 table('agent-list',['Name / ID','Paths','State','Actions'],agents.map(a=>[a.name+' / '+a.id,(a.paths||[]).join('\n'),a.revoked?'Revoked':'Active',[
  ...(a.revoked?[]:[action('Edit permissions',()=>openPermissions('agent',a)),action('Revoke',async()=>{if(confirm('Revoke '+a.name+'?')){await api('admin/agents/'+a.id,'DELETE');await refresh();}})]),
  action('Delete',async()=>{if(confirm('Permanently delete '+a.name+' and all its enrollment tokens and runtime credentials? Existing deployed files are retained.')){await api('admin/agents/'+a.id+'/purge','DELETE');$('new-token').textContent='';await refresh();}})
 ]]));
 $('enrollment-agent').replaceChildren(...agents.filter(a=>!a.revoked).map(a=>{const o=document.createElement('option');o.value=a.id;o.textContent=a.name+' / '+a.id;return o;}));
 table('enrollment-list',['ID','Agent','Expires','Used','Actions'],enrollments.map(e=>[e.id,e.agent_id,e.expires_at,e.used,[action('Delete token',async()=>{await api('admin/enrollment/'+e.id,'DELETE');await refresh();})]]));
 // Names and paths are untrusted server data; table() always inserts text.
 table('writer-list',['Name / ID','Paths','Creation','State','Actions'],writers.map(c=>[c.name+' / '+c.id,(c.paths||[]).join('\n'),c.allow_create?'Allowed':'Not allowed',c.revoked?'Revoked':'Active',c.revoked?[]:[action('Edit permissions',()=>openPermissions('writer',c)),action('Revoke',async()=>{if(confirm('Revoke '+c.name+'?')){await api('admin/write-credentials/'+c.id,'DELETE');await refresh();}})]]));
 table('admin-list',['Administrator','Actions'],admins.map(name=>[name,[action('Delete',async()=>{if(confirm('Delete administrator '+name+'?')){await api('admin/administrators/'+encodeURIComponent(name),'DELETE');await refresh();}})]]));
}
function form(id, fn){$(id).onsubmit=async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(e.target));try{await fn(data);e.target.reset();message('Saved.');}catch(e){message(e.message);}finally{e.target.querySelectorAll('input[type=password],textarea[name=value]').forEach(x=>x.value='');}};}
form('login-form',async d=>signedIn(await api('login','POST',d)));

form('enrollment-form',async d=>{const v=await api('admin/enrollment','POST',{agent_id:d.agent_id,ttl_seconds:Number(d.ttl_seconds)});$('new-token').textContent=v.token;await refresh();});
form('admin-form',async d=>{await api('admin/administrators','POST',d);await refresh();});
$('logout').onclick=async()=>{try{await api('admin/logout','POST',{});signedOut();}catch(e){message(e.message);}};
$('lock').onclick=async()=>{try{await api('admin/lock','POST',{});await status();}catch(e){message(e.message);}};
$('hide-token').onclick=()=>{$('new-token').textContent='';};
$('close-reveal').onclick=()=>{$('revealed-value').textContent='';$('reveal').close();};
$('reveal').addEventListener('close',()=>{$('revealed-value').textContent='';});
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab').forEach(s=>s.hidden=s.id!==b.dataset.tab);$('new-token').textContent='';});
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

// Unlock inputs exist only while the server is locked. Polling an unchanged
// state does not replace a form the administrator is currently typing into.
function renderLockControls(locked){
 $('lock').hidden=locked;
 $('lock-title').textContent=locked?'Server is locked':'Server is unlocked';
 $('lock-description').textContent=locked?'Unlock to make secret operations available.':'Secret operations are available. Locking removes the encryption key from memory.';
 if(!locked){$('unlock-controls').replaceChildren();return;}
 if(!$('unlock-form')){
  $('unlock-controls').append($('unlock-template').content.cloneNode(true));
  form('unlock-form',async data=>{await api('admin/unlock','POST',data);await status();});
 }
}

// A single configure -> token flow serves agents and writers. Closing or losing
// the session clears credentials. While a request is pending, closing is blocked
// so a successfully issued one-time token is not silently discarded.
let accessKind='writer',createdAgentID='',permissionTarget=null;
let workflowGeneration=0;
const pathLines=value=>value.split('\n').map(s=>s.trim()).filter(Boolean);
function busy(dialog,on){dialog.dataset.busy=on?'true':'false';dialog.querySelectorAll('button').forEach(b=>b.disabled=on);}
function resetWorkflow(name){
 workflowGeneration++;
 $(name+'-form').reset();$(name+'-error').textContent='';
 if(name==='access'){$('access-token').textContent='';createdAgentID='';}
}
for(const name of ['access','permissions','master']){
 const dialog=$(name+'-dialog');
 dialog.addEventListener('cancel',e=>{
  if(dialog.dataset.busy==='true')e.preventDefault();
  else resetWorkflow(name); // Clear secrets immediately on Escape.
 });
 const close=()=>{if(dialog.dataset.busy!=='true'){dialog.close();resetWorkflow(name);}};
 $('close-'+name).onclick=$('cancel-'+name).onclick=close;
 // Ignore a queued close event if the user already reopened the dialog.
 dialog.addEventListener('close',()=>{if(!dialog.open)resetWorkflow(name);});
}
function clearWorkflows(){
 workflowGeneration++;
 for(const name of ['access','permissions','master']){
  const dialog=$(name+'-dialog');busy(dialog,false);dialog.close();
  $(name+'-form').reset();$(name+'-error').textContent='';
 }
 $('access-token').textContent='';createdAgentID='';permissionTarget=null;
 $('unlock-controls').replaceChildren();$('lock').hidden=true;
}
function openAccess(kind){
 workflowGeneration++;accessKind=kind;createdAgentID='';
 $('access-form').reset();$('access-name').readOnly=false;$('access-paths').readOnly=false;$('access-form').hidden=false;$('access-result').hidden=true;$('access-token').textContent='';$('access-error').textContent='';
 $('access-title').textContent=kind==='agent'?'Create agent':'Create write credential';
 $('access-step').textContent='STEP 1 OF 2 · CONFIGURE ACCESS';
 $('access-create-label').hidden=kind==='agent';$('access-ttl-label').hidden=kind!=='agent';
 $('access-ttl').required=kind==='agent';$('access-ttl').disabled=kind!=='agent';
 $('submit-access').textContent=kind==='agent'?'Create agent & enrollment token':'Create credential';
 busy($('access-dialog'),false);$('access-dialog').showModal();$('access-name').focus();
}
$('create-agent').onclick=()=>openAccess('agent');$('create-writer').onclick=()=>openAccess('writer');
$('done-access').onclick=()=>{$('access-dialog').close();resetWorkflow('access');};
$('copy-access-token').onclick=async()=>{try{await navigator.clipboard.writeText($('access-token').textContent);$('access-error').textContent='Token copied.';}catch{$('access-error').textContent='Clipboard unavailable. Select and copy the token above.';}};
$('access-form').onsubmit=async event=>{
 event.preventDefault();const generation=workflowGeneration,dialog=$('access-dialog');
 busy(dialog,true);$('access-error').textContent='';
 const name=$('access-name').value,paths=pathLines($('access-paths').value);
 try{
  let token;
  if(accessKind==='writer'){
   const result=await api('admin/write-credentials','POST',{name,paths,allow_create:$('access-create').checked});
   token=result.token;
  }else{
   // Retain the created identity if token generation fails. A retry issues a
   // token for that identity instead of creating duplicate agents.
   if(!createdAgentID){const agent=await api('admin/agents','POST',{name,paths});if(generation!==workflowGeneration)return;createdAgentID=agent.id;$('access-name').readOnly=true;$('access-paths').readOnly=true;}
   const result=await api('admin/enrollment','POST',{agent_id:createdAgentID,ttl_seconds:Number($('access-ttl').value)});
   token=result.token;
  }
  if(generation!==workflowGeneration||!csrf)return;
  $('access-token').textContent=token;$('access-form').hidden=true;$('access-result').hidden=false;
  $('access-step').textContent='STEP 2 OF 2 · SAVE YOUR TOKEN';
  $('access-result-description').textContent=accessKind==='agent'?'Agent created. Use this expiring, one-time enrollment token in the agent configuration.':'Credential created. Use this bearer token for writes to the assigned paths.';
  $('copy-access-token').focus();await refresh();
 }catch(e){if(generation===workflowGeneration)$('access-error').textContent=(createdAgentID?'Agent was created. Retry to generate its enrollment token. ':'')+e.message;}
 finally{busy(dialog,false);}
};
function openPermissions(kind,record){
 workflowGeneration++;permissionTarget={kind,id:record.id};
 $('permissions-name').textContent=record.name;$('permissions-paths').value=(record.paths||[]).join('\n');
 $('permissions-create-label').hidden=kind!=='writer';$('permissions-create').checked=!!record.allow_create;
 $('permissions-error').textContent='';busy($('permissions-dialog'),false);$('permissions-dialog').showModal();$('permissions-paths').focus();
}
$('permissions-form').onsubmit=async event=>{
 event.preventDefault();const generation=workflowGeneration,dialog=$('permissions-dialog');busy(dialog,true);$('permissions-error').textContent='';
 const target=permissionTarget,body={paths:pathLines($('permissions-paths').value)};
 if(target.kind==='writer')body.allow_create=$('permissions-create').checked;
 try{
  await api('admin/'+(target.kind==='writer'?'write-credentials/':'agents/')+target.id,'PUT',body);
  if(generation!==workflowGeneration)return;
  dialog.close();message('Permissions saved.');await refresh();
 }catch(e){if(generation===workflowGeneration)$('permissions-error').textContent=e.message;}
 finally{busy(dialog,false);}
};
$('change-master').onclick=()=>{workflowGeneration++;$('master-form').reset();$('master-error').textContent='';busy($('master-dialog'),false);$('master-dialog').showModal();$('master-form').elements.old.focus();};
$('master-form').onsubmit=async event=>{
 event.preventDefault();const generation=workflowGeneration,dialog=$('master-dialog');busy(dialog,true);$('master-error').textContent='';
 const fields=$('master-form').elements;
 try{await api('admin/master','POST',{old:fields.old.value,new:fields.new.value});if(generation===workflowGeneration){dialog.close();message('Master key changed. Use your new key for the next unlock.');}}
 catch(e){if(generation===workflowGeneration)$('master-error').textContent=e.message;}
 finally{$('master-form').reset();busy(dialog,false);}
};
