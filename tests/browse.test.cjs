const test = require('node:test');
const assert = require('node:assert/strict');
const {entries} = require('../internal/server/web/browse.js');
const secrets = ['servers/web01/key','servers/web01/cert','servers/web02/key','servers','servers2/key','root-secret'].map(path=>({path,revision:1}));
test('root folders precede files and duplicate folders collapse',()=>{
 assert.deepEqual(entries(secrets).map(e=>[e.name,e.folder]),[['servers',true],['servers2',true],['root-secret',false],['servers',false]]);
});
test('navigation respects slash boundaries and shows only direct children',()=>{
 assert.deepEqual(entries(secrets,'servers/').map(e=>e.name),['web01','web02']);
 assert.deepEqual(entries(secrets,'servers/web01/').map(e=>e.path),['servers/web01/cert','servers/web01/key']);
});
test('filter is case insensitive, empty folders are supported, metadata stays intact',()=>{
 assert.deepEqual(entries(secrets,'servers/','WEB01').map(e=>e.name),['web01']);
 assert.deepEqual(entries(secrets,'missing/'),[]);
 assert.equal(entries(secrets,'servers/web01/')[0].secret.revision,1);
 assert.equal(secrets.length,6);
});
test('names containing HTML are returned literally for text-only DOM rendering',()=>{
 assert.equal(entries([{path:'<img src=x>'}])[0].name,'<img src=x>');
});
