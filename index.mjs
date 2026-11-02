// Curbi Check: bounded, read-only fixture replay. No dependencies; Node 24.
import {appendFileSync,closeSync,constants,fstatSync,lstatSync,openSync,opendirSync,readSync} from 'node:fs';
import {isAbsolute,join,relative,resolve,sep} from 'node:path';
import {pathToFileURL} from 'node:url';

export const LIMITS=Object.freeze({requestBytes:65536,fileBytes:1048576,totalFileBytes:16777216,responseBytes:1048576,files:256,entries:4096,cases:10000,depth:16,findings:2048,checkTimeoutMs:20000,commentTimeoutMs:3000,reportChars:60000});
const MARKER='<!-- curbi-check -->',BATCH=50,encoder=new TextEncoder();
const input=(name,fallback='')=>(process.env['INPUT_'+name.replace(/ /g,'_').toUpperCase()]??fallback).trim()||fallback;
const out=(key,value)=>process.env.GITHUB_OUTPUT&&appendFileSync(process.env.GITHUB_OUTPUT,`${key}=${value}\n`);
const plain=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const text=(value,max)=>typeof value==='string'&&value.length<=max;
const bytes=value=>encoder.encode(value).byteLength;
const fail=message=>{throw new Error(message);};
// Entities render as literal punctuation rather than untrusted Markdown or HTML.
const md=value=>String(value).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g,' ').replace(/[&<>!"#$%'()*+,\-./:;=?@[\]\\^_`{|}~]/g,c=>'&#'+c.codePointAt(0)+';');
const safeError=value=>String(value).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g,' ').slice(0,500);

function stat(path){try{return lstatSync(path);}catch{fail('Cannot read regression path.');}}
export function findFiles(path){
  const root=resolve(path),files=[];let entries=0,totalBytes=0;
  if(process.env.GITHUB_WORKSPACE){
    const workspace=resolve(process.env.GITHUB_WORKSPACE),inside=relative(workspace,root);
    if(inside==='..'||inside.startsWith('..'+sep)||isAbsolute(inside))fail('Regression path must stay inside GITHUB_WORKSPACE.');
    let ancestor=workspace;
    for(const part of inside.split(sep).filter(Boolean)){ancestor=join(ancestor,part);if(stat(ancestor).isSymbolicLink())fail('Regression symlink ancestors are not allowed.');}
  }
  const walk=(current,depth)=>{
    if(depth>LIMITS.depth)fail('Regression directory depth limit exceeded.');
    const info=stat(current);
    if(info.isSymbolicLink())fail('Regression symlinks are not allowed.');
    if(info.isFile()){
      if(current===root||current.endsWith('.json')){if(files.length>=LIMITS.files)fail('Regression file limit exceeded.');if((totalBytes+=info.size)>LIMITS.totalFileBytes)fail('Regression aggregate file size limit exceeded.');files.push(current);}
      return;
    }
    if(!info.isDirectory())fail('Regression path must contain regular files only.');
    const directory=opendirSync(current);
    try{for(let child;(child=directory.readSync())!==null;){
      if(++entries>LIMITS.entries)fail('Regression directory entry limit exceeded.');
      if(child.isSymbolicLink())fail('Regression symlinks are not allowed.');
      if(child.isDirectory()||child.isFile()&&child.name.endsWith('.json'))walk(join(current,child.name),depth+1);
      else if(!child.isFile())fail('Regression path must contain regular files only.');
    }}finally{directory.closeSync();}
  };
  walk(root,0);return files.sort();
}

function readBounded(file){
  const info=stat(file);if(info.isSymbolicLink()||!info.isFile())fail('Regression files must be regular files, never symlinks.');
  let fd;
  try{
    fd=openSync(file,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
    const actual=fstatSync(fd);if(!actual.isFile()||actual.size>LIMITS.fileBytes)fail('Regression file size limit exceeded.');
    const chunks=[];let size=0;
    for(;;){const chunk=Buffer.alloc(Math.min(65536,LIMITS.fileBytes+1-size)),count=readSync(fd,chunk);if(!count)break;size+=count;if(size>LIMITS.fileBytes)fail('Regression file size limit exceeded.');chunks.push(chunk.subarray(0,count));}
    return new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,size));
  }catch(error){if(error.message==='Regression file size limit exceeded.')throw error;fail('Cannot read bounded regression file.');}
  finally{if(fd!==undefined)closeSync(fd);}
}
export function load(file){
  let suite;try{suite=JSON.parse(readBounded(file));}catch(error){if(/^(Regression|Cannot read)/.test(error.message))throw error;fail('Regression file is not JSON.');}
  if(suite?.regression?.object==='curbi.regression')suite=suite.regression;
  if(suite?.object!=='curbi.regression')return null;
  if(!plain(suite.policy)||!Array.isArray(suite.cases)||!suite.cases.length||suite.cases.length>LIMITS.cases)fail('curbi.regression needs a policy and bounded cases.');
  if(suite.version!==undefined&&(!text(suite.version,40)||!suite.version.length))fail('Invalid regression version.');
  const ids=new Set();
  suite.cases.forEach((c,index)=>{
    if(!plain(c)||Object.keys(c).some(key=>!['id','reply','record','expectedPass','expectedRules'].includes(key))||!text(c.reply,4000)||typeof c.expectedPass!=='boolean'||!Array.isArray(c.expectedRules)||c.expectedRules.length>LIMITS.findings||c.expectedRules.some(rule=>!text(rule,200)||!rule.length)||new Set(c.expectedRules).size!==c.expectedRules.length||c.record!==undefined&&!plain(c.record))fail('Each case needs reply, expectedPass and expectedRules with valid types and limits.');
    if(c.id!==undefined&&(!text(c.id,60)||!c.id.length))fail('Case id must be a nonempty string of at most 60 characters.');
    const id=c.id??String(index);if(ids.has(id))fail('Duplicate regression case id.');ids.add(id);
    if(c.expectedPass!==(c.expectedRules.length===0))fail('Expected pass and expected rules must agree.');
  });
  return suite;
}

function endpoint(value,key){
  let url;try{url=new URL(value);}catch{fail('Invalid Check API endpoint.');}
  const loopback=['localhost','127.0.0.1','[::1]'].includes(url.hostname);
  if(url.username||url.password||url.hash||!['http:','https:'].includes(url.protocol)||url.protocol==='http:'&&!loopback)fail('Check API endpoint requires HTTPS (HTTP loopback is allowed for local testing).');
  if(key&&!text(key,4096))fail('Invalid API credential.');
  return url.href;
}
async function responseJson(response,limit=LIMITS.responseBytes){
  const length=response.headers.get('Content-Length');if(length!==null&&(!/^\d+$/.test(length)||Number(length)>limit))fail('API response size limit exceeded.');
  const reader=response.body?.getReader();if(!reader)fail('API response has no JSON body.');
  const chunks=[];let size=0;
  for(;;){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit){await reader.cancel();fail('API response size limit exceeded.');}chunks.push(value);}
  const data=new Uint8Array(size);let offset=0;for(const chunk of chunks){data.set(chunk,offset);offset+=chunk.byteLength;}
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(data));}catch{fail('API response is not valid JSON.');}
}
const payload=(suite,cases)=>JSON.stringify({...(suite.version?{version:suite.version}:{}),policy:suite.policy,cases:cases.map(({id,reply,record})=>({id,reply,...(record!==undefined?{record}:{})}))});
async function check(api,key,body,cases){
  let response;
  try{response=await fetch(api,{method:'POST',redirect:'error',signal:AbortSignal.timeout(LIMITS.checkTimeoutMs),headers:{'Content-Type':'application/json','User-Agent':'curbi-check-action/1',...(key?{Authorization:'Bearer '+key}:{})},body});}
  catch{fail('Check API unreachable. No verdict was produced.');}
  if(response.status!==200){await response.body?.cancel();fail(`Check API answered ${response.status}. No verdict was produced.`);}
  const result=await responseJson(response);
  if(!plain(result)||result.object!=='check.batch'||!Array.isArray(result.results)||result.results.length!==cases.length)fail('Malformed Check API results. No verdict was produced.');
  const wanted=new Set(cases.map(c=>c.id)),seen=new Set(),matched=new Map();
  for(const row of result.results){
    if(!plain(row)||typeof row.id!=='string'||!wanted.has(row.id)||seen.has(row.id)||typeof row.pass!=='boolean'||!Array.isArray(row.findings)||row.findings.length>LIMITS.findings||row.pass!==(row.findings.length===0)||row.findings.some(f=>!plain(f)||!text(f.rule,200)||!f.rule.length||!text(f.text,4000)||!text(f.why,8000)))fail('Malformed Check API results. No verdict was produced.');
    seen.add(row.id);matched.set(row.id,row);
  }
  return matched;
}
export async function run({path,api,key}){
  api=endpoint(api,key);const rows=[],suites=[];let count=0;
  for(const file of findFiles(path)){
    const suite=load(file);if(!suite)continue;
    if((count+=suite.cases.length)>LIMITS.cases)fail('Regression aggregate case limit exceeded.');
    suites.push({file,suite});
  }
  // Validate the full fixture set before sending any customer-supplied content.
  for(const {file,suite}of suites){
    let batch=[];
    const replay=async()=>{
      if(!batch.length)return;const results=await check(api,key,payload(suite,batch),batch);
      for(const c of batch){const r=results.get(c.id),got=[...new Set(r.findings.map(f=>f.rule))].sort(),want=[...c.expectedRules].sort();rows.push({file,id:c.id,reply:c.reply,ok:r.pass===c.expectedPass&&JSON.stringify(got)===JSON.stringify(want),want,got,findings:r.findings});}
      batch=[];
    };
    for(const [index,original]of suite.cases.entries()){
      const c={...original,id:original.id??String(index)};
      if(bytes(payload(suite,[c]))>LIMITS.requestBytes)fail('A single regression policy/case exceeds the Check API request size limit.');
      if(batch.length===BATCH||bytes(payload(suite,[...batch,c]))>LIMITS.requestBytes)await replay();
      batch.push(c);
    }
    await replay();
  }
  if(!rows.length)fail('No curbi.regression files found.');return rows;
}

export function report(rows,root=process.cwd()){
  const failed=rows.filter(r=>!r.ok),head=failed.length?`❌ **Curbi Check: ${failed.length} of ${rows.length} cases changed**`:`✅ **Curbi Check: ${rows.length} cases match**`;
  const lines=[MARKER,head,'','| | File | Case | Expected | Got |','|---|---|---|---|---|'];let length=lines.join('\n').length,full=false;
  const add=line=>{if(length+line.length+1>LIMITS.reportChars-500){full=true;return false;}lines.push(line);length+=line.length+1;return true;};
  for(const r of [...failed,...rows.filter(r=>r.ok)].slice(0,100))if(!add(`| ${r.ok?'✅':'❌'} | ${md(relative(root,r.file))} | ${md(r.id)} | ${md(r.want.join(', ')||'pass')} | ${md(r.got?r.got.join(', ')||'pass':'missing')} |`))break;
  if(rows.length>100)add(`Showing 100 of ${rows.length}.`);
  for(const r of failed.slice(0,10)){
    const block=['',`<details><summary>${md(r.id)}: ${md(r.reply.slice(0,80))}</summary>`,''];
    for(const f of r.findings){if(block.join('\n').length>10000)break;block.push(`- ${md(f.rule)} "${md(f.text)}": ${md(f.why)}`);}
    if(!r.findings.length)block.push('- No findings: the reply now passes.');block.push('','</details>');if(!add(block.join('\n')))break;
  }
  if(full)add('Report truncated to the GitHub comment size limit. The job outputs retain the full case counts.');
  add('');add('A pass means no configured rule fired; it is not general truth and grants no permission. [Curbi](https://curbi.io/connect/)');return lines.join('\n');
}

async function comment(body,token){
  try{
    const ev=process.env.GITHUB_EVENT_PATH&&JSON.parse(readBounded(process.env.GITHUB_EVENT_PATH));
    const pr=ev?.pull_request?.number;if(!Number.isSafeInteger(pr)||pr<1||!token)return 'skipped (not a pull request)';
    const url=new URL(process.env.GITHUB_API_URL||'https://api.github.com');endpoint(url.href);
    if(url.search||url.hash||!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(process.env.GITHUB_REPOSITORY??''))return 'skipped (invalid GitHub context)';
    const base=url.href.replace(/\/$/,'')+'/repos/'+process.env.GITHUB_REPOSITORY+'/issues';
    const gh=(target,method='GET',data)=>fetch(target,{method,redirect:'error',signal:AbortSignal.timeout(LIMITS.commentTimeoutMs),headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','User-Agent':'curbi-check-action/1','Content-Type':'application/json'},...(data?{body:JSON.stringify(data)}:{})});
    const list=await gh(`${base}/${pr}/comments?per_page=100`);if(!list.ok){await list.body?.cancel();return `skipped (${list.status})`;}
    const comments=await responseJson(list);if(!Array.isArray(comments))return 'skipped (invalid GitHub response)';
    const mine=comments.find(c=>c.user?.login==='github-actions[bot]'&&c.user?.type==='Bot'&&typeof c.body==='string'&&c.body.startsWith(MARKER)&&Number.isSafeInteger(c.id)&&c.id>0);
    const response=mine?await gh(`${base}/comments/${mine.id}`,'PATCH',{body}):await gh(`${base}/${pr}/comments`,'POST',{body});
    const ok=response.ok,status=response.status;await response.body?.cancel();return ok?(mine?'updated':'posted'):`skipped (${status}; token cannot comment)`;
  }catch{return 'skipped (GitHub comment unavailable)';}
}
export async function main(){
  try{
    const rows=await run({path:input('path','curbi'),api:input('api','https://api.curbi.io/v1/check'),key:input('api-key')});
    const body=report(rows),failed=rows.filter(r=>!r.ok).length;out('cases',rows.length);out('failed',failed);
    if(process.env.GITHUB_STEP_SUMMARY)appendFileSync(process.env.GITHUB_STEP_SUMMARY,body+'\n');
    if(input('comment','true')==='true')console.log('Comment:',await comment(body,input('github-token')));
    console.log(body);if(failed){console.log(`::error::${failed} Curbi case(s) changed verdict or rules`);process.exitCode=1;}
  }catch(error){console.log(`::error::${safeError(error.message)}`);process.exitCode=1;}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)await main();
