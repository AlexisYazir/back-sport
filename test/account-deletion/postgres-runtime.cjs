'use strict';
// Dedicated PostgreSQL18 cluster. No existing server, provider or shared DB.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { execFileSync } = require('node:child_process');
const TEST_ROOT=__dirname;
assert.equal(process.env.ACCOUNT_DELETION_POSTGRES_QA,'true','EXPLICIT_QA_OPT_IN_REQUIRED');
assert.ok(process.env.ACCOUNT_DELETION_QA_ROOT && path.isAbsolute(process.env.ACCOUNT_DELETION_QA_ROOT),'FRESH_QA_ROOT_REQUIRED');
assert.ok(process.env.PG_BINDIR && path.isAbsolute(process.env.PG_BINDIR),'PG_BINDIR_REQUIRED');
const BASE=fs.realpathSync(process.env.ACCOUNT_DELETION_QA_ROOT),BIN=fs.realpathSync(process.env.PG_BINDIR);
const DB = 'sportcenter_deletion_qa', USER = 'qa_admin';
const sha = data => crypto.createHash('sha256').update(data).digest('hex');
const osKeys = ['PATH','Path','SystemRoot','SYSTEMROOT','WINDIR','COMSPEC','ComSpec','PATHEXT','USERPROFILE','LOCALAPPDATA','APPDATA','TEMP','TMP','PG_BINDIR','ACCOUNT_DELETION_QA_ROOT','ACCOUNT_DELETION_POSTGRES_QA'];
const env = Object.fromEntries(osKeys.filter(key => typeof process.env[key] === 'string').map(key => [key, process.env[key]]));
process.env = { ...env, NODE_ENV:'test', ISOLATED_TEST_ENV:'true' };
const save = (file,value) => fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
function command(name,args,options={}) {
  return execFileSync(path.join(BIN,name+(process.platform==='win32'?'.exe':'')),args,{cwd:BASE,env,windowsHide:true,encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:45000,maxBuffer:4*1024*1024,...options});
}
function psql(port,database,sql) {
  assert.ok(Number.isInteger(port)&&port>=1024&&port<=65535);
  assert.ok(database === DB || database === 'postgres');
  return command('psql',['-X','-v','ON_ERROR_STOP=1','--no-password','-h','127.0.0.1','-p',String(port),'-U',USER,'-d',database,'-At'],{env:{...env,PGPASSWORD:'qa-admin-local'},input:sql});
}
async function sparePort() {
  const server=net.createServer();
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const port=server.address().port;
  await new Promise(resolve=>server.close(resolve));
  return port;
}
async function baseline() {
  const schema=fs.readFileSync(path.join(TEST_ROOT,'schema.sql'));
  assert.equal(sha(schema),'4d91e9a467de9cdab15afbad76f9770b11e65ecff86727f5a1b2dcb24ab54203','QA_BASELINE_SCHEMA_CHANGED');
  assert.ok(!/^(?:COPY|INSERT|SELECT|GRANT|REVOKE|CREATE ROLE)/m.test(schema.toString('utf8')),'DDL_ONLY_BASELINE_REQUIRED');
  const run=path.join(BASE,'native-pg-'+process.pid+'-'+Date.now());
  fs.mkdirSync(run,{mode:0o700});
  const pgdata=path.join(run,'pgdata'), passwordFile=path.join(run,'synthetic-init-password.txt');
  fs.writeFileSync(passwordFile,'qa-admin-local\n',{flag:'wx',mode:0o600});
  const port=await sparePort();
  const report={scope:'fresh-native-postgresql18-synthetic-qa-baseline-not-production',status:'failed',run,dataDirectory:pgdata,port,host:'127.0.0.1',database:DB,username:USER,baselineSha256:sha(schema),originalDataImported:false,sharedDatabaseTouched:false,externalServicesUsed:false,started:false,stopped:false};
  let started=false;
  try {
    fs.writeFileSync(path.join(run,'initdb.log'),command('initdb',['-D',pgdata,'-U',USER,'--pwfile='+passwordFile,'--auth-local=scram-sha-256','--auth-host=scram-sha-256','--encoding=UTF8','--locale=C']),{flag:'wx'});
    const options='-h 127.0.0.1 -p '+port+' -c shared_buffers=32MB -c max_connections=15 -c log_statement=none -c log_min_error_statement=panic';
    command('pg_ctl',['-D',pgdata,'-l',path.join(run,'postgres.log'),'-o',options,'-w','-t','15','start'],{stdio:'ignore',timeout:20000});
    fs.writeFileSync(path.join(run,'start.log'),'pg_ctl returned exit0; server output in postgres.log\n',{flag:'wx'});
    started=true;report.started=true;
    psql(port,'postgres','CREATE DATABASE '+DB+';\n');
    psql(port,DB,schema);
    psql(port,DB,"CREATE ROLE qa_editor LOGIN PASSWORD 'qa-editor-local';\nCREATE ROLE qa_reader LOGIN PASSWORD 'qa-reader-local';\nCREATE ROLE qa_backup LOGIN PASSWORD 'qa-backup-local';\nGRANT USAGE ON SCHEMA core, public TO qa_editor,qa_reader,qa_backup;\nGRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA core,public TO qa_editor;\nGRANT SELECT ON ALL TABLES IN SCHEMA core,public TO qa_reader,qa_backup;\nGRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA core,public TO qa_editor;\n");
    const identity=JSON.parse(psql(port,DB,"SELECT json_build_object('database',current_database(),'user',current_user,'host',host(inet_server_addr()),'port',inet_server_port(),'dataDirectory',current_setting('data_directory'),'version',current_setting('server_version'));\n").trim());
    assert.equal(identity.database,DB);assert.equal(identity.user,USER);assert.equal(identity.host,'127.0.0.1');assert.equal(identity.port,port);assert.equal(path.resolve(identity.dataDirectory),path.resolve(pgdata));
    const inventory=JSON.parse(psql(port,DB,"SELECT json_build_object('columns',(SELECT json_agg(c ORDER BY c.table_schema,c.table_name,c.ordinal_position) FROM (SELECT table_schema,table_name,column_name,ordinal_position,data_type,udt_name,is_nullable,character_maximum_length,column_default FROM information_schema.columns WHERE table_schema IN ('core','public')) c),'constraints',(SELECT json_agg(x ORDER BY x.schema,x.table_name,x.name) FROM (SELECT n.nspname AS schema,t.relname AS table_name,c.conname AS name,c.contype AS type,pg_get_constraintdef(c.oid) AS definition FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname IN ('core','public')) x));\n").trim());
    const rows=JSON.parse(psql(port,DB,"SELECT json_agg(json_build_object('schema',schemaname,'table',relname,'rows',n_live_tup)) FROM pg_stat_user_tables;\n").trim());
    assert.ok(rows.every(row=>row.rows===0));
    save(path.join(run,'schema-inventory.json'),{scope:report.scope,identity,inventory,tableCount:rows.length,originalRowsImported:false,foreignKeyCount:inventory.constraints.filter(item=>item.type==='f').length});
    report.tableCount=rows.length;report.columnCount=inventory.columns.length;report.constraintCount=inventory.constraints.length;report.foreignKeyCount=inventory.constraints.filter(item=>item.type==='f').length;
    report.identity=identity;report.status='passed';
  } catch(error) {
    report.errorCode=String(error.code||error.name||'ERROR');
    fs.writeFileSync(path.join(run,'failure-private.log'),String(error.message||error)+'\n'+String(error.stdout||'')+'\n'+String(error.stderr||''),{flag:'wx',mode:0o600});
    throw error;
  } finally {
    if(started) {
      try {command('pg_ctl',['-D',pgdata,'-m','fast','-w','-t','15','stop'],{stdio:'ignore',timeout:20000});fs.writeFileSync(path.join(run,'stop.log'),'pg_ctl stop returned exit0\n',{flag:'wx'});report.stopped=true;}catch{report.stopped=false;}
    }
    save(path.join(run,'baseline-result.json'),report);
    save(path.join(BASE,'baseline-run-'+path.basename(run)+'.json'),{run,status:report.status,stopped:report.stopped});
    process.stdout.write(JSON.stringify({run,status:report.status,tableCount:report.tableCount,columnCount:report.columnCount,foreignKeyCount:report.foreignKeyCount,stopped:report.stopped})+'\n');
  }
}
if (require.main === module) baseline().catch(()=>{process.stderr.write('ISOLATED_BASELINE_FAILED_PRIVATE_LOG_SAVED\n');process.exitCode=1;});
module.exports = { command, psql, baseline, env, BASE, DB, USER, sha };
