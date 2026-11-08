'use strict';
// Independent high-impact behavior checks. No AppModule, scheduler or real mail.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {randomBytes}=require('node:crypto'),{createRequire}=require('node:module'),{execFileSync}=require('node:child_process');
assert.ok(process.argv.includes('--execute'),'EXPLICIT_QA_EXECUTE_REQUIRED');
assert.ok(process.env.PG_BINDIR && path.isAbsolute(process.env.PG_BINDIR),'PG_BINDIR_REQUIRED');
assert.ok(!process.env.ACCOUNT_DELETION_QA_ROOT,'EXISTING_QA_ROOT_MUST_NOT_BE_REUSED');
process.argv[2]=process.argv.find(value=>['service','restore-only','nest-only','expiry-only'].includes(value))??'service';
process.env.ACCOUNT_DELETION_QA_ROOT=fs.mkdtempSync(path.join(require('node:os').tmpdir(),'sportcenter-account-deletion-qa-'));
process.env.ACCOUNT_DELETION_POSTGRES_QA='true';
const {command,env,BASE,DB,USER,sha}=require('./postgres-runtime.cjs');
const SOURCE=path.resolve(__dirname,'../..');
const deps=createRequire(path.join(SOURCE,'package.json'));
// Fail closed on any attempted non-loopback socket or HTTP/provider traffic.
const net=require('node:net'),connect=net.Socket.prototype.connect;
net.Socket.prototype.connect=function(...args){
  const value=args[0],options=value&&typeof value==='object'?value:{host:typeof args[1]==='string'?args[1]:'127.0.0.1'};
  assert.ok(['127.0.0.1','::1'].includes(options.host??'127.0.0.1')&&!options.path,'QA_LOOPBACK_ONLY');
  return connect.apply(this,args);
};
for(const method of ['request','get']){
  const http=require('node:http'),original=http[method];
  http[method]=function(input,...args){const target=typeof input==='string'||input instanceof URL?new URL(input):input;assert.ok(['127.0.0.1','::1'].includes(target.hostname??target.host),'QA_HTTP_LOOPBACK_ONLY');return original.call(this,input,...args);};
  require('node:https')[method]=()=>{throw new Error('QA_HTTPS_DISABLED');};
}
global.fetch=()=>Promise.reject(new Error('QA_FETCH_DISABLED'));
deps('reflect-metadata');
deps('ts-node').register({project:path.join(SOURCE,'tsconfig.json'),transpileOnly:true,compilerOptions:{incremental:false}});
const {DataSource}=deps('typeorm'),{ConfigService}=deps('@nestjs/config'),{Client}=deps('pg');
const {User}=require(path.join(SOURCE,'src/modules/users/entities/user.entity.ts'));
const {ReviewModeration1793740000000}=require(path.join(SOURCE,'src/database/migrations/1793740000000-ReviewModeration.ts'));
const {AccountDeletion1794100000000}=require(path.join(SOURCE,'src/database/migrations/1794100000000-AccountDeletion.ts'));
const {AccountDeletionService}=require(path.join(SOURCE,'src/modules/account-deletion/account-deletion.service.ts'));
const {AccountDeletionDataService}=require(path.join(SOURCE,'src/modules/account-deletion/account-deletion-data.service.ts'));
const {DeletionSecrets}=require(path.join(SOURCE,'src/modules/account-deletion/deletion-secrets.ts'));
const {DeletionRecoveryGate}=require(path.join(SOURCE,'src/modules/account-deletion/deletion-recovery-gate.ts'));
const {FileDeletionLedger}=require(path.join(SOURCE,'src/modules/account-deletion/ledger/file-deletion-ledger.ts'));
const save=(file,value)=>fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
const principal=id=>({id_usuario:id,sessionId:'71000000-0000-4000-8000-'+String(id).padStart(12,'0'),rol:1});
const connection=port=>({host:'127.0.0.1',port,database:DB,user:USER,password:'qa-admin-local',ssl:false,statement_timeout:15000,query_timeout:18000});
function provisionPrivateDirectory(directory){
  if(process.platform!=='win32')return;
  assert.equal(path.dirname(path.dirname(directory)),BASE,'OWN_QA_DIRECTORY_REQUIRED');
  const literal=directory.replaceAll("'","''");
  const script="$ErrorActionPreference='Stop'; $p='"+literal+"'; $me=[Security.Principal.WindowsIdentity]::GetCurrent().User; $acl=New-Object Security.AccessControl.DirectorySecurity; $acl.SetOwner($me); $acl.SetAccessRuleProtection($true,$false); foreach($sid in @($me.Value,'S-1-5-18','S-1-5-32-544')) { $identity=New-Object Security.Principal.SecurityIdentifier($sid); $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow'); $acl.AddAccessRule($rule) }; Set-Acl -LiteralPath $p -AclObject $acl; Write-Output 'QA_PRIVATE_DIRECTORY_READY'";
  const output=execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{cwd:BASE,env,windowsHide:true,encoding:'utf8',timeout:10000});assert.equal(output.trim(),'QA_PRIVATE_DIRECTORY_READY');
}
function hashes(){const result={};for(const file of ['src/database/migrations/1793740000000-ReviewModeration.ts','src/database/migrations/1794100000000-AccountDeletion.ts','src/modules/users/entities/user.entity.ts'])result[file]=sha(fs.readFileSync(path.join(SOURCE,file)));function visit(dir){for(const item of fs.readdirSync(dir,{withFileTypes:true})){const full=path.join(dir,item.name);if(item.isDirectory())visit(full);else if(item.isFile()&&item.name.endsWith('.ts')&&!item.name.endsWith('.spec.ts'))result[path.relative(SOURCE,full).replace(/\\/g,'/')]=sha(fs.readFileSync(full));}}const directories=['src/modules/account-deletion',...(process.argv[2]==='nest-only'?['src/modules/users','src/services/auth','src/services/mail']:[])];for(const dir of directories)visit(path.join(SOURCE,dir));return result;}
async function main(){
  const frozen=hashes();
  const output=execFileSync(process.execPath,[path.join(__dirname,'postgres-runtime.cjs')],{cwd:BASE,env,windowsHide:true,encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:60000});
  const baseline=JSON.parse(output.trim().split(/\r?\n/).at(-1));assert.equal(baseline.status,'passed');assert.equal(baseline.stopped,true);
  const run=baseline.run,metadata=JSON.parse(fs.readFileSync(path.join(run,'baseline-result.json'),'utf8'));
  assert.equal(path.dirname(run),BASE);assert.match(path.basename(run),/^native-pg-\d+-\d+$/);
  const report={scope:'independent-real-postgres18-full-services-native-private-ledger-synthetic-qa-not-production',mode:process.argv[2]??'service',status:'failed',run,sourceHashes:frozen,harnessSha256:sha(fs.readFileSync(__filename)),checks:[],networkGuard:'127.0.0.1-only-HTTP-HTTPS-and-fetch-external-disabled',mailProvider:'in-memory-capture-no-delivery',sharedDatabaseTouched:false,stopped:false};
  const checked=(name,detail={})=>{report.checks.push({name,status:'passed',...detail});fs.appendFileSync(path.join(run,'service-progress.jsonl'),JSON.stringify({name,utc:new Date().toISOString()})+'\n',{mode:0o600});};
  let started=false,client,source;
  const mail={codes:[],results:[],failCode:false,failResult:false,async sendAccountDeletionCode(email,code){assert.ok(email.endsWith('@qa.invalid'));if(this.failCode){this.failCode=false;throw new Error('QA_MAIL_FAILURE');}this.codes.push({email,code});},async sendAccountDeletionResult(email,id){assert.ok(email.endsWith('@qa.invalid'));if(this.failResult){this.failResult=false;throw new Error('QA_MAIL_FAILURE');}this.results.push({email,id});}};
  const restoreOnly=process.argv[2]==='restore-only';
  const configValues={ACCOUNT_DELETION_ENABLED:'true',ACCOUNT_DELETION_SECRET:randomBytes(32).toString('hex'),ACCOUNT_DELETION_LEDGER_SECRET:randomBytes(32).toString('hex'),JWT_SECRET:'qa-only-distinct-jwt-key',JWT_REFRESH_SECRET:'qa-only-distinct-refresh-key',FRONTEND_URL:'http://localhost:4200',...(restoreOnly?{ACCOUNT_DELETION_RETENTION_BASIS:'Synthetic restoration QA basis; not a production legal decision',ACCOUNT_DELETION_RETENTION_DAYS:'30'}:{})};
  const config=new ConfigService(configValues);
  const createSource=()=>new DataSource({type:'postgres',host:'127.0.0.1',port:metadata.port,database:DB,username:USER,password:'qa-admin-local',ssl:false,entities:[User],synchronize:false,logging:false,extra:{statement_timeout:15000,query_timeout:18000}});
  let service,gate;
  try{
    command('pg_ctl',['-D',metadata.dataDirectory,'-l',path.join(run,'service-postgres.log'),'-o','-h 127.0.0.1 -p '+metadata.port+' -c shared_buffers=32MB -c max_connections=15 -c log_statement=none -c log_min_error_statement=panic','-w','-t','15','start'],{stdio:'ignore',timeout:20000});started=true;
    client=new Client(connection(metadata.port));await client.connect();
    const identity=(await client.query("SELECT current_database() database,current_user username,host(inet_server_addr()) host,inet_server_port() port,current_setting('data_directory') directory")).rows[0];
    assert.equal(identity.database,DB);assert.equal(identity.username,USER);assert.equal(identity.host,'127.0.0.1');assert.equal(identity.port,metadata.port);assert.equal(path.resolve(identity.directory),path.resolve(metadata.dataDirectory));report.identity=identity;
    const fixture=fs.readFileSync(path.join(__dirname,'fixtures.sql'));report.fixtureSha256=sha(fixture);await client.query(fixture.toString('utf8'));
    const runner={query:async(sql,args)=>(await client.query(sql,args)).rows};
    await client.query('BEGIN');await new ReviewModeration1793740000000().up(runner);await client.query('COMMIT');
    await client.query('CREATE TABLE public.contact_messages (LIKE core.contact_messages INCLUDING ALL)');
    await client.query('INSERT INTO public.contact_messages SELECT * FROM core.contact_messages');
    if(process.argv[2]==='service'){
      for(const backupRole of ['qa_editor','qa_absent_backup']){
        await client.query('BEGIN');
        try{await assert.rejects(new AccountDeletion1794100000000(backupRole).up(runner));}finally{await client.query('ROLLBACK');}
        assert.equal((await client.query("SELECT to_regclass('core.account_deletion_accounts')::text value")).rows[0].value,null);
      }
      checked('migration-backup-role-preflight-rejects-writer-and-missing-role-without-leaving-private-tables');
    }
    await client.query('BEGIN');await new AccountDeletion1794100000000('qa_backup').up(runner);await client.query('COMMIT');
    if(process.argv[2]==='service'){
      for(const role of ['qa_reader','qa_editor'])for(const table of ['account_deletion_requests','account_deletion_retention','account_deletion_notifications'])assert.equal((await client.query('SELECT has_table_privilege($1,$2,\'SELECT\') allowed',[role,'core.'+table])).rows[0].allowed,false);
      for(const role of ['qa_reader','qa_editor'])assert.equal((await client.query('SELECT has_column_privilege($1,\'core.account_deletion_accounts\',\'identity_email\',\'SELECT\') allowed',[role])).rows[0].allowed,false);
      for(const table of ['account_deletion_accounts','account_deletion_requests','account_deletion_retention','account_deletion_notifications'])assert.equal((await client.query('SELECT has_table_privilege(\'qa_backup\',$1,\'SELECT\') allowed',['core.'+table])).rows[0].allowed,true);
      const editor=new Client({...connection(metadata.port),user:'qa_editor',password:'qa-editor-local'});await editor.connect();
      try{assert.equal((await editor.query('SELECT state FROM core.account_deletion_accounts WHERE user_id=710101')).rows[0].state,'active');await assert.rejects(editor.query('SELECT identity_email FROM core.account_deletion_accounts'),error=>error.code==='42501');await assert.rejects(editor.query('SELECT * FROM core.account_deletion_requests'),error=>error.code==='42501');}finally{await editor.end();}
      checked('inherited-default-read-grants-revoked-for-reader-editor-and-verified-anchor-kept-private');
      checked('editor-can-read-only-account-state-required-for-existing-authentication');
      const backup=command('pg_dump',['-h','127.0.0.1','-p',String(metadata.port),'-U','qa_backup','-d',DB,'--format=custom','--no-owner'],{env:{...env,PGPASSWORD:'qa-backup-local'},encoding:null,maxBuffer:32*1024*1024});
      fs.writeFileSync(path.join(run,'backup-role-full-synthetic.dump'),backup,{flag:'wx',mode:0o600});report.backupRoleDumpSha256=sha(backup);assert.ok(backup.length>1000);
      checked('authorized-read-only-backup-role-can-pg-dump-complete-database-with-private-tables');
    }
    // Genuine append-only moderation history, including an author whose account is erased.
    await client.query("BEGIN; INSERT INTO core.review_moderation_events(id_review,id_mensaje,accion,motivo,id_administrador,retirada_anterior,retirada_nueva,revision) VALUES(710101,710101,'conservar','QA moderation evidence',710199,false,false,1); UPDATE core.reviews SET revision=1 WHERE id_review=710101; COMMIT;");
    checked('fresh-identity-schema-migrations-and-commercial-moderation-FK-fixtures');
    const ledgerDir=path.join(run,'independent-ledger');fs.mkdirSync(ledgerDir,{mode:0o700});provisionPrivateDirectory(ledgerDir);
    const ledger=new FileDeletionLedger({directory:ledgerDir,repositoryRoot:SOURCE,hmacKey:Buffer.from(config.get('ACCOUNT_DELETION_LEDGER_SECRET'),'hex')});
    await ledger.initializeNew();checked('real-external-file-ledger-initialized-with-native-ACL-verifier');
    source=createSource();await source.initialize();
    const setup=()=>{gate=new DeletionRecoveryGate(true,ledger);service=new AccountDeletionService(source,config,new DeletionSecrets(config),new AccountDeletionDataService(),mail,ledger,gate);};
    setup();assert.throws(()=>gate.assertApplicationReady(),/RECOVERY_NOT_READY/);
    await gate.reconcileBeforeServing(intent=>service.replay(intent));gate.assertApplicationReady();checked('traffic-gate-closed-before-real-ledger-reconciliation');
    const requestAndVerify=async(id)=>{const req=await service.request(principal(id));const delivery=mail.codes.at(-1);assert.match(delivery.code,/^\d{6}$/);const grant=await service.verify(principal(id),req.requestId,delivery.code);return{req,grant,delivery};};
    const backupDatabase=name=>{const archive=path.join(run,name);const dump=command('pg_dump',['-h','127.0.0.1','-p',String(metadata.port),'-U',USER,'-d',DB,'--format=custom','--no-owner'],{env:{...env,PGPASSWORD:'qa-admin-local'},encoding:null,maxBuffer:32*1024*1024});fs.writeFileSync(archive,dump,{flag:'wx',mode:0o600});return{archive,sha256:sha(dump)};};
    const restoreDatabase=async archive=>{
      await source.destroy();await client.end();client=null;
      const admin=new Client({...connection(metadata.port),database:'postgres'});await admin.connect();
      try{const target=(await admin.query("SELECT host(inet_server_addr()) host,inet_server_port() port,current_setting('data_directory') directory")).rows[0];assert.equal(target.host,'127.0.0.1');assert.equal(target.port,metadata.port);assert.equal(path.resolve(target.directory),path.resolve(metadata.dataDirectory));await admin.query('DROP DATABASE sportcenter_deletion_qa WITH (FORCE)');await admin.query('CREATE DATABASE sportcenter_deletion_qa');}finally{await admin.end();}
      command('pg_restore',['-h','127.0.0.1','-p',String(metadata.port),'-U',USER,'-d',DB,'--no-owner','--exit-on-error',archive],{env:{...env,PGPASSWORD:'qa-admin-local'},timeout:45000});
      client=new Client(connection(metadata.port));await client.connect();source=createSource();await source.initialize();setup();
    };
    if(process.argv[2]==='expiry-only'){
      const before=backupDatabase('pre-expiry-synthetic.dump');report.restoreArchiveSha256=before.sha256;
      const user=(await client.query('SELECT u.fecha_creacion,a.account_id FROM core.users u JOIN core.account_deletion_accounts a ON a.user_id=u.id_usuario WHERE u.id_usuario=710104')).rows[0];
      const operationId='76000000-0000-4000-8000-000000710104',until=new Date(Date.now()-86400000).toISOString();
      const intent={operationId,accountId:user.account_id,legacyUserId:710104,legacyFingerprint:new DeletionSecrets(config).hash('legacy','710104',new Date(user.fecha_creacion).toISOString())};
      await ledger.recordIntent(intent);await ledger.recordRetention(operationId,{until,basisHash:new DeletionSecrets(config).hash('retention-basis',operationId,'Synthetic QA prior legal-basis decision'),categories:['orders','payments','returns']});await ledger.markCompleted(operationId);
      const reconcile=async()=>{await gate.reconcileBeforeServing(record=>service.replay(record));gate.assertApplicationReady();};
      const assertExpired=async()=>{
        const retention=(await client.query('SELECT retain_until,identifiers_expired_at FROM core.account_deletion_retention WHERE request_id=$1',[operationId])).rows[0];assert.ok(retention);assert.equal(new Date(retention.retain_until).toISOString(),until);assert.ok(retention.identifiers_expired_at);
        const payment=(await client.query('SELECT referencia_externa,monto,estado FROM core.pagos WHERE id_pago=710104')).rows[0];assert.equal(payment.referencia_externa,'deleted:710104');assert.equal(payment.monto,'100.00');assert.equal(payment.estado,'approved');
        const shipment=(await client.query('SELECT numero_guia,paqueteria,codigo_confirmacion_entrega FROM core.shipments WHERE id_envio=710104')).rows[0];assert.equal(shipment.numero_guia,null);assert.equal(shipment.paqueteria,null);assert.equal(shipment.codigo_confirmacion_entrega,null);
        assert.equal((await client.query('SELECT state FROM core.account_deletion_accounts WHERE user_id=710104')).rows[0].state,'deleted');assert.equal((await client.query('SELECT email FROM core.users WHERE id_usuario=710104')).rows[0].email,null);
      };
      await reconcile();await service.expireRetainedRecords();await assertExpired();checked('expired-retention-deadline-from-durable-ledger-scrubs-commercial-identifiers-not-amounts');
      await service.expireRetainedRecords();await assertExpired();checked('retention-expiry-worker-is-idempotent');
      await restoreDatabase(before.archive);assert.equal((await client.query('SELECT referencia_externa FROM core.pagos WHERE id_pago=710104')).rows[0].referencia_externa,'synthetic-qa-reference');
      await reconcile();await service.expireRetainedRecords();await assertExpired();checked('restored-backup-cannot-extend-expired-deadline-or-resurrect-commercial-identifiers');
      const retained=(await ledger.verifyAndRead()).intents.find(record=>record.operationId===operationId);assert.equal(retained.retention.until,until);
      assert.deepEqual(hashes(),frozen,'SOURCE_CHANGED_DURING_INDEPENDENT_TEST');report.status='passed';return;
    }
    if(process.argv[2]==='nest-only'){
      const {Test}=deps('@nestjs/testing'),{TypeOrmModule}=deps('@nestjs/typeorm'),{ConfigModule}=deps('@nestjs/config'),{ValidationPipe}=deps('@nestjs/common');
      const {UserSession}=require(path.join(SOURCE,'src/modules/users/entities/user-session.entity.ts')),{Roles}=require(path.join(SOURCE,'src/modules/users/entities/roles.entity.ts'));
      const {UsersModule}=require(path.join(SOURCE,'src/modules/users/users.module.ts')),{AccountDeletionModule}=require(path.join(SOURCE,'src/modules/account-deletion/account-deletion.module.ts'));
      const {AccountDeletionBootstrapService}=require(path.join(SOURCE,'src/modules/account-deletion/account-deletion-bootstrap.service.ts')),{DeletionRecoveryGuard}=require(path.join(SOURCE,'src/modules/account-deletion/account-deletion.guards.ts'));
      const {MailService}=require(path.join(SOURCE,'src/services/mail/mail.service.ts')),{DELETION_LEDGER}=require(path.join(SOURCE,'src/modules/account-deletion/account-deletion.service.ts'));
      const bcrypt=deps('bcrypt');
      await client.query('UPDATE core.users SET passw=$2 WHERE id_usuario=$1',[710112,await bcrypt.hash('QAonly!Deletion2026',4)]);
      let app;
      try{
        const imports=[ConfigModule.forRoot({isGlobal:true,ignoreEnvFile:true,ignoreEnvVars:true,load:[()=>configValues]}),...['adminConnection','editorConnection','readerConnection'].map((name,index)=>TypeOrmModule.forRoot({name,type:'postgres',host:'127.0.0.1',port:metadata.port,database:DB,username:[USER,'qa_editor','qa_reader'][index],password:['qa-admin-local','qa-editor-local','qa-reader-local'][index],ssl:false,entities:[User,UserSession,Roles],synchronize:false,logging:false,retryAttempts:0,extra:{max:3,statement_timeout:15000}})),UsersModule,AccountDeletionModule];
        const module=await Test.createTestingModule({imports}).overrideProvider(MailService).useValue(mail).overrideProvider(DELETION_LEDGER).useValue(ledger).compile();
        app=module.createNestApplication({logger:false});app.useGlobalPipes(new ValidationPipe({whitelist:true,forbidNonWhitelisted:true,transform:true}));app.useGlobalGuards(app.get(DeletionRecoveryGuard));
        await app.get(AccountDeletionBootstrapService).prepare();await app.init();await app.listen(0,'127.0.0.1');
        checked('real-Nest-UsersModule-AccountDeletionModule-three-role-DataSources-compile-prepare-init');
        const origin='http://127.0.0.1:'+app.getHttpServer().address().port;
        const call=(method,url,body,headers={})=>new Promise((resolve,reject)=>{const bytes=body===undefined?null:Buffer.from(JSON.stringify(body));const req=require('node:http').request(new URL(url,origin),{method,headers:{Accept:'application/json',...(bytes?{'Content-Type':'application/json','Content-Length':bytes.length}:{}),...headers}},res=>{const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>{try{const text=Buffer.concat(chunks).toString('utf8');resolve({status:res.statusCode,headers:res.headers,body:text?JSON.parse(text):null});}catch(error){reject(error);}});});req.on('error',reject);if(bytes)req.write(bytes);req.end();});
        const login=await call('POST','/users/login-user',{email:'deletion-710112@qa.invalid',passw:'QAonly!Deletion2026',deviceName:'Independent synthetic QA'});assert.equal(login.status,201);assert.ok(login.body.accessToken);assert.ok(login.body.refreshToken);
        const bearer={Authorization:'Bearer '+login.body.accessToken};const cookies=login.headers['set-cookie'].map(value=>value.split(';')[0]).join('; ');
        assert.equal((await call('GET','/users/profile',undefined,{...bearer,Cookie:'sc_access_token=stale-invalid-qa-cookie'})).status,200);
        checked('valid-Bearer-authentication-takes-priority-over-a-stale-invalid-cookie');
        const requested=await call('POST','/users/account-deletion/requests',{},bearer);assert.equal(requested.status,201);assert.equal(requested.body.status,'received');assert.equal(requested.headers['cache-control'],'no-store');
        const requestId=requested.body.requestId;
        const verified=await call('POST','/users/account-deletion/requests/'+requestId+'/verify',{code:mail.codes.at(-1).code},{Cookie:cookies,Origin:'http://localhost:4200'});assert.equal(verified.status,201);assert.equal(verified.body.status,'identity_verified');
        const confirmed=await call('POST','/users/account-deletion/requests/'+requestId+'/confirm',{confirmationToken:verified.body.confirmationToken,confirmed:true},bearer);assert.equal(confirmed.status,201);assert.equal(confirmed.body.status,'completed');assert.ok(confirmed.headers['set-cookie'].some(value=>value.startsWith('sc_access_token=;')));
        assert.equal((await call('GET','/users/profile',undefined,bearer)).status,401);
        const refreshed=await call('POST','/users/refresh-token',{refreshToken:login.body.refreshToken});assert.ok(refreshed.status===401||refreshed.status===400);
        const result=await call('POST','/users/account-deletion/requests/'+requestId+'/result',{receiptToken:requested.body.receiptToken});assert.equal(result.status,201);assert.equal(result.body.status,'completed');
        assert.equal((await client.query('SELECT count(*)::int count FROM core.user_sessions WHERE id_usuario=710112')).rows[0].count,0);
        checked('real-HTTP-login-Bearer-request-cookie-OTP-confirm-receipt-session-and-refresh-revoked');
      }finally{if(app)await app.close();}
      assert.deepEqual(hashes(),frozen,'SOURCE_CHANGED_DURING_INDEPENDENT_TEST');report.status='passed';return;
    }
    if(restoreOnly){
      const restoredOldRequest=await service.request(principal(710101));
      const archive=path.join(run,'pre-deletion-synthetic.dump');
      const dump=command('pg_dump',['-h','127.0.0.1','-p',String(metadata.port),'-U',USER,'-d',DB,'--format=custom','--no-owner'],{env:{...env,PGPASSWORD:'qa-admin-local'},encoding:null,maxBuffer:32*1024*1024});
      fs.writeFileSync(archive,dump,{flag:'wx',mode:0o600});report.restoreArchiveSha256=sha(dump);
      await client.query("UPDATE core.account_deletion_requests SET requested_at=clock_timestamp()-interval '61 seconds' WHERE request_id=$1",[restoredOldRequest.requestId]);
      const a=await requestAndVerify(710101),aResult=await service.confirm(principal(710101),a.req.requestId,a.grant.confirmationToken,true);assert.equal(aResult.status,'completed');
      assert.notEqual(a.req.requestId,restoredOldRequest.requestId);
      const p=await requestAndVerify(710103),pResult=await service.confirm(principal(710103),p.req.requestId,p.grant.confirmationToken,true);assert.equal(pResult.status,'requires_attention');assert.equal(pResult.reason,'pending_orders');
      const beforeRestore=await ledger.verifyAndRead();assert.equal(beforeRestore.intents.find(item=>item.operationId===a.req.requestId).completed,true);assert.equal(beforeRestore.intents.find(item=>item.operationId===p.req.requestId).completed,false);
      checked('custom-database-backup-precedes-completed-and-still-pending-deletion-intents');
      await source.destroy();await client.end();client=null;
      const admin=new Client({...connection(metadata.port),database:'postgres'});await admin.connect();
      try{
        const target=(await admin.query("SELECT host(inet_server_addr()) host,inet_server_port() port,current_setting('data_directory') directory")).rows[0];assert.equal(target.host,'127.0.0.1');assert.equal(target.port,metadata.port);assert.equal(path.resolve(target.directory),path.resolve(metadata.dataDirectory));
        // Only the fixed disposable database in this newly initialized cluster.
        await admin.query('DROP DATABASE sportcenter_deletion_qa WITH (FORCE)');await admin.query('CREATE DATABASE sportcenter_deletion_qa');
      }finally{await admin.end();}
      command('pg_restore',['-h','127.0.0.1','-p',String(metadata.port),'-U',USER,'-d',DB,'--no-owner','--exit-on-error',archive],{env:{...env,PGPASSWORD:'qa-admin-local'},timeout:45000});
      client=new Client(connection(metadata.port));await client.connect();source=createSource();await source.initialize();setup();
      assert.equal((await client.query('SELECT email FROM core.users WHERE id_usuario=710101')).rows[0].email,'deletion-710101@qa.invalid');
      assert.throws(()=>gate.assertApplicationReady(),/RECOVERY_NOT_READY/);
      await gate.reconcileBeforeServing(intent=>service.replay(intent));gate.assertApplicationReady();
      assert.equal((await client.query('SELECT email FROM core.users WHERE id_usuario=710101')).rows[0].email,null);
      assert.equal((await client.query('SELECT state FROM core.account_deletion_accounts WHERE user_id=710101')).rows[0].state,'deleted');
      assert.equal((await client.query('SELECT count(*)::int count FROM core.user_sessions WHERE id_usuario=710101')).rows[0].count,0);
      const pendingAfter=(await client.query('SELECT r.status,r.reason,a.state FROM core.account_deletion_requests r JOIN core.account_deletion_accounts a ON a.user_id=r.user_id WHERE r.request_id=$1',[p.req.requestId])).rows[0];
      assert.equal(pendingAfter.status,'requires_attention');assert.equal(pendingAfter.reason,'pending_orders');assert.equal(pendingAfter.state,'deleting');
      assert.equal((await client.query('SELECT count(*)::int count FROM core.user_sessions WHERE id_usuario=710103 AND revocada_en IS NULL')).rows[0].count,0);
      const afterRestore=await ledger.verifyAndRead();assert.equal(afterRestore.intents.find(item=>item.operationId===p.req.requestId).completed,false);
      checked('restoring-older-database-cannot-resurrect-completed-account-or-pending-access');
      checked('pending-restored-case-is-restricted-without-falsely-completing-ledger');
      const invalidOld=(await client.query('SELECT status,code_hash,authorization_hash FROM core.account_deletion_requests WHERE request_id=$1',[restoredOldRequest.requestId])).rows[0];assert.equal(invalidOld.status,'error');assert.equal(invalidOld.code_hash,null);assert.equal(invalidOld.authorization_hash,null);
      checked('older-restored-OTP-request-is-invalidated-before-later-ledger-operation-is-replayed');
      const crashUser=(await client.query('SELECT u.fecha_creacion,a.account_id FROM core.users u JOIN core.account_deletion_accounts a ON a.user_id=u.id_usuario WHERE u.id_usuario=710108')).rows[0];
      const crashIntent={operationId:'74000000-0000-4000-8000-000000710108',accountId:crashUser.account_id,legacyUserId:710108,legacyFingerprint:new DeletionSecrets(config).hash('legacy','710108',new Date(crashUser.fecha_creacion).toISOString())};
      await ledger.recordIntent(crashIntent);
      const crashGate=new DeletionRecoveryGate(true,ledger);await crashGate.reconcileBeforeServing(intent=>service.replay(intent));crashGate.assertApplicationReady();
      assert.equal((await client.query('SELECT state FROM core.account_deletion_accounts WHERE user_id=710108')).rows[0].state,'deleted');
      checked('durable-intent-before-database-commit-replays-after-simulated-crash');
      const originalIntent=(await ledger.verifyAndRead()).intents.find(item=>item.operationId===a.req.requestId);
      await assert.rejects(service.replay({...originalIntent,operationId:'75000000-0000-4000-8000-000000710109',legacyUserId:710109}),/IDENTITY_MISMATCH/);
      assert.equal((await client.query('SELECT email FROM core.users WHERE id_usuario=710109')).rows[0].email,'deletion-710109@qa.invalid');
      checked('recovery-does-not-erase-an-unrelated-reused-or-mismatched-identity');
      const absentId=990001;
      await ledger.recordIntent({operationId:'77000000-0000-4000-8000-000000990001',accountId:'78000000-0000-4000-8000-000000990001',legacyUserId:absentId,legacyFingerprint:'f'.repeat(64)});await ledger.markCompleted('77000000-0000-4000-8000-000000990001');
      const sequenceGate=new DeletionRecoveryGate(true,ledger);await sequenceGate.reconcileBeforeServing(record=>service.replay(record));sequenceGate.assertApplicationReady();
      const newIdentity=(await client.query("INSERT INTO core.users(nombre,\"aPaterno\",\"aMaterno\",email,passw,rol,activo,email_verified) VALUES('QA fresh','Synthetic','Local','fresh-sequence@qa.invalid','qa-only',1,1,1) RETURNING id_usuario")).rows[0].id_usuario;
      assert.ok(newIdentity>absentId);assert.equal((await client.query('SELECT state FROM core.account_deletion_accounts WHERE user_id=$1',[newIdentity])).rows[0].state,'active');
      checked('absent-retired-legacy-user-ID-raises-sequence-floor-and-is-not-reused-by-registration');
      const missingDir=path.join(run,'missing-ledger');fs.mkdirSync(missingDir,{mode:0o700});provisionPrivateDirectory(missingDir);
      const missingLedger=new FileDeletionLedger({directory:missingDir,repositoryRoot:SOURCE,hmacKey:randomBytes(32)}),missingGate=new DeletionRecoveryGate(true,missingLedger);
      await assert.rejects(missingGate.reconcileBeforeServing(async()=> 'completed'),/RECOVERY_FAILED/);assert.equal(missingGate.state,'closed');assert.deepEqual(fs.readdirSync(missingDir),[]);
      checked('missing-external-ledger-closes-traffic-and-is-never-silently-provisioned');
      assert.deepEqual(hashes(),frozen,'SOURCE_CHANGED_DURING_INDEPENDENT_TEST');report.status='passed';return;
    }
    const first=await service.request(principal(710101)),firstCode=mail.codes.at(-1).code;
    assert.equal(mail.codes.at(-1).email,'deletion-710101@qa.invalid');
    const stored=(await client.query('SELECT code_hash,authorization_hash,status FROM core.account_deletion_requests WHERE request_id=$1',[first.requestId])).rows[0];
    assert.match(stored.code_hash,/^[0-9a-f]{64}$/);assert.notEqual(stored.code_hash,firstCode);assert.equal(stored.authorization_hash,null);assert.equal(stored.status,'received');
    await assert.rejects(service.verify(principal(710108),first.requestId,firstCode),error=>error.getStatus()===404);
    const otherSession={...principal(710101),sessionId:'72000000-0000-4000-8000-000000710101'};
    await assert.rejects(service.verify(otherSession,first.requestId,firstCode),error=>error.getStatus()===404);
    checked('OTP-purpose-hash-bound-to-owner-and-requesting-session');
    const grant=await service.verify(principal(710101),first.requestId,firstCode);
    await assert.rejects(service.verify(principal(710101),first.requestId,firstCode),error=>error.getStatus()===409);
    await assert.rejects(service.confirm(principal(710101),first.requestId,grant.confirmationToken,false),error=>error.getStatus()===400);
    assert.equal((await client.query('SELECT state FROM core.account_deletion_accounts WHERE user_id=710101')).rows[0].state,'active');
    checked('verify-consumes-code-without-deleting-and-final-confirmation-required');
    const moderationBefore=JSON.parse((await client.query('SELECT row_to_json(e)::text value FROM core.review_moderation_events e WHERE id_review=710101')).rows[0].value);
    const confirmed=await service.confirm(principal(710101),first.requestId,grant.confirmationToken,true);
    assert.equal(confirmed.status,'completed');
    const completed=await service.process(first.requestId);
    assert.equal(completed.status,'completed');assert.equal(completed.notification,'sent');
    const user=(await client.query('SELECT * FROM core.users WHERE id_usuario=710101')).rows[0];
    assert.equal(user.activo,0);assert.equal(user.email,null);assert.equal(user.telefono,null);assert.equal(user.google_id,null);assert.equal(user.token_verificacion,null);assert.equal(user.nombre,'Cuenta eliminada');assert.match(user.passw,/^!deleted:/);
    for(const table of ['user_sessions','carts','user_payment_methods','direcciones'])assert.equal((await client.query('SELECT count(*)::int count FROM core.'+table+' WHERE id_usuario=710101')).rows[0].count,0);
    assert.equal((await client.query('SELECT count(*)::int count FROM core.cart_items WHERE id_carrito=710101')).rows[0].count,0);
    assert.equal((await client.query('SELECT comentario FROM core.reviews WHERE id_usuario=710101')).rows[0].comentario,'Contenido eliminado por su autor');
    const moderationAfter=JSON.parse((await client.query('SELECT row_to_json(e)::text value FROM core.review_moderation_events e WHERE id_review=710101')).rows[0].value);
    assert.equal(moderationAfter.motivo,'Contenido eliminado por su titular');delete moderationBefore.motivo;delete moderationAfter.motivo;assert.deepEqual(moderationAfter,moderationBefore);
    await assert.rejects(client.query("UPDATE core.review_moderation_events SET motivo='changed' WHERE id_review=710101"),error=>error.code==='42501');
    for(const schema of ['core','public']){const contact=(await client.query('SELECT nombre,email,telefono,mensaje FROM '+schema+'.contact_messages WHERE id_mensaje=710101')).rows[0];assert.equal(contact.email,'');assert.equal(contact.telefono,null);assert.equal(contact.nombre,'Cuenta eliminada');assert.equal(contact.mensaje,'Contenido eliminado por su titular');}
    assert.equal((await service.result(first.requestId,first.receiptToken)).status,'completed');
    await assert.rejects(service.result(first.requestId,'incorrect-receipt'),error=>error.getStatus()===404);
    await assert.rejects(service.confirm(principal(710101),first.requestId,grant.confirmationToken,true),error=>error.getStatus()===401);
    const notification=(await client.query('SELECT encrypted_recipient FROM core.account_deletion_notifications WHERE request_id=$1',[first.requestId])).rows[0];assert.equal(notification.encrypted_recipient,null);
    checked('real-delete-personal-data-all-sessions-carts-methods-contacts-and-reviews-with-FKs-intact');
    checked('moderation-identities-actions-revisions-preserved-while-personal-reason-scrubbed-and-ordinary-writes-still-blocked');
    checked('opaque-receipt-recovers-result-after-auth-revocation-and-double-confirm-cannot-repeat');
    // Exhaustion and expiry are server-enforced, not browser-only timers.
    const exhausted=await service.request(principal(710102)),actual=mail.codes.at(-1).code,wrong=actual==='000000'?'111111':'000000';
    for(let n=0;n<5;n++)await assert.rejects(service.verify(principal(710102),exhausted.requestId,wrong),error=>error.getStatus()===400);
    const exhaustedState=(await client.query('SELECT status,attempts,code_hash FROM core.account_deletion_requests WHERE request_id=$1',[exhausted.requestId])).rows[0];assert.equal(exhaustedState.status,'error');assert.equal(exhaustedState.attempts,5);assert.equal(exhaustedState.code_hash,null);
    await assert.rejects(service.verify(principal(710102),exhausted.requestId,actual),error=>error.getStatus()===409);
    const expired=await service.request(principal(710105)),expiredCode=mail.codes.at(-1).code;
    await client.query("UPDATE core.account_deletion_requests SET code_expires_at=clock_timestamp()-interval '1 second' WHERE request_id=$1",[expired.requestId]);
    await assert.rejects(service.verify(principal(710105),expired.requestId,expiredCode),error=>error.getStatus()===400);
    assert.equal((await client.query('SELECT state FROM core.account_deletion_accounts WHERE user_id=710105')).rows[0].state,'active');
    checked('five-wrong-attempts-lock-code-and-expiry-never-deletes-account');
    // Pending orders revoke access but must not be reported as completed.
    const pending=await requestAndVerify(710103);const pendingResult=await service.confirm(principal(710103),pending.req.requestId,pending.grant.confirmationToken,true);
    assert.equal(pendingResult.status,'requires_attention');assert.equal(pendingResult.reason,'pending_orders');
    assert.equal((await client.query('SELECT count(*)::int count FROM core.user_sessions WHERE id_usuario=710103 AND revocada_en IS NULL')).rows[0].count,0);
    const stillPending=await service.process(pending.req.requestId,{basis:'Synthetic QA basis',days:30});assert.equal(stillPending.status,'requires_attention');
    await client.query("UPDATE core.orders SET estado='cancelado' WHERE id_orden=710103");
    assert.equal((await service.process(pending.req.requestId,{basis:'Synthetic QA basis',days:30})).status,'completed');
    checked('pending-order-exception-holds-completion-and-admin-can-resume-after-resolution');
    const paid=await requestAndVerify(710104);
    const financialBefore=(await client.query('SELECT row_to_json(p)::text value FROM core.pagos p WHERE id_orden=710104')).rows[0].value;
    const paidResult=await service.confirm(principal(710104),paid.req.requestId,paid.grant.confirmationToken,true);assert.equal(paidResult.reason,'retention_policy_required');
    assert.equal((await service.process(paid.req.requestId,{basis:'Synthetic QA basis for orders and payments; not a legal production period',days:30})).status,'completed');
    assert.equal((await client.query('SELECT row_to_json(p)::text value FROM core.pagos p WHERE id_orden=710104')).rows[0].value,financialBefore);
    const retained=(await client.query('SELECT basis,retain_until,categories FROM core.account_deletion_retention WHERE request_id=$1',[paid.req.requestId])).rows[0];assert.ok(retained.basis.includes('Synthetic QA'));assert.ok(new Date(retained.retain_until)>new Date());assert.ok(retained.categories.includes('payments'));
    const address=(await client.query('SELECT calle,numero,ciudad FROM core.direcciones WHERE id_direccion=710104')).rows[0];assert.equal(address.calle,'');assert.equal(address.numero,'');assert.equal(address.ciudad,'');
    for(const [table,fields]of [['returns',['motivo','descripcion','resolucion']],['return_items',['motivo']],['return_events',['comentario']]]){
      const records=(await client.query('SELECT '+fields.join(',')+' FROM core.'+table+' WHERE id_devolucion=710104')).rows;assert.equal(records.length,1);
      for(const value of Object.values(records[0]))assert.ok(!String(value).includes('QA private'),'RETURN_PERSONAL_TEXT_NOT_SCRUBBED');
    }
    checked('financial-records-and-FKs-retained-with-explicit-test-basis-and-personal-address-scrubbed');
    checked('returns-items-and-events-personal-free-text-scrubbed-with-financial-links-intact');
    const pendingReturn=await requestAndVerify(710113);
    const pendingReturnResult=await service.confirm(principal(710113),pendingReturn.req.requestId,pendingReturn.grant.confirmationToken,true);
    assert.equal(pendingReturnResult.status,'requires_attention');assert.equal(pendingReturnResult.reason,'pending_returns');
    const preservedAddress=(await client.query('SELECT calle,numero FROM core.direcciones WHERE id_direccion=710113')).rows[0];assert.equal(preservedAddress.calle,'Calle sintetica devolucion');assert.equal(preservedAddress.numero,'13');
    await client.query("UPDATE core.account_deletion_requests SET receipt_expires_at=clock_timestamp()-interval '1 second' WHERE request_id=$1",[pendingReturn.req.requestId]);
    await client.query("UPDATE core.account_deletion_notifications SET expires_at=clock_timestamp()-interval '1 second' WHERE request_id=$1",[pendingReturn.req.requestId]);
    await service.retryNotifications();
    assert.equal((await service.result(pendingReturn.req.requestId,pendingReturn.req.receiptToken)).status,'requires_attention');
    await client.query("UPDATE core.returns SET estado='completada' WHERE id_devolucion=710113");
    const completedReturn=await service.process(pendingReturn.req.requestId,{basis:'Synthetic QA retention basis after closed return',days:30});assert.equal(completedReturn.status,'completed');assert.equal(completedReturn.notification,'sent');
    assert.equal((await service.result(pendingReturn.req.requestId,pendingReturn.req.receiptToken)).status,'completed');
    const finalizedAddress=(await client.query('SELECT calle,numero FROM core.direcciones WHERE id_direccion=710113')).rows[0];assert.equal(finalizedAddress.calle,'');assert.equal(finalizedAddress.numero,'');
    checked('pending-return-preserves-necessary-address-of-delivered-order-until-resolution-then-scrubs-it');
    checked('long-pending-case-keeps-receipt-followup-and-final-result-email-after-old-notification-expires');
    // Stable verified identity must not follow an attacker-controlled profile email.
    await client.query("UPDATE core.users SET email='changed-contact@qa.invalid',email_verified=1 WHERE id_usuario=710107");
    const anchored=await service.request(principal(710107));assert.equal(mail.codes.at(-1).email,'deletion-710107@qa.invalid');
    await service.verify(principal(710107),anchored.requestId,mail.codes.at(-1).code);
    checked('OTP-delivery-stays-on-original-verified-identity-after-profile-email-change');
    const resend=await service.request(principal(710109));await assert.rejects(service.request(principal(710109)),error=>error.getStatus()===409);
    await client.query("UPDATE core.account_deletion_requests SET requested_at=clock_timestamp()-interval '61 seconds' WHERE request_id=$1",[resend.requestId]);
    const resent=await service.request(principal(710109));assert.notEqual(resent.requestId,resend.requestId);
    assert.equal((await client.query('SELECT status,reason FROM core.account_deletion_requests WHERE request_id=$1',[resend.requestId])).rows[0].reason,'replaced');
    checked('server-resend-cooldown-and-old-code-challenge-replacement');
    mail.failCode=true;await assert.rejects(service.request(principal(710110)),error=>error.getStatus()===503);
    assert.equal((await client.query('SELECT state FROM core.account_deletion_accounts WHERE user_id=710110')).rows[0].state,'active');
    const failedDelivery=(await client.query('SELECT status,reason FROM core.account_deletion_requests WHERE user_id=710110')).rows[0];assert.equal(failedDelivery.reason,'code_delivery_failed');
    checked('code-delivery-failure-is-real-error-without-destructive-side-effects');
    const retry=await requestAndVerify(710111);mail.failResult=true;
    const retryResult=await service.confirm(principal(710111),retry.req.requestId,retry.grant.confirmationToken,true);assert.equal(retryResult.status,'completed');assert.equal(retryResult.notification,'pending');
    await service.retryNotifications();assert.equal((await service.result(retry.req.requestId,retry.req.receiptToken)).notification,'sent');
    checked('result-mail-failure-does-not-undo-deletion-and-retry-clears-recipient');
    // Additional personal columns must stop completion instead of being ignored.
    await client.query('ALTER TABLE core.users ADD COLUMN extra_personal text');
    const unexpected=await requestAndVerify(710112);const unexpectedResult=await service.confirm(principal(710112),unexpected.req.requestId,unexpected.grant.confirmationToken,true);
    assert.equal(unexpectedResult.status,'requires_attention');assert.equal(unexpectedResult.reason,'schema_review_required');
    checked('unknown-personal-column-prevents-false-completion');
    await client.query('ALTER TABLE core.users DROP COLUMN extra_personal');
    // Unknown schema with an otherwise familiar table name must fail closed.
    await client.query('CREATE SCHEMA qa_unknown; CREATE TABLE qa_unknown.orders(owner_id integer REFERENCES core.users(id_usuario))');
    const unknown=await requestAndVerify(710106);const unknownResult=await service.confirm(principal(710106),unknown.req.requestId,unknown.grant.confirmationToken,true);
    assert.equal(unknownResult.status,'requires_attention');assert.equal(unknownResult.reason,'schema_review_required');
    assert.notEqual((await client.query('SELECT email FROM core.users WHERE id_usuario=710106')).rows[0].email,null);
    checked('unknown-FK-even-with-known-name-in-other-schema-prevents-false-completion');
    const snapshot=await ledger.verifyAndRead();assert.ok(snapshot.intents.some(item=>item.operationId===first.requestId&&item.completed));
    const ledgerText=fs.readFileSync(path.join(ledgerDir,'deletions.jsonl'),'utf8');assert.ok(!ledgerText.includes('@qa.invalid'));assert.ok(!ledgerText.includes(first.receiptToken));assert.ok(!ledgerText.includes(firstCode));
    checked('external-ledger-persists-keyed-non-PII-intents-without-code-receipt-or-email');
    assert.deepEqual(hashes(),frozen,'SOURCE_CHANGED_DURING_INDEPENDENT_TEST');
    report.status='passed';
  }catch(error){report.errorCode=String(error.code||error.name||'ERROR');fs.writeFileSync(path.join(run,'service-failure-private.log'),String(error.stack||error)+'\n',{flag:'wx',mode:0o600});throw error;}
  finally{if(source?.isInitialized)await source.destroy().catch(()=>{});if(client)await client.end().catch(()=>{});if(started)try{command('pg_ctl',['-D',metadata.dataDirectory,'-m','fast','-w','-t','15','stop'],{stdio:'ignore',timeout:20000});report.stopped=true;}catch{report.stopped=false;}save(path.join(run,'service-integration-result.json'),report);process.stdout.write(JSON.stringify({run,status:report.status,checks:report.checks.length,stopped:report.stopped})+'\n');}
}
main().catch(()=>{process.stderr.write('INDEPENDENT_SERVICE_QA_FAILED_PRIVATE_LOG_SAVED\n');process.exitCode=1;});
