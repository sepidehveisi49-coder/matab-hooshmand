const express=require("express"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const app=express(),PORT=Number(process.env.PORT||3000),HOST="0.0.0.0";
const DATA_DIR=process.env.MATAB_DATA_DIR||__dirname;
const DATA=path.join(DATA_DIR,"data.json"),BACKUPS=path.join(DATA_DIR,"backups"),sessions=new Map(),attempts=new Map();
app.disable("x-powered-by");
app.use((q,s,n)=>{s.setHeader("X-Content-Type-Options","nosniff");s.setHeader("X-Frame-Options","DENY");s.setHeader("Cache-Control","no-store");n()});
app.use(express.json({limit:"100kb"}));app.get("/health",(q,s)=>s.json({ok:true,service:"matab-hooshmand"}));app.use(express.static(path.join(__dirname,"public")));
const clean=(v,n=200)=>String(v??"").trim().slice(0,n),safe=u=>({id:u.id,username:u.username,name:u.name,role:u.role,active:u.active!==false});
function hash(p){const salt=crypto.randomBytes(16).toString("hex");return {salt,hash:crypto.scryptSync(String(p),salt,64).toString("hex")}}
function verify(p,u){if(!u.passwordHash)return false;const a=crypto.scryptSync(String(p),u.passwordSalt,64),b=Buffer.from(u.passwordHash,"hex");return a.length===b.length&&crypto.timingSafeEqual(a,b)}
function save(db){fs.mkdirSync(DATA_DIR,{recursive:true});fs.mkdirSync(BACKUPS,{recursive:true});if(fs.existsSync(DATA)){const stamp=new Date().toISOString().replace(/[:.]/g,"-");fs.copyFileSync(DATA,path.join(BACKUPS,"data-"+stamp+".json"));const old=fs.readdirSync(BACKUPS).filter(x=>x.endsWith(".json")).sort();while(old.length>20)fs.unlinkSync(path.join(BACKUPS,old.shift()))}const tmp=DATA+".tmp";fs.writeFileSync(tmp,JSON.stringify(db,null,2),{encoding:"utf8",mode:0o600});fs.renameSync(tmp,DATA)}
function load(){if(!fs.existsSync(DATA)){const p=process.env.MATAB_ADMIN_PASSWORD;if(!p||p.length<10)throw Error("برای نصب تازه، رمز مدیر را با MATAB_ADMIN_PASSWORD (حداقل ۱۰ نویسه) تنظیم کنید؛ راهنما را بخوانید.");const h=hash(p),clinic={id:"clinic_default",name:"مطب اصلی",active:true,createdAt:new Date().toISOString()},db={clinics:[clinic],users:[{id:1,username:"admin",name:"مدیر سامانه",role:"admin",active:true,clinicIds:[clinic.id],activeClinicId:clinic.id,passwordSalt:h.salt,passwordHash:h.hash}],patients:[],appointments:[]};save(db);return db}
const db=JSON.parse(fs.readFileSync(DATA,"utf8"));db.users||=[];db.patients||=[];db.appointments||=[];db.clinics||=[];let changed=false;
if(db.clinics.length===0){db.clinics.push({id:"clinic_default",name:"مطب اصلی",active:true,createdAt:new Date().toISOString()});changed=true}
for(const u of db.users){if(u.role!=="superadmin"&&(!Array.isArray(u.clinicIds)||u.clinicIds.length===0)){u.clinicIds=[db.clinics[0].id];u.activeClinicId=db.clinics[0].id;changed=true}}
for(const u of db.users){if(u.password&&!u.passwordHash){const h=hash(u.password);u.passwordSalt=h.salt;u.passwordHash=h.hash;delete u.password;changed=true}if(u.active===undefined){u.active=true;changed=true}}
if(changed){const tmp=DATA+".migration.tmp";fs.writeFileSync(tmp,JSON.stringify(db,null,2),{mode:0o600});fs.renameSync(tmp,DATA)}return db}
function sessionFingerprint(u){
  const memberships=Array.isArray(u.clinicIds)?u.clinicIds.map(String).sort():[];
  const securityState=[
    String(u.passwordSalt||""),
    String(u.passwordHash||""),
    String(u.role||""),
    u.active!==false,
    String(u.activeClinicId??""),
    memberships
  ];
  return crypto.createHash("sha256").update(JSON.stringify(securityState)).digest("hex");
}
function auth(q,s,n){
  const token=(q.headers.authorization||"").replace(/^Bearer\s+/i,"");
  const ss=sessions.get(token);

  if(!ss||ss.exp<Date.now()){
    sessions.delete(token);
    return s.status(401).json({error:"لطفاً دوباره وارد شوید."});
  }

  const db=load();
  const u=db.users.find(x=>x.id===ss.uid&&x.active!==false);

  if(!u){
    sessions.delete(token);
    return s.status(401).json({error:"حساب غیرفعال است."});
  }

  if(!ss.fp||ss.fp!==sessionFingerprint(u)){
    sessions.delete(token);
    return s.status(401).json({error:"اطلاعات امنیتی حساب تغییر کرده است؛ دوباره وارد شوید."});
  }

  q.user=u;
  q.db=db;
  q.token=token;
  q.clinicId=null;
  q.clinic=null;

  if(u.role!=="superadmin"){
    const memberships=Array.isArray(u.clinicIds)?u.clinicIds:[];
    const clinicId=u.activeClinicId;

    if(!clinicId||!memberships.some(id=>String(id)===String(clinicId))){
      return s.status(403).json({error:"مطب فعال یا عضویت معتبر نیست."});
    }

    const clinic=(db.clinics||[]).find(c=>
      String(c.id)===String(clinicId)&&c.active!==false
    );

    if(!clinic){
      return s.status(403).json({error:"مطب فعال پیدا نشد یا غیرفعال است."});
    }

    q.clinicId=clinic.id;
    q.clinic=clinic;
  }

  ss.exp=Date.now()+43200000;
  n();
}

/* MATAB_TENANT_CONTEXT_V1 */
function clinicContext(q,s,n){
  if(q.user.role==="superadmin"||!q.clinicId){
    return s.status(403).json({error:"دسترسی به پنل مطب مجاز نیست."});
  }
  n();
}

/* MATAB_API_ISOLATION_V1 */
function clinicRows(rows,q){
  return rows.filter(r=>
    String(r.clinic_id??r.clinicId??"")===String(q.clinicId)
  );
}
const admin=(q,s,n)=>q.user.role==="admin"?n():s.status(403).json({error:"دسترسی مدیر لازم است."});
/* MATAB_ROLE_SECURITY_V1 */
const allowRoles=(...roles)=>(q,s,n)=>roles.includes(q.user.role)?n():s.status(403).json({error:"شما مجوز انجام این عملیات را ندارید."});
/* MATAB_FINANCE_FILTER_V1 */
const visibleAppointments=(rows,user)=>user.role==="admin"?rows:rows.map(({amount,paymentStatus,...a})=>a);
app.post("/api/login",(q,s)=>{const ip=q.ip||"unknown",a=attempts.get(ip)||{n:0,until:0};if(a.until>Date.now())return s.status(429).json({error:"تلاش زیاد؛ ۱۰ دقیقه دیگر امتحان کنید."});const db=load(),u=db.users.find(x=>x.username===clean(q.body?.username,40)&&x.active!==false);if(!u||!verify(q.body?.password||"",u)){a.n++;if(a.n>=6){a.n=0;a.until=Date.now()+600000}attempts.set(ip,a);return s.status(401).json({error:"نام کاربری یا رمز اشتباه است."})}attempts.delete(ip);const token=crypto.randomBytes(32).toString("hex");sessions.set(token,{uid:u.id,exp:Date.now()+43200000,fp:sessionFingerprint(u)});s.json({token,user:safe(u)})});
app.post("/api/logout",auth,(q,s)=>{sessions.delete(q.token);s.json({ok:true})});
app.get("/api/me",auth,(q,s)=>s.json({user:safe(q.user)}));
app.post("/api/change-password",auth,(q,s)=>{if(!verify(q.body?.oldPassword||"",q.user))return s.status(400).json({error:"رمز فعلی نادرست است."});const p=String(q.body?.newPassword||"");if(p.length<10)return s.status(400).json({error:"رمز جدید حداقل ۱۰ نویسه باشد."});const h=hash(p);q.user.passwordSalt=h.salt;q.user.passwordHash=h.hash;save(q.db);for(const [token,session] of sessions){if(session.uid===q.user.id){if(token===q.token)session.fp=sessionFingerprint(q.user);else sessions.delete(token)}}s.json({ok:true})});
app.get("/api/dashboard",auth,clinicContext,(q,s)=>{const d=q.db,patients=clinicRows(d.patients,q),appointments=clinicRows(d.appointments,q);s.json({patients:patients.length,appointments:appointments.length,today:appointments.filter(a=>a.date===new Date().toISOString().slice(0,10)).length,upcoming:visibleAppointments(appointments.filter(a=>a.status!=="لغو شده").slice().sort((a,b)=>(a.date+a.time).localeCompare(b.date+b.time)).slice(0,8),q.user)})});
app.get("/api/patients",auth,clinicContext,allowRoles("admin","doctor","reception"),(q,s)=>{const rows=clinicRows(q.db.patients,q).slice().sort((a,b)=>b.id-a.id);s.json(q.user.role==="reception"?rows.map(p=>({id:p.id,name:p.name,phone:p.phone,nationalId:p.nationalId})):rows)});
app.post("/api/patients",auth,clinicContext,allowRoles("admin","doctor","reception"),(q,s)=>{const {name,phone,nationalId,notes,medicalHistory,allergies,medications}=q.body||{};if(!clean(name)||!clean(phone))return s.status(400).json({error:"نام و شماره تماس الزامی است."});const clinical=q.user.role==="reception"?{}:{notes:clean(notes,2000),medicalHistory:clean(medicalHistory,4000),allergies:clean(allergies,2000),medications:clean(medications,2000)};const p={id:Date.now(),clinic_id:q.clinicId,name:clean(name),phone:clean(phone,30),nationalId:clean(nationalId,20),...clinical,visits:[],createdAt:new Date().toISOString()};q.db.patients.push(p);save(q.db);s.json(q.user.role==="reception"?{id:p.id,name:p.name,phone:p.phone,nationalId:p.nationalId}:p)});
app.get("/api/appointments",auth,clinicContext,allowRoles("admin","doctor","reception"),(q,s)=>s.json(visibleAppointments(clinicRows(q.db.appointments,q).slice().sort((a,b)=>(a.date+a.time).localeCompare(b.date+b.time)),q.user)));

app.patch("/api/patients/:id",auth,clinicContext,allowRoles("admin","doctor"),(q,s)=>{const p=clinicRows(q.db.patients,q).find(x=>x.id===Number(q.params.id));if(!p)return s.status(404).json({error:"بیمار پیدا نشد."});for(const k of ["notes","medicalHistory","allergies","medications"])if(q.body?.[k]!==undefined)p[k]=clean(q.body[k],k==="medicalHistory"?4000:2000);save(q.db);s.json(p)});
app.post("/api/patients/:id/visits",auth,clinicContext,allowRoles("admin","doctor"),(q,s)=>{const p=clinicRows(q.db.patients,q).find(x=>x.id===Number(q.params.id));if(!p)return s.status(404).json({error:"بیمار پیدا نشد."});const note=clean(q.body?.note,3000),date=clean(q.body?.date,10)||new Date().toISOString().slice(0,10);if(!note)return s.status(400).json({error:"شرح مراجعه را وارد کنید."});p.visits=p.visits||[];p.visits.push({id:Date.now(),date,note,doctor:q.user.name});save(q.db);s.status(201).json(p.visits[p.visits.length-1])});
app.get("/api/calendar",auth,clinicContext,allowRoles("admin","doctor","reception"),(q,s)=>{const month=String(q.query.month||"").slice(0,7);s.json(visibleAppointments(clinicRows(q.db.appointments,q).filter(a=>!month||String(a.date||"").startsWith(month)).sort((a,b)=>(a.date+a.time).localeCompare(b.date+b.time)),q.user))});
app.get("/api/reports",auth,clinicContext,admin,(q,s)=>{const d=q.db,from=String(q.query.from||"0000-01-01"),to=String(q.query.to||"9999-12-31"),rows=clinicRows(d.appointments,q).filter(a=>a.date>=from&&a.date<=to),paid=rows.filter(a=>a.paymentStatus==="پرداخت شد").reduce((n,a)=>n+(Number(a.amount)||0),0),unpaid=rows.filter(a=>a.paymentStatus!=="پرداخت شد").reduce((n,a)=>n+(Number(a.amount)||0),0);s.json({patients:clinicRows(d.patients,q).length,appointments:rows.length,visited:rows.filter(a=>a.status==="مراجعه کرد").length,cancelled:rows.filter(a=>a.status==="لغو شده").length,paid,unpaid,rows})});
app.get("/api/backup",auth,clinicContext,admin,(q,s)=>{fs.mkdirSync(BACKUPS,{recursive:true});const name="manual-"+new Date().toISOString().replace(/[:.]/g,"-")+".json";fs.writeFileSync(path.join(BACKUPS,name),JSON.stringify({
clinic:q.clinic,
users:q.db.users.filter(u=>Array.isArray(u.clinicIds)&&u.clinicIds.some(id=>String(id)===String(q.clinicId))).map(safe),
patients:clinicRows(q.db.patients,q),
appointments:clinicRows(q.db.appointments,q),
createdAt:new Date().toISOString()
},null,2),{mode:0o600});s.json({ok:true,name})});

app.post("/api/appointments",auth,clinicContext,allowRoles("admin","doctor","reception"),(q,s)=>{const {patientName,phone,date,time,service,amount,paymentStatus}=q.body||{};if(!clean(patientName)||!clean(phone)||!/^\d{4}-\d{2}-\d{2}$/.test(String(date))||!/^\d{2}:\d{2}$/.test(String(time)))return s.status(400).json({error:"نام، تماس، تاریخ و ساعت معتبر الزامی است."});if(clinicRows(q.db.appointments,q).some(a=>a.date===date&&a.time===time&&a.status!=="لغو شده"))return s.status(409).json({error:"این ساعت قبلاً رزرو شده است."});const a={id:Date.now(),clinic_id:q.clinicId,patientName:clean(patientName),phone:clean(phone,30),date,time,service:clean(service||"ویزیت",100),status:"ثبت شده",amount:q.user.role==="admin"?Math.max(0,Number(amount)||0):0,paymentStatus:q.user.role==="admin"&&["پرداخت شد","پرداخت نشده","عودت شد"].includes(paymentStatus)?paymentStatus:"پرداخت نشده",createdAt:new Date().toISOString()};q.db.appointments.push(a);save(q.db);s.json(a)});
app.patch("/api/appointments/:id",auth,clinicContext,admin,(q,s)=>{const a=clinicRows(q.db.appointments,q).find(x=>x.id===Number(q.params.id));if(!a)return s.status(404).json({error:"نوبت پیدا نشد."});const st=clean(q.body?.status,30);if(!["ثبت شده","مراجعه کرد","لغو شده"].includes(st))return s.status(400).json({error:"وضعیت نامعتبر است."});a.status=st;save(q.db);s.json(a)});
app.get("/api/users",auth,clinicContext,admin,(q,s)=>s.json(q.db.users.filter(u=>Array.isArray(u.clinicIds)&&u.clinicIds.some(id=>String(id)===String(q.clinicId))).map(safe)));
app.post("/api/users",auth,clinicContext,admin,(q,s)=>{const username=clean(q.body?.username,40),name=clean(q.body?.name,100),password=String(q.body?.password||""),role=clean(q.body?.role,20);if(!/^[a-zA-Z0-9_.-]{3,40}$/.test(username)||name.length<2||password.length<10||!["doctor","reception"].includes(role))return s.status(400).json({error:"نام، نام کاربری معتبر و رمز حداقل ۱۰ نویسه لازم است."});if(q.db.users.some(u=>u.username.toLowerCase()===username.toLowerCase()))return s.status(409).json({error:"این نام کاربری موجود است."});const h=hash(password),u={id:Date.now(),username,name,role,active:true,clinicIds:[q.clinicId],activeClinicId:q.clinicId,passwordSalt:h.salt,passwordHash:h.hash};q.db.users.push(u);save(q.db);s.status(201).json(safe(u))});

/* MATAB_DAILY_BACKUP_V1 */
function dailyBackup(){
  try {
    if(!fs.existsSync(DATA)) return;
    const dir=path.join(BACKUPS,"daily");
    fs.mkdirSync(dir,{recursive:true,mode:0o700});
    try { fs.chmodSync(dir,0o700); } catch(e) {}
    const now=new Date();
    const day=[now.getFullYear(),String(now.getMonth()+1).padStart(2,"0"),String(now.getDate()).padStart(2,"0")].join("-");
    const dest=path.join(dir,"daily-"+day+".json");
    if(!fs.existsSync(dest)){
      fs.copyFileSync(DATA,dest);
      try { fs.chmodSync(dest,0o600); } catch(e) {}
      console.log("Daily backup created:",dest);
    }
    const old=fs.readdirSync(dir).filter(x=>/^daily-\d{4}-\d{2}-\d{2}\.json$/.test(x)).sort();
    while(old.length>30) fs.unlinkSync(path.join(dir,old.shift()));
  } catch(e) {
    console.error("Daily backup error:",e.message);
  }
}
dailyBackup();
const dailyBackupTimer=setInterval(dailyBackup,6*60*60*1000);
dailyBackupTimer.unref();



/* MATAB_SUPERADMIN_CLINICS_V1 */
const superadminOnly=(q,s,n)=>
  q.user&&q.user.role==="superadmin"
    ? n()
    : s.status(403).json({error:"دسترسی مدیر کل سامانه لازم است."});

function superadminClinic(db,id){
  return (db.clinics||[]).find(c=>String(c.id)===String(id));
}

function superadminUserView(u){
  return {
    id:u.id,
    username:u.username,
    name:u.name,
    role:u.role,
    active:u.active!==false,
    clinicIds:Array.isArray(u.clinicIds)?u.clinicIds:[],
    activeClinicId:u.activeClinicId??null
  };
}

function activeClinicAdminCount(db,clinicId,exceptUserId){
  return db.users.filter(u=>
    u.id!==exceptUserId &&
    u.active!==false &&
    u.role==="admin" &&
    Array.isArray(u.clinicIds) &&
    u.clinicIds.some(id=>String(id)===String(clinicId))
  ).length;
}

/* MATAB_SUPERADMIN_USERS_V1 */

app.get("/api/superadmin/clinics",auth,superadminOnly,(q,s)=>{
  const clinics=(q.db.clinics||[]).map(c=>({
    id:c.id,
    name:c.name,
    active:c.active!==false,
    createdAt:c.createdAt||null,
    userCount:q.db.users.filter(u=>
      u.active!==false &&
      Array.isArray(u.clinicIds) &&
      u.clinicIds.some(id=>String(id)===String(c.id))
    ).length
  }));
  s.json(clinics);
});

app.post("/api/superadmin/clinics",auth,superadminOnly,(q,s)=>{
  const name=clean(q.body?.name,100);
  if(name.length<2)
    return s.status(400).json({error:"نام مطب باید حداقل ۲ نویسه باشد."});

  q.db.clinics=q.db.clinics||[];

  if(q.db.clinics.some(c=>String(c.name||"").toLowerCase()===name.toLowerCase()))
    return s.status(409).json({error:"مطب با این نام قبلاً ثبت شده است."});

  const clinic={
    id:"clinic_"+crypto.randomBytes(12).toString("hex"),
    name,
    active:true,
    createdAt:new Date().toISOString()
  };

  q.db.clinics.push(clinic);
  save(q.db);

  s.status(201).json({
    ok:true,
    clinic:{
      id:clinic.id,
      name:clinic.name,
      active:clinic.active,
      createdAt:clinic.createdAt,
      userCount:0
    }
  });
});

app.patch("/api/superadmin/clinics/:id",auth,superadminOnly,(q,s)=>{
  const clinic=superadminClinic(q.db,q.params.id);
  if(!clinic) return s.status(404).json({error:"مطب پیدا نشد."});

  const body=q.body||{};

  if(Object.prototype.hasOwnProperty.call(body,"name")){
    const name=clean(body.name,100);
    if(name.length<2)
      return s.status(400).json({error:"نام مطب معتبر نیست."});

    if(q.db.clinics.some(c=>
      c.id!==clinic.id &&
      String(c.name||"").toLowerCase()===name.toLowerCase()
    )) return s.status(409).json({error:"نام این مطب قبلاً استفاده شده است."});

    clinic.name=name;
  }

  if(Object.prototype.hasOwnProperty.call(body,"active")){
    if(typeof body.active!=="boolean")
      return s.status(400).json({error:"وضعیت مطب باید فعال یا غیرفعال باشد."});

    clinic.active=body.active;
  }

  save(q.db);

  if(clinic.active===false){
    const memberIds=q.db.users
      .filter(u=>Array.isArray(u.clinicIds)&&u.clinicIds.some(id=>String(id)===String(clinic.id)))
      .map(u=>u.id);

    for(const [token,session] of sessions.entries()){
      if(memberIds.some(id=>String(id)===String(session.uid)))
        sessions.delete(token);
    }
  }

  s.json({ok:true,clinic:{
    id:clinic.id,
    name:clinic.name,
    active:clinic.active!==false,
    createdAt:clinic.createdAt||null
  }});
});

app.get("/api/superadmin/clinics/:id/users",auth,superadminOnly,(q,s)=>{
  const clinic=superadminClinic(q.db,q.params.id);
  if(!clinic) return s.status(404).json({error:"مطب پیدا نشد."});

  const users=q.db.users
    .filter(u=>Array.isArray(u.clinicIds)&&u.clinicIds.some(id=>String(id)===String(clinic.id)))
    .map(superadminUserView);

  s.json(users);
});

app.post("/api/superadmin/clinics/:id/users",auth,superadminOnly,(q,s)=>{
  const clinic=superadminClinic(q.db,q.params.id);
  if(!clinic) return s.status(404).json({error:"مطب پیدا نشد."});
  if(clinic.active===false)
    return s.status(409).json({error:"برای مطب غیرفعال نمی‌توان حساب جدید ساخت."});

  const body=q.body||{};
  const name=clean(body.name,80);
  const username=clean(body.username,40);
  const password=String(body.password||"");
  const role=String(body.role||"");

  if(name.length<2)
    return s.status(400).json({error:"نام کاربر معتبر نیست."});
  if(!/^[a-zA-Z0-9_.-]{3,40}$/.test(username))
    return s.status(400).json({error:"نام کاربری باید ۳ تا ۴۰ نویسه انگلیسی باشد."});
  if(password.length<10||password.length>200)
    return s.status(400).json({error:"رمز عبور باید حداقل ۱۰ نویسه داشته باشد."});
  if(!["admin","doctor","reception"].includes(role))
    return s.status(400).json({error:"نقش کاربر معتبر نیست."});

  if(q.db.users.some(u=>String(u.username).toLowerCase()===username.toLowerCase()))
    return s.status(409).json({error:"این نام کاربری قبلاً استفاده شده است."});

  const h=hash(password);
  const user={
    id:"user_"+crypto.randomBytes(12).toString("hex"),
    username,
    name,
    role,
    active:true,
    passwordSalt:h.salt,
    passwordHash:h.hash,
    clinicIds:[clinic.id],
    activeClinicId:clinic.id,
    createdAt:new Date().toISOString()
  };

  q.db.users.push(user);
  save(q.db);

  s.status(201).json({ok:true,user:superadminUserView(user)});
});

app.patch("/api/superadmin/users/:id",auth,superadminOnly,(q,s)=>{
  const user=q.db.users.find(u=>String(u.id)===String(q.params.id));
  if(!user) return s.status(404).json({error:"کاربر پیدا نشد."});

  if(user.role==="superadmin")
    return s.status(403).json({error:"تغییر حساب مدیر کل از این مسیر مجاز نیست."});

  const body=q.body||{};
  const nextRole=Object.prototype.hasOwnProperty.call(body,"role")?String(body.role):user.role;
  const nextActive=Object.prototype.hasOwnProperty.call(body,"active")?body.active:user.active!==false;

  if(!["admin","doctor","reception"].includes(nextRole))
    return s.status(400).json({error:"نقش کاربر معتبر نیست."});
  if(typeof nextActive!=="boolean")
    return s.status(400).json({error:"وضعیت کاربر باید فعال یا غیرفعال باشد."});

  const losesAdmin=user.role==="admin"&&(nextRole!=="admin"||nextActive===false);
  if(losesAdmin){
    const memberships=Array.isArray(user.clinicIds)?user.clinicIds:[];
    for(const clinicId of memberships){
      const clinic=superadminClinic(q.db,clinicId);
      if(clinic&&clinic.active!==false&&activeClinicAdminCount(q.db,clinicId,user.id)===0)
        return s.status(409).json({error:"این تغییر باعث می‌شود مطب فعال بدون مدیر بماند."});
    }
  }

  user.role=nextRole;
  user.active=nextActive;
  save(q.db);

  for(const [token,session] of sessions.entries()){
    if(String(session.uid)===String(user.id)) sessions.delete(token);
  }

  s.json({ok:true,user:superadminUserView(user)});
});

app.patch("/api/superadmin/users/:id/membership",auth,superadminOnly,(q,s)=>{
  const user=q.db.users.find(u=>String(u.id)===String(q.params.id));
  if(!user) return s.status(404).json({error:"کاربر پیدا نشد."});
  if(user.role==="superadmin")
    return s.status(403).json({error:"عضویت حساب مدیر کل قابل تغییر نیست."});

  const clinicId=clean(q.body?.clinicId,100);
  const active=q.body?.active;

  if(!clinicId||typeof active!=="boolean")
    return s.status(400).json({error:"شناسه مطب و وضعیت عضویت الزامی است."});

  const clinic=superadminClinic(q.db,clinicId);
  if(!clinic) return s.status(404).json({error:"مطب پیدا نشد."});
  if(active&&clinic.active===false)
    return s.status(409).json({error:"مطب غیرفعال است."});

  user.clinicIds=Array.isArray(user.clinicIds)?user.clinicIds:[];
  const has=user.clinicIds.some(id=>String(id)===String(clinicId));

  if(active&&!has){
    user.clinicIds.push(clinic.id);
    if(!user.activeClinicId) user.activeClinicId=clinic.id;
  } else if(!active&&has){
    if(user.role==="admin"&&clinic.active!==false&&activeClinicAdminCount(q.db,clinicId,user.id)===0)
      return s.status(409).json({error:"حذف این عضویت باعث می‌شود مطب فعال بدون مدیر بماند."});

    user.clinicIds=user.clinicIds.filter(id=>String(id)!==String(clinicId));
    if(String(user.activeClinicId)===String(clinicId))
      user.activeClinicId=user.clinicIds.length?user.clinicIds[0]:null;
  }

  save(q.db);

  for(const [token,session] of sessions.entries()){
    if(String(session.uid)===String(user.id)) sessions.delete(token);
  }

  s.json({ok:true,user:superadminUserView(user)});
});

app.listen(PORT,HOST,()=>console.log(`Matab listening on ${HOST}:${PORT}`));