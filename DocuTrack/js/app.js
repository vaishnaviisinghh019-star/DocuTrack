(function(){
  var $ = function(id){return document.getElementById(id)};
  var mem = {};
  function load(k, d){ try{ var v = localStorage.getItem(k); if(v!==null) return JSON.parse(v); }catch(e){} return k in mem ? mem[k] : d; }
  function save(k, v){ mem[k]=v; try{ localStorage.setItem(k, JSON.stringify(v)); }catch(e){} }

  var users = load('dt_users', {});
  var session = load('dt_session', null);
  var filter = 'all', mode = 'login', renewId = null;

  function esc(s){ return String(s).replace(/[&<>"']/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]}); }
  function hash(s){
    if(window.crypto && crypto.subtle && window.TextEncoder){
      return crypto.subtle.digest('SHA-256', new TextEncoder().encode('docutrack:'+s)).then(function(b){
        return Array.prototype.map.call(new Uint8Array(b), function(x){return ('0'+x.toString(16)).slice(-2)}).join('');
      });
    }
    var h=0; for(var i=0;i<s.length;i++){h=(h*31+s.charCodeAt(i))|0} return Promise.resolve('x'+h);
  }
  function today(){ var d=new Date(); return new Date(d.getFullYear(), d.getMonth(), d.getDate()); }
  function parse(s){ var p=s.split('-'); return new Date(+p[0], +p[1]-1, +p[2]); }
  function daysLeft(s){ return Math.round((parse(s)-today())/86400000); }
  function fmt(s){ return parse(s).toLocaleDateString(undefined,{day:'numeric',month:'short',year:'numeric'}); }
  function status(d){ var n=daysLeft(d.expiry); return n<0?'expired':(n<=d.remind?'soon':'active'); }
  function when(n){ if(n<0) return 'expired '+(-n)+(n===-1?' day':' days')+' ago'; if(n===0) return 'expires today'; return n+(n===1?' day':' days')+' left'; }

  // ---------- auth ----------
  function setMode(m){
    mode=m; $('nameBox').hidden = m!=='reg';
    $('tLogin').className='btn sm'+(m==='login'?'':' ghost');
    $('tReg').className='btn sm'+(m==='reg'?'':' ghost');
    $('authGo').textContent = m==='login'?'Log in':'Create account';
    $('pw').autocomplete = m==='login'?'current-password':'new-password';
    $('authMsg').textContent='';
  }
  $('tLogin').onclick=function(){setMode('login')};
  $('tReg').onclick=function(){setMode('reg')};
  $('authGo').onclick=function(){
    var email=$('email').value.trim().toLowerCase(), pw=$('pw').value, name=$('name').value.trim();
    var msg=$('authMsg'); msg.textContent='';
    if(!/^\S+@\S+\.\S+$/.test(email)){ msg.textContent='Enter a valid email address.'; return; }
    if(pw.length<6){ msg.textContent='Use a password with at least 6 characters.'; return; }
    hash(pw).then(function(h){
      if(mode==='reg'){
        if(!name){ msg.textContent='Enter your name.'; return; }
        if(users[email]){ msg.textContent='That email already has an account. Log in instead.'; return; }
        users[email]={name:name,hash:h,docs:[]}; save('dt_users',users);
      } else {
        if(!users[email] || users[email].hash!==h){ msg.textContent='Email or password is incorrect.'; return; }
      }
      session=email; save('dt_session',session); $('pw').value=''; render();
    });
  };
  $('out').onclick=function(){ session=null; save('dt_session',null); render(); };

  // ---------- documents ----------
  function me(){ return users[session]; }
  $('add').onclick=function(){
    var n=$('dn').value.trim(), x=$('dx').value, m=$('addMsg'); m.textContent='';
    if(!n){ m.textContent='Enter a document name.'; return; }
    if(!x){ m.textContent='Choose the expiry date shown on the document.'; return; }
    me().docs.push({id:Date.now().toString(36)+Math.random().toString(36).slice(2,6),name:n,type:$('dt').value,expiry:x,remind:+$('dr').value,renewals:[]});
    save('dt_users',users); $('dn').value=''; $('dx').value=''; render();
  };
  function del(id){
    var d=me().docs.filter(function(x){return x.id===id})[0];
    if(d && confirm('Delete “'+d.name+'”?')){ me().docs=me().docs.filter(function(x){return x.id!==id}); save('dt_users',users); render(); }
  }
  function openRenew(id){
    var d=me().docs.filter(function(x){return x.id===id})[0]; if(!d) return;
    renewId=id; $('dlgS').textContent=d.name+' currently expires on '+fmt(d.expiry)+'.';
    $('nx').value=''; $('dlgMsg').textContent=''; $('dlg').showModal();
  }
  $('dlgNo').onclick=function(){ $('dlg').close(); };
  $('dlgOk').onclick=function(){
    var v=$('nx').value, d=me().docs.filter(function(x){return x.id===renewId})[0];
    if(!v){ $('dlgMsg').textContent='Choose the new expiry date.'; return; }
    if(daysLeft(v)<=daysLeft(d.expiry)){ $('dlgMsg').textContent='The new date must be later than the current expiry date.'; return; }
    d.renewals.push({on:new Date().toISOString().slice(0,10),from:d.expiry,to:v});
    d.expiry=v; save('dt_users',users); $('dlg').close(); render();
  };

  // ---------- render ----------
  function render(){
    $('auth').hidden = !!(session && users[session]);
    $('app').hidden = !(session && users[session]);
    if($('app').hidden){ setMode(mode); return; }
    var u=me(), docs=u.docs.slice().sort(function(a,b){return a.expiry<b.expiry?-1:1});
    $('hello').textContent='Hi, '+u.name;

    var c={expired:0,soon:0,active:0};
    docs.forEach(function(d){c[status(d)]++});
    var renewed=docs.filter(function(d){return d.renewals.length}).length;
    $('stats').innerHTML=
      '<div class="stat bad"><b>'+c.expired+'</b><span>Expired</span></div>'+
      '<div class="stat soon"><b>'+c.soon+'</b><span>Due soon</span></div>'+
      '<div class="stat ok"><b>'+c.active+'</b><span>Active</span></div>'+
      '<div class="stat done"><b>'+renewed+'</b><span>Renewed so far</span></div>';

    var urgent=docs.filter(function(d){return status(d)!=='active'});
    var r=$('remind');
    if(!docs.length){ r.innerHTML=''; }
    else if(!urgent.length){ r.innerHTML='<div class="remind calm"><h2>You’re all caught up</h2>No documents need attention right now.</div>'; }
    else {
      r.innerHTML='<div class="remind'+(c.expired?' bad':'')+'"><h2>'+urgent.length+(urgent.length===1?' document needs':' documents need')+' attention</h2><ul>'+
        urgent.map(function(d){return '<li><b>'+esc(d.name)+'</b> — '+when(daysLeft(d.expiry))+' ('+fmt(d.expiry)+')</li>'}).join('')+'</ul></div>';
    }

    var defs=[['all','All'],['expired','Expired'],['soon','Due soon'],['active','Active']];
    $('filters').innerHTML=defs.map(function(f){return '<button class="chip" type="button" data-f="'+f[0]+'" aria-pressed="'+(filter===f[0])+'">'+f[1]+'</button>'}).join('');

    var shown=docs.filter(function(d){return filter==='all'||status(d)===filter});
    if(!shown.length){
      $('list').innerHTML='<li class="empty">'+(docs.length?'No documents match this filter.':'No documents yet. Add your first one above to start tracking its expiry date.')+'</li>';
    } else {
      $('list').innerHTML=shown.map(function(d){
        var s=status(d), n=daysLeft(d.expiry), lab={expired:'Expired',soon:'Due soon',active:'Active'}[s];
        var h=d.renewals.length?'<div class="hist">Renewed '+d.renewals.length+(d.renewals.length===1?' time':' times')+', last on '+fmt(d.renewals[d.renewals.length-1].on)+'</div>':'';
        return '<li class="doc '+s+'"><div><h3>'+esc(d.name)+'<span class="badge '+s+'">'+lab+'</span></h3>'+
          '<div class="meta">'+esc(d.type)+' · expires '+fmt(d.expiry)+' · '+when(n)+'</div>'+h+'</div>'+
          '<div class="acts"><button class="btn sm" type="button" data-r="'+d.id+'">Mark renewed</button>'+
          '<button class="btn danger sm" type="button" data-d="'+d.id+'" aria-label="Delete '+esc(d.name)+'">Delete</button></div></li>';
      }).join('');
    }
  }
  $('filters').onclick=function(e){ var f=e.target.getAttribute('data-f'); if(f){filter=f;render();} };
  $('list').onclick=function(e){
    var r=e.target.getAttribute('data-r'), d=e.target.getAttribute('data-d');
    if(r) openRenew(r); else if(d) del(d);
  };

  render();
})();
