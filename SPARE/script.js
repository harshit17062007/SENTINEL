(function(){
'use strict';

/* ================= Seeded RNG ================= */
function mulberry32(a){
  return function(){
    a |= 0; a = a + 0x6D2B79F5 | 0;
    var t = Math.imul(a ^ a >>> 15, 1 | a);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}
var SEED = Math.floor(Math.random()*900000)+100000;
var rand = mulberry32(SEED);
function ri(min,max){ return Math.floor(rand()*(max-min+1))+min; }
function pick(arr){ return arr[Math.floor(rand()*arr.length)]; }
function chance(p){ return rand() < p; }

/* ================= Reference data ================= */
var VENDORS = ['Nyra Systems','Corvex Networks','Fenwick IoT','Halcyon Grid','Ostrum Labs','BrightPath Municipal','Ferrotech Sensors','Ardennet'];
var CATEGORY_META = {
  TSC:{label:'Traffic Signal Controller'},
  WAP:{label:'Public Wi-Fi AP'},
  SLT:{label:'Smart Streetlight'},
  ENV:{label:'Environmental Sensor'},
  PKS:{label:'Parking Sensor'},
  WMG:{label:'Water Meter Gateway'},
  CCV:{label:'CCTV Node'}
};
var PORTS = [
  {port:22,name:'ssh',risk:0},
  {port:80,name:'http',risk:0},
  {port:443,name:'https',risk:0},
  {port:8080,name:'http-alt',risk:5},
  {port:1883,name:'mqtt',risk:5},
  {port:502,name:'modbus',risk:15},
  {port:21,name:'ftp',risk:20},
  {port:23,name:'telnet',risk:25}
];
var CVE_DESCRIPTORS = [
  {match:23, text:'Telnet service enabled with vendor-default credentials'},
  {match:21, text:'Anonymous FTP write access to firmware partition'},
  {match:502, text:'Unauthenticated Modbus register write'},
  {match:null, text:'Hardcoded SSH host key shared across the fleet'},
  {match:null, text:'Firmware heap overflow enabling remote code execution'},
  {match:null, text:'Improper access control on local config API'},
  {match:null, text:'Weak / deprecated TLS cipher suite accepted'}
];
var ZONES = [
  {id:'downtown',name:'Downtown Core',hub:{x:250,y:190},count:40,weights:{WAP:.25,TSC:.20,CCV:.20,SLT:.20,PKS:.15}},
  {id:'north-res',name:'North Residential',hub:{x:560,y:90},count:30,weights:{SLT:.40,WMG:.30,ENV:.10,WAP:.10,TSC:.10}},
  {id:'industrial',name:'Industrial Park',hub:{x:800,y:240},count:35,weights:{ENV:.30,CCV:.25,WMG:.15,SLT:.15,TSC:.15}},
  {id:'south-res',name:'South Residential',hub:{x:300,y:480},count:30,weights:{SLT:.35,WMG:.35,ENV:.15,WAP:.15}},
  {id:'harborfront',name:'Harborfront',hub:{x:770,y:500},count:25,weights:{ENV:.35,CCV:.25,WAP:.20,SLT:.20}},
  {id:'civic',name:'Civic Center',hub:{x:510,y:300},count:10,weights:{CCV:.40,WAP:.30,TSC:.30}}
];

function weightedPick(weights){
  var r = rand(), acc = 0, keys = Object.keys(weights);
  for(var i=0;i<keys.length;i++){ acc += weights[keys[i]]; if(r<=acc) return keys[i]; }
  return keys[keys.length-1];
}
function clamp(v,min,max){ return Math.max(min,Math.min(max,v)); }

/* ================= State ================= */
var devices = [];
var counters = {};
var currentSweep = 0;
var lastSweepAt = null;
var scanning = false;
var selectedDeviceId = null;
var filters = {status:'all', zone:'all', q:'', sort:'risk'};

/* ================= Generation ================= */
function computeRisk(dev){
  var firmwareFactor = dev.firmwareMajor===1?40:dev.firmwareMajor===2?25:dev.firmwareMajor===3?10:0;
  var portFactor = 0;
  dev.ports.forEach(function(p){
    var meta = PORTS.filter(function(x){return x.port===p;})[0];
    if(meta) portFactor += meta.risk;
  });
  return firmwareFactor + portFactor;
}
function classify(score){
  if(score>=75) return 'critical';
  if(score>=50) return 'high';
  if(score>=25) return 'medium';
  return 'low';
}
function riskColor(level){
  return level==='critical'?'var(--red)':level==='high'?'var(--orange)':level==='medium'?'var(--amber)':'var(--green)';
}
function pickCVEDescriptor(dev){
  var risky = dev.ports.filter(function(p){ return [23,21,502].indexOf(p)>-1; });
  if(risky.length){
    var m = CVE_DESCRIPTORS.filter(function(c){ return c.match===risky[0]; })[0];
    if(m) return m;
  }
  var generic = CVE_DESCRIPTORS.filter(function(c){ return c.match===null; });
  return pick(generic);
}
function assignCVE(dev){
  var d = pickCVEDescriptor(dev);
  var year = 2023 + ri(0,2);
  var num = ri(10000,99999);
  return { id:'SIM-CVE-'+year+'-'+num, text:d.text, severity:dev.riskLevel };
}
function makePorts(){
  var ports = [pick([80,443,22])];
  if(chance(.22)) ports.push(23);
  if(chance(.16)) ports.push(21);
  if(chance(.14)) ports.push(502);
  if(chance(.25)) ports.push(pick([1883,8080]));
  return Array.from(new Set(ports));
}

var idCounters = {};
function nextId(cat){
  idCounters[cat] = (idCounters[cat]||0)+1;
  var n = idCounters[cat];
  return cat+'-'+(n<10?'00'+n:n<100?'0'+n:n);
}

function generateCity(){
  devices = []; idCounters = {};
  ZONES.forEach(function(zone){
    for(var i=0;i<zone.count;i++){
      var cat = weightedPick(zone.weights);
      var angle = rand()*Math.PI*2;
      var radius = 26 + rand()*130;
      var x = clamp(zone.hub.x + Math.cos(angle)*radius, 28, 972);
      var y = clamp(zone.hub.y + Math.sin(angle)*radius, 28, 612);
      var firmwareMajor = ri(1,4);
      var dev = {
        id: nextId(cat),
        category: cat,
        categoryLabel: CATEGORY_META[cat].label,
        vendor: pick(VENDORS),
        firmwareMajor: firmwareMajor,
        firmware: 'v'+firmwareMajor+'.'+ri(0,6)+'.'+ri(0,9),
        zoneId: zone.id,
        zoneName: zone.name,
        hub: zone.hub,
        x:x, y:y,
        ports: makePorts(),
        online: chance(.92),
        isolated:false,
        vulnerable:false,
        flagged:false,
        cve:null,
        lastSeen:0,
        history:[]
      };
      dev.riskScore = computeRisk(dev);
      dev.riskLevel = classify(dev.riskScore);
      if(dev.riskScore>=25 && chance(.8)){
        dev.vulnerable = true;
        dev.cve = assignCVE(dev);
      }
      devices.push(dev);
    }
  });
  currentSweep = 0; lastSweepAt = null; selectedDeviceId = null;
  clearTranscript(); clearActivity();
  populateZoneSelect();
  renderAll();
}

/* ================= Probe engine ================= */
function bumpFirmware(dev){
  dev.firmwareMajor = Math.min(dev.firmwareMajor+1,4);
  dev.firmware = 'v'+dev.firmwareMajor+'.0.0';
}

function probeDevice(dev){
  var entry = {sweep:currentSweep, ts:timeLabel(), qa:[], outcome:'no_change'};

  if(chance(.05)) dev.online = !dev.online;
  entry.qa.push({q:'Are you still there?', a: dev.online ? 'Yes — responding, nominal uptime' : 'No response (timeout)'});

  if(dev.vulnerable){
    var patched = chance(.30);
    entry.qa.push({q:'What is your current firmware version?', a: patched ? 'Auto-patch applied, now on '+('v'+Math.min(dev.firmwareMajor+1,4)+'.0.0') : 'Still on '+dev.firmware+' (unpatched)'});
    if(patched){
      bumpFirmware(dev);
      dev.vulnerable = false;
      var oldCve = dev.cve;
      dev.cve = null;
      dev.flagged = false;
      dev.riskScore = computeRisk(dev);
      dev.riskLevel = classify(dev.riskScore);
      entry.outcome = 'vulnerability_resolved';
      entry.resolvedCve = oldCve;
    }
  } else if(!dev.isolated){
    var configChanged = chance(.12);
    var suspicious = chance(.10);
    if(configChanged) entry.qa.push({q:'Any configuration changes since last sweep?', a:'Yes — local configuration was modified'});
    if(suspicious) entry.qa.push({q:'Any suspicious behavior detected?', a:'Yes — anomalous outbound traffic observed'});
    if(configChanged || suspicious){
      if(chance(.7)){
        dev.cve = assignCVE(dev);
        dev.vulnerable = true;
        entry.outcome = 'new_vulnerability_found';
        entry.newCve = dev.cve;
      } else {
        dev.flagged = true;
        entry.outcome = 'flagged_no_matching_cve';
      }
    }
  }

  dev.lastSeen = currentSweep;
  dev.history.unshift(entry);
  return entry;
}

function timeLabel(){
  var d = new Date();
  return d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

function runScanSweep(){
  if(scanning) return;
  scanning = true;
  currentSweep += 1;
  document.getElementById('btnScan').disabled = true;
  document.getElementById('mapWrap').classList.add('scanning');
  pushTranscriptSystem('=== Sweep #'+currentSweep+' started — probing '+devices.filter(function(d){return !d.isolated;}).length+' active nodes ===');

  var queue = devices.filter(function(d){ return !d.isolated; }).slice();
  // shuffle
  for(var i=queue.length-1;i>0;i--){ var j = Math.floor(rand()*(i+1)); var tmp=queue[i]; queue[i]=queue[j]; queue[j]=tmp; }

  var counts = {resolved:0, discovered:0, flagged:0};
  var batchSize = 8, idx = 0;

  var timer = setInterval(function(){
    var batch = queue.slice(idx, idx+batchSize);
    if(batch.length===0){
      clearInterval(timer);
      finishSweep(counts);
      return;
    }
    batch.forEach(function(dev){
      var entry = probeDevice(dev);
      pushTranscriptEntry(dev, entry);
      pingNode(dev.id);
      if(entry.outcome==='vulnerability_resolved'){
        counts.resolved++;
        pushActivity('resolved', dev.id+' — vulnerability resolved, patched to '+dev.firmware);
      } else if(entry.outcome==='new_vulnerability_found'){
        counts.discovered++;
        pushActivity('discovered', dev.id+' — new vulnerability: '+entry.newCve.text+' ('+entry.newCve.id+')');
      } else if(entry.outcome==='flagged_no_matching_cve'){
        counts.flagged++;
        pushActivity('flagged', dev.id+' — anomalous signal, no matching CVE on record, routed to manual review');
      }
    });
    idx += batchSize;
    renderStats(); renderMap(); renderTable();
    if(selectedDeviceId){ var d = devices.filter(function(x){return x.id===selectedDeviceId;})[0]; if(d) openDrawer(d.id, true); }
  }, 140);
}

function finishSweep(counts){
  scanning = false;
  lastSweepAt = new Date();
  document.getElementById('btnScan').disabled = false;
  document.getElementById('mapWrap').classList.remove('scanning');
  pushTranscriptSystem('=== Sweep #'+currentSweep+' complete: '+counts.resolved+' resolved · '+counts.discovered+' new · '+counts.flagged+' flagged ===');
  toast('Sweep #'+currentSweep+' complete — '+counts.resolved+' resolved, '+counts.discovered+' new vulnerabilities, '+counts.flagged+' flagged for review.');
  renderStats(); renderMap(); renderTable(); renderFooter();
}

/* ================= Isolation ================= */
function setIsolated(dev, isolated){
  dev.isolated = isolated;
  pushActivity(isolated?'isolated':'reconnected',
    dev.id + (isolated ? ' — isolated from municipal grid (micro-segmentation applied)' : ' — reconnected to municipal grid'));
  toast((isolated?'Isolated ':'Reconnected ')+dev.id+(isolated?' — traffic segmented from the grid.':' — resuming normal probing.'));
  renderStats(); renderMap(); renderTable();
  if(selectedDeviceId===dev.id) openDrawer(dev.id, true);
}

/* ================= Rendering: stats ================= */
function renderStats(){
  var total = devices.length;
  var active = devices.filter(function(d){return d.online && !d.isolated;}).length;
  var vuln = devices.filter(function(d){return d.vulnerable && !d.isolated;}).length;
  var critical = devices.filter(function(d){return d.vulnerable && d.riskLevel==='critical' && !d.isolated;}).length;
  var isolated = devices.filter(function(d){return d.isolated;}).length;
  var flagged = devices.filter(function(d){return d.flagged && !d.vulnerable && !d.isolated;}).length;
  document.getElementById('statTotal').textContent = total;
  document.getElementById('statActive').textContent = active;
  document.getElementById('statActivePct').textContent = total? Math.round(active/total*100)+'% online' : '—';
  document.getElementById('statVuln').textContent = vuln;
  document.getElementById('statCritical').textContent = critical;
  document.getElementById('statIsolated').textContent = isolated;
  document.getElementById('statFlagged').textContent = flagged;
  renderFooter();
}
function renderFooter(){
  document.getElementById('sweepFooter').textContent = 'Sweep #'+currentSweep+' · '+(lastSweepAt? 'last run '+lastSweepAt.toLocaleTimeString() : 'never run');
}

/* ================= Rendering: map ================= */
function statusOf(dev){
  if(dev.isolated) return 'isolated';
  if(!dev.online) return 'offline';
  if(dev.vulnerable) return dev.riskLevel==='critical' ? 'critical' : 'vulnerable';
  if(dev.flagged) return 'flagged';
  return 'healthy';
}
function statusColorVar(status){
  return {
    healthy:'var(--green)', vulnerable:'var(--amber)', critical:'var(--red)',
    flagged:'var(--orange)', isolated:'var(--cyan)', offline:'var(--grey)'
  }[status];
}

function renderMap(){
  var svg = document.getElementById('topoSvg');
  var parts = [];
  parts.push('<defs><linearGradient id="beamGrad" x1="0" y1="1" x2="0" y2="0">'+
    '<stop offset="0%" stop-color="#FF2E2E" stop-opacity="0"/>'+
    '<stop offset="100%" stop-color="#FF2E2E" stop-opacity="0.55"/></linearGradient></defs>');

  // zone hub labels + connecting backbone
  ZONES.forEach(function(z){
    parts.push('<circle cx="'+z.hub.x+'" cy="'+z.hub.y+'" r="3" fill="none"/>');
  });
  // civic hub to other hubs backbone lines
  var civic = ZONES.filter(function(z){return z.id==='civic';})[0];
  ZONES.forEach(function(z){
    if(z.id!=='civic'){
      parts.push('<line x1="'+civic.hub.x+'" y1="'+civic.hub.y+'" x2="'+z.hub.x+'" y2="'+z.hub.y+'" stroke="#242424" stroke-width="1.5" stroke-dasharray="2 4"/>');
    }
  });

  // device connector lines
  devices.forEach(function(dev){
    var status = statusOf(dev);
    var color = statusColorVar(status);
    if(dev.isolated){
      var sx = dev.x + (dev.hub.x-dev.x)*0.14, sy = dev.y + (dev.hub.y-dev.y)*0.14;
      parts.push('<line x1="'+dev.x+'" y1="'+dev.y+'" x2="'+sx+'" y2="'+sy+'" stroke="'+color+'" stroke-width="1.4" stroke-dasharray="3 3" opacity="0.8"/>');
    } else {
      parts.push('<line x1="'+dev.hub.x+'" y1="'+dev.hub.y+'" x2="'+dev.x+'" y2="'+dev.y+'" stroke="'+color+'" stroke-width="1" opacity="0.16"/>');
    }
  });

  // hub nodes
  ZONES.forEach(function(z){
    var isCivic = z.id==='civic';
    parts.push('<circle cx="'+z.hub.x+'" cy="'+z.hub.y+'" r="'+(isCivic?12:8)+'" fill="'+(isCivic?'#0D0D0D':'#101010')+'" stroke="'+(isCivic?'#FF2E2E':'#333333')+'" stroke-width="1.6"/>');
    if(isCivic){
      parts.push('<circle cx="'+z.hub.x+'" cy="'+z.hub.y+'" r="18" fill="none" stroke="#FF2E2E" stroke-width="1" opacity="0.35"/>');
    }
    parts.push('<text x="'+z.hub.x+'" y="'+(z.hub.y - (isCivic?24:14))+'" text-anchor="middle" font-family="JetBrains Mono" font-size="10" fill="#6B6B64" letter-spacing="0.5">'+z.name.toUpperCase()+'</text>');
  });

  // scan beam
  parts.push('<g transform="translate('+civic.hub.x+','+civic.hub.y+')"><path id="scanBeam" d="M0,0 L0,-300 A300,300 0 0,1 260,-150 Z" fill="url(#beamGrad)" opacity="0"/></g>');

  // device nodes
  devices.forEach(function(dev){
    var status = statusOf(dev);
    var color = statusColorVar(status);
    var r = status==='critical' ? 6.5 : status==='healthy' ? 3.6 : 5;
    var sel = dev.id===selectedDeviceId;
    parts.push('<g class="node" id="node-'+dev.id+'" data-id="'+dev.id+'" style="color:'+color+'">'+
      (sel?'<circle cx="'+dev.x+'" cy="'+dev.y+'" r="'+(r+6)+'" fill="none" stroke="'+color+'" stroke-width="1.4" opacity="0.6"/>':'')+
      '<circle cx="'+dev.x+'" cy="'+dev.y+'" r="'+r+'" fill="'+color+'" opacity="'+(status==='offline'?0.35:0.95)+'"/>'+
      '<title>'+dev.id+' — '+dev.categoryLabel+' ('+status+')</title>'+
      '</g>');
  });

  svg.innerHTML = parts.join('');
  svg.querySelectorAll('.node').forEach(function(n){
    n.addEventListener('click', function(){ openDrawer(n.getAttribute('data-id')); });
  });
}

function pingNode(id){
  var node = document.getElementById('node-'+id);
  if(!node) return;
  var circ = node.querySelector('circle:last-of-type');
  if(!circ) return;
  var ring = document.createElementNS('http://www.w3.org/2000/svg','circle');
  ring.setAttribute('cx', circ.getAttribute('cx'));
  ring.setAttribute('cy', circ.getAttribute('cy'));
  ring.setAttribute('r','4');
  ring.setAttribute('class','ping-ring');
  ring.style.color = node.style.color;
  node.appendChild(ring);
  ring.addEventListener('animationend', function(){ ring.remove(); });
}

/* ================= Rendering: transcript / activity ================= */
function clearTranscript(){
  document.getElementById('transcript').innerHTML = '<div class="transcript-empty">// No sweep has run yet. Click "Run scan sweep" to start interrogating nodes.</div>';
}
function clearActivity(){
  document.getElementById('activityLog').innerHTML = '<div class="transcript-empty" style="padding:10px 4px;">// Waiting for first sweep or manual action…</div>';
}
function pushTranscriptSystem(text){
  var el = document.getElementById('transcript');
  if(el.querySelector('.transcript-empty')) el.innerHTML='';
  var line = document.createElement('div');
  line.className = 'transcript-line';
  line.innerHTML = '<span class="tag">'+text+'</span>';
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
  trimChildren(el, 140);
}
function pushTranscriptEntry(dev, entry){
  var el = document.getElementById('transcript');
  if(el.querySelector('.transcript-empty')) el.innerHTML='';
  var outcomeClass = entry.outcome==='vulnerability_resolved'?'t-outcome-resolved':entry.outcome==='new_vulnerability_found'?'t-outcome-new':entry.outcome==='flagged_no_matching_cve'?'t-outcome-flag':'';
  var qaHtml = entry.qa.map(function(qa){
    return '<span class="t-scanner">SCANNER→'+dev.id+':</span> "'+qa.q+'" &nbsp; <span class="t-device">'+dev.id+'→SCANNER:</span> "'+qa.a+'"';
  }).join('<br>');
  var line = document.createElement('div');
  line.className = 'transcript-line';
  line.innerHTML = '<span class="tag">['+entry.ts+']</span><br>'+qaHtml+(entry.outcome!=='no_change'?'<br><span class="'+outcomeClass+'">→ '+entry.outcome+'</span>':'');
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
  trimChildren(el, 140);
}
function trimChildren(el, max){
  while(el.children.length>max){ el.removeChild(el.firstChild); }
}
function pushActivity(type, text){
  var el = document.getElementById('activityLog');
  if(el.querySelector('.transcript-empty')) el.innerHTML='';
  var icoMap = {resolved:{c:'var(--green)',s:'✓'}, discovered:{c:'var(--red)',s:'!'}, flagged:{c:'var(--orange)',s:'?'}, isolated:{c:'var(--cyan)',s:'×'}, reconnected:{c:'var(--green)',s:'+'}};
  var ico = icoMap[type] || {c:'var(--text-dim)',s:'•'};
  var item = document.createElement('div');
  item.className = 'activity-item';
  item.innerHTML = '<span class="ico" style="background:'+ico.c+'22;color:'+ico.c+'">'+ico.s+'</span>'+
    '<span class="txt">'+text+'</span><span class="time">'+timeLabel()+'</span>';
  el.prepend(item);
  trimChildren(el, 80);
}

/* ================= Rendering: devices table ================= */
function populateZoneSelect(){
  var sel = document.getElementById('zoneSelect');
  sel.innerHTML = '<option value="all">All zones</option>' + ZONES.map(function(z){return '<option value="'+z.id+'">'+z.name+'</option>';}).join('');
}

function matchesStatus(dev, status){
  var s = statusOf(dev);
  if(status==='all') return true;
  if(status==='vulnerable') return s==='vulnerable' || s==='critical';
  return s===status;
}

function renderTable(){
  var body = document.getElementById('devicesBody');
  var q = filters.q.trim().toLowerCase();
  var list = devices.filter(function(d){
    if(!matchesStatus(d, filters.status)) return false;
    if(filters.zone!=='all' && d.zoneId!==filters.zone) return false;
    if(q && !(d.id.toLowerCase().indexOf(q)>-1 || d.vendor.toLowerCase().indexOf(q)>-1 || d.zoneName.toLowerCase().indexOf(q)>-1)) return false;
    return true;
  });
  if(filters.sort==='risk') list.sort(function(a,b){ return b.riskScore - a.riskScore; });
  else if(filters.sort==='id') list.sort(function(a,b){ return a.id.localeCompare(b.id); });
  else if(filters.sort==='zone') list.sort(function(a,b){ return a.zoneName.localeCompare(b.zoneName); });

  if(list.length===0){
    body.innerHTML = '<tr class="empty-row"><td colspan="8">No devices match the current filters.</td></tr>';
    return;
  }

  body.innerHTML = list.map(function(dev){
    var status = statusOf(dev);
    var badgeClass = 'badge-'+(status==='vulnerable'?'medium':status);
    var portsHtml = dev.ports.map(function(p){
      var risky = [21,23,502].indexOf(p)>-1;
      return '<span class="port-badge'+(risky?' risky':'')+'">'+p+'</span>';
    }).join('');
    return '<tr data-id="'+dev.id+'">'+
      '<td><div class="mono" style="font-weight:600;">'+dev.id+'</div><div style="font-size:11px;color:var(--text-faint);">'+dev.categoryLabel+'</div></td>'+
      '<td>'+dev.zoneName+'</td>'+
      '<td>'+dev.vendor+'</td>'+
      '<td class="mono">'+dev.firmware+'</td>'+
      '<td>'+portsHtml+'</td>'+
      '<td><span class="risk-bar-wrap"><span class="risk-bar" style="width:'+Math.min(dev.riskScore,100)+'%;background:'+riskColor(dev.riskLevel)+'"></span></span><span class="mono">'+dev.riskScore+'</span></td>'+
      '<td><span class="badge '+badgeClass+'" style="color:'+statusColorVar(status)+'">'+status+'</span></td>'+
      '<td class="row-actions">'+
        '<button class="icon-btn" data-view="'+dev.id+'" title="View details"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg></button>'+
        '<button class="icon-btn" data-toggle="'+dev.id+'" title="'+(dev.isolated?'Reconnect':'Isolate')+'">'+
          (dev.isolated
            ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 12h16"/><path d="M14 6l6 6-6 6"/></svg>'
            : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.4 5.6a9 9 0 1 1-12.8 0"/><path d="M12 2v10"/></svg>')+
        '</button>'+
      '</td>'+
    '</tr>';
  }).join('');

  body.querySelectorAll('tr[data-id]').forEach(function(row){
    row.addEventListener('click', function(e){
      if(e.target.closest('button')) return;
      openDrawer(row.getAttribute('data-id'));
    });
  });
  body.querySelectorAll('[data-view]').forEach(function(btn){
    btn.addEventListener('click', function(){ openDrawer(btn.getAttribute('data-view')); });
  });
  body.querySelectorAll('[data-toggle]').forEach(function(btn){
    btn.addEventListener('click', function(){
      var dev = devices.filter(function(d){return d.id===btn.getAttribute('data-toggle');})[0];
      if(dev) setIsolated(dev, !dev.isolated);
    });
  });
}

/* ================= Drawer ================= */
function openDrawer(id, silent){
  var dev = devices.filter(function(d){return d.id===id;})[0];
  if(!dev) return;
  selectedDeviceId = id;
  var status = statusOf(dev);
  var firmwareFactor = dev.firmwareMajor===1?40:dev.firmwareMajor===2?25:dev.firmwareMajor===3?10:0;
  var portRows = dev.ports.map(function(p){
    var meta = PORTS.filter(function(x){return x.port===p;})[0];
    return {label:'Port '+p+' ('+meta.name+')', pts:meta.risk};
  });
  var historyHtml = dev.history.slice(0,8).map(function(h){
    var qaHtml = h.qa.map(function(qa){ return '<div class="qa"><span class="q">Q:</span> '+qa.q+' <br><span style="color:var(--text-faint)">A:</span> '+qa.a+'</div>'; }).join('');
    return '<div class="probe-entry"><span class="sweep-tag">SWEEP #'+h.sweep+' · '+h.ts+' · '+h.outcome+'</span>'+qaHtml+'</div>';
  }).join('') || '<div class="transcript-empty">No probe history yet — run a scan sweep.</div>';

  var html = ''+
  '<div class="drawer-head">'+
    '<div><h2>'+dev.id+'</h2><div class="cat">'+dev.categoryLabel+' · '+dev.zoneName+'</div></div>'+
    '<button class="drawer-close" id="drawerCloseBtn">✕</button>'+
  '</div>'+
  '<div class="drawer-section">'+
    '<h4>Overview</h4>'+
    '<div class="meta-grid">'+
      '<div><div class="k">Vendor</div><div class="v">'+dev.vendor+'</div></div>'+
      '<div><div class="k">Firmware</div><div class="v">'+dev.firmware+'</div></div>'+
      '<div><div class="k">Status</div><div class="v" style="color:'+statusColorVar(status)+'">'+status+'</div></div>'+
      '<div><div class="k">Online</div><div class="v">'+(dev.online?'yes':'no response')+'</div></div>'+
      '<div><div class="k">Coordinates</div><div class="v">'+dev.x.toFixed(1)+', '+dev.y.toFixed(1)+' (map units)</div></div>'+
      '<div><div class="k">Last probed</div><div class="v">'+(dev.lastSeen? 'sweep #'+dev.lastSeen : '—')+'</div></div>'+
    '</div>'+
  '</div>'+
  '<div class="drawer-section">'+
    '<h4>Risk score breakdown</h4>'+
    '<div class="risk-line"><span>Firmware ('+dev.firmware+')</span><b>+'+firmwareFactor+'</b></div>'+
    portRows.map(function(r){ return '<div class="risk-line"><span>'+r.label+'</span><b>+'+r.pts+'</b></div>'; }).join('')+
    '<div class="risk-total"><span>Total exposure score</span><span style="color:'+riskColor(dev.riskLevel)+'">'+dev.riskScore+' — '+dev.riskLevel+'</span></div>'+
    (dev.cve ? '<div class="cve-box"><div class="id">'+dev.cve.id+'</div><div class="desc">'+dev.cve.text+'</div></div>' : '')+
    (dev.flagged && !dev.vulnerable ? '<div class="cve-box" style="border-color:rgba(255,157,82,.3)"><div class="id" style="color:var(--orange)">FLAGGED — NO MATCHING CVE</div><div class="desc">Device reported an elevated signal during probing, but no CVE record matches this vendor/firmware combination yet. Routed to manual analyst review rather than dropped.</div></div>' : '')+
  '</div>'+
  '<div class="drawer-section">'+
    '<h4>Probe history (latest 8)</h4>'+
    historyHtml+
  '</div>'+
  '<div class="drawer-actions">'+
    (dev.isolated
      ? '<button class="btn btn-primary" id="drawerToggleBtn">Reconnect to grid</button>'
      : '<button class="btn btn-danger-outline" id="drawerToggleBtn">Isolate (micro-segment)</button>')+
  '</div>';

  document.getElementById('drawer').innerHTML = html;
  document.getElementById('drawer').classList.add('show');
  document.getElementById('overlay').classList.add('show');
  document.getElementById('drawerCloseBtn').addEventListener('click', closeDrawer);
  document.getElementById('drawerToggleBtn').addEventListener('click', function(){ setIsolated(dev, !dev.isolated); });
  if(!silent) renderMap();
  else {
    document.querySelectorAll('.node').forEach(function(n){});
  }
}
function closeDrawer(){
  document.getElementById('drawer').classList.remove('show');
  document.getElementById('overlay').classList.remove('show');
  selectedDeviceId = null;
  renderMap();
}
document.getElementById('overlay').addEventListener('click', closeDrawer);

/* ================= Toasts ================= */
function toast(text){
  var stack = document.getElementById('toastStack');
  var el = document.createElement('div');
  el.className = 'toast';
  el.textContent = text;
  stack.appendChild(el);
  setTimeout(function(){ el.style.opacity='0'; el.style.transition='opacity .3s'; setTimeout(function(){ el.remove(); }, 300); }, 4200);
}

/* ================= Export ================= */
function exportSnapshot(){
  var data = {
    generatedAt: new Date().toISOString(),
    seed: SEED,
    sweep: currentSweep,
    stats: {
      total: devices.length,
      active: devices.filter(function(d){return d.online && !d.isolated;}).length,
      vulnerable: devices.filter(function(d){return d.vulnerable;}).length,
      isolated: devices.filter(function(d){return d.isolated;}).length,
      flagged: devices.filter(function(d){return d.flagged && !d.vulnerable;}).length
    },
    devices: devices.map(function(d){
      return {
        id:d.id, category:d.categoryLabel, zone:d.zoneName, vendor:d.vendor, firmware:d.firmware,
        ports:d.ports, riskScore:d.riskScore, riskLevel:d.riskLevel, status:statusOf(d),
        cve: d.cve ? d.cve.id+' — '+d.cve.text : null
      };
    })
  };
  var blob = new Blob([JSON.stringify(data,null,2)], {type:'application/json'});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = 'sentinel-snapshot-sweep'+currentSweep+'.json';
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
  toast('Snapshot exported — sentinel-snapshot-sweep'+currentSweep+'.json');
}

/* ================= Wiring ================= */
function renderAll(){ renderStats(); renderMap(); renderTable(); document.getElementById('seedInput').value = SEED; }

document.getElementById('btnScan').addEventListener('click', runScanSweep);
document.getElementById('btnExport').addEventListener('click', exportSnapshot);
document.getElementById('btnReseed').addEventListener('click', function(){
  var v = parseInt(document.getElementById('seedInput').value, 10);
  SEED = isNaN(v) ? Math.floor(Math.random()*900000)+100000 : v;
  rand = mulberry32(SEED);
  generateCity();
  toast('City regenerated with seed '+SEED);
});
document.getElementById('searchInput').addEventListener('input', function(e){ filters.q = e.target.value; renderTable(); });
document.getElementById('zoneSelect').addEventListener('change', function(e){ filters.zone = e.target.value; renderTable(); });
document.getElementById('sortSelect').addEventListener('change', function(e){ filters.sort = e.target.value; renderTable(); });
document.getElementById('statusChips').addEventListener('click', function(e){
  var btn = e.target.closest('.chip');
  if(!btn) return;
  filters.status = btn.getAttribute('data-status');
  document.querySelectorAll('#statusChips .chip').forEach(function(c){ c.classList.remove('active'); });
  btn.classList.add('active');
  renderTable();
});
document.getElementById('btnArch').addEventListener('click', function(){ document.getElementById('archModal').classList.add('show'); });
document.getElementById('btnLogic').addEventListener('click', function(){ document.getElementById('logicModal').classList.add('show'); });
document.querySelectorAll('[data-close-modal]').forEach(function(btn){
  btn.addEventListener('click', function(){ btn.closest('.modal-overlay').classList.remove('show'); });
});
document.querySelectorAll('.modal-overlay').forEach(function(m){
  m.addEventListener('click', function(e){ if(e.target===m) m.classList.remove('show'); });
});

function tickClock(){
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}
setInterval(tickClock, 1000); tickClock();

/* ================= Init ================= */
generateCity();
})();