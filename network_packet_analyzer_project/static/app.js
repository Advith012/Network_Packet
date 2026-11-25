const $ = (id) => document.getElementById(id);
let selectedPacket = null;
let protocolChart, trafficChart;

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
function setMessage(message, error=false) {
  $("message").textContent = message;
  $("message").className = error ? "message error" : "message";
}
async function api(url, options={}) {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || data.error || `Request failed (${res.status})`);
  return data;
}
async function loadInterfaces() {
  try {
    const data = await api("/api/interfaces");
    const select = $("interface");
    for (const name of data.interfaces || []) {
      const option = document.createElement("option");
      option.value = name; option.textContent = name;
      select.appendChild(option);
    }
  } catch (e) { setMessage(`Could not list interfaces: ${e.message}`, true); }
}
async function startCapture() {
  try {
    const data = await api("/api/capture/start", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({interface:$("interface").value})
    });
    setMessage(data.message);
    await refresh();
  } catch(e) { setMessage(`${e.message}. Check capture permissions and interface selection.`, true); }
}
async function stopCapture() {
  try { const data = await api("/api/capture/stop", {method:"POST"}); setMessage(data.message); }
  catch(e) { setMessage(e.message, true); }
}
async function clearPackets() {
  try { await api("/api/clear", {method:"POST"}); selectedPacket=null; renderDetails(null); await refresh(); }
  catch(e) { setMessage(e.message, true); }
}
function renderPackets(data) {
  const tbody = $("packetRows");
  $("visibleCount").textContent = `${data.length} packets`;
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty">No packets match the current filters.</td></tr>';
    return;
  }
  tbody.innerHTML = "";
  for (const p of data) {
    const tr = document.createElement("tr");
    const vals = [p.id,p.timestamp,p.source_ip,p.destination_ip,p.protocol,p.source_port ?? "-",p.destination_port ?? "-",p.size];
    vals.forEach((v,i) => {
      const td = document.createElement("td");
      td.textContent = v;
      if (i === 4) td.className = "protocol";
      tr.appendChild(td);
    });
    tr.addEventListener("click", () => { selectedPacket=p; renderDetails(p); });
    tbody.appendChild(tr);
  }
}
function renderDetails(p) {
  const box = $("details");
  if (!p) { box.innerHTML = '<p class="muted">Select a packet row to view details.</p>'; return; }
  const fields = [["Packet ID",p.id],["Timestamp",p.timestamp],["Source IP",p.source_ip],["Destination IP",p.destination_ip],["Protocol",p.protocol],["Source Port",p.source_port ?? "N/A"],["Destination Port",p.destination_port ?? "N/A"],["Packet Size",`${p.size} bytes`]];
  box.innerHTML = fields.map(([k,v]) => `<div class="detail-item"><span>${k}</span><strong></strong></div>`).join("");
  [...box.querySelectorAll(".detail-item strong")].forEach((el,i)=>el.textContent=fields[i][1]);
}
function initCharts() {
  if (!window.Chart) return;
  protocolChart = new Chart($("protocolChart"), {
    type:"doughnut",
    data:{labels:["TCP","UDP","ICMP","ARP","Other"],datasets:[{data:[0,0,0,0,0]}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:"bottom"}}}
  });
  trafficChart = new Chart($("trafficChart"), {
    type:"line",
    data:{labels:[],datasets:[{label:"Bytes per recent packet",data:[],tension:.25,fill:true}]},
    options:{responsive:true,maintainAspectRatio:false,scales:{y:{beginAtZero:true}}}
  });
}
async function refresh() {
  try {
    const protocol = $("protocolFilter").value;
    const ip = $("ipFilter").value.trim();
    const [status, stats, packetData] = await Promise.all([
      api("/api/capture/status"), api("/api/statistics"),
      api(`/api/packets?protocol=${encodeURIComponent(protocol)}&ip=${encodeURIComponent(ip)}&limit=300`)
    ]);
    $("status").className = `status ${status.running ? "running" : "stopped"}`;
    $("status").lastElementChild.textContent = status.running ? "Capturing" : "Stopped";
    $("startBtn").disabled = status.running;
    $("stopBtn").disabled = !status.running;
    $("total").textContent = stats.total_packets.toLocaleString();
    $("tcp").textContent = stats.tcp.toLocaleString();
    $("udp").textContent = stats.udp.toLocaleString();
    $("other").textContent = (stats.icmp + stats.arp + stats.other).toLocaleString();
    $("bytes").textContent = formatBytes(stats.total_bytes);
    $("avg").textContent = `${stats.average_size} B`;
    renderPackets(packetData.packets);
    if (protocolChart) {
      protocolChart.data.datasets[0].data = [stats.tcp,stats.udp,stats.icmp,stats.arp,stats.other];
      protocolChart.update("none");
    }
    if (trafficChart) {
      const recent = packetData.packets.slice(0,30).reverse();
      trafficChart.data.labels = recent.map(p=>p.timestamp);
      trafficChart.data.datasets[0].data = recent.map(p=>p.size);
      trafficChart.update("none");
    }
    if (status.error) setMessage(`Capture error: ${status.error}`, true);
  } catch(e) { setMessage(`Dashboard update failed: ${e.message}`, true); }
}
$("startBtn").addEventListener("click", startCapture);
$("stopBtn").addEventListener("click", stopCapture);
$("clearBtn").addEventListener("click", clearPackets);
$("resetFilter").addEventListener("click",()=>{$("protocolFilter").value="All";$("ipFilter").value="";refresh();});
$("protocolFilter").addEventListener("change",refresh);
$("ipFilter").addEventListener("input",()=>{clearTimeout(window.filterTimer);window.filterTimer=setTimeout(refresh,250);});
initCharts(); loadInterfaces(); refresh(); setInterval(refresh,1500);
