"use strict";

(() => {
  const $ = id => document.getElementById(id);
  const state = { inventory: null, base: null, tab: "dashboard", pending: null, job: null, report: null, timer: null, busy: false };
  const labels = { nuclei: "Nuclei · templates revisados", zap: "OWASP ZAP", http_headers: "Cabeçalhos HTTP", tcp_connect: "Conexões TCP", tls_certificate: "Certificado TLS", nmap_service: "Nmap · serviços", appsec_sqli: "SQLi · marcadores fictícios", appsec_auth: "Autenticação · contas A/B", code_audit: "Code Auditor", static_file: "Análise estática + YARA-X", investigate: "YARA-X + REA", ghidra: "Ghidra headless", rea: "REA MCP", asset_inventory: "Inventário DNS/HTTP/TLS", osint: "Pesquisa pública delimitada", cve: "Consulta CVE", windows: "Windows · somente leitura" };
  const modules = [
    ["web", "WEB PENTEST", ["http_headers", "nuclei", "zap"]], ["network", "NETWORK SECURITY", ["tcp_connect", "tls_certificate", "nmap_service"]],
    ["auth", "AUTH & DATABASE SECURITY", ["appsec_sqli", "appsec_auth"]], ["code", "CODE SECURITY", ["code_audit"]],
    ["malware", "MALWARE ANALYSIS", ["static_file", "investigate"]], ["reverse", "REVERSE ENGINEERING", ["ghidra", "rea"]],
    ["osint", "OSINT & INVESTIGATION", ["asset_inventory", "osint", "cve"]], ["blue", "BLUE TEAM", ["windows"]],
    ["remediation", "AUTO-REMEDIATION", []], ["reports", "REPORT CENTER", []]
  ];
  const network = new Set(["http_headers", "tcp_connect", "tls_certificate", "nmap_service", "nuclei", "zap", "appsec_sqli", "appsec_auth", "asset_inventory", "osint"]);
  const text = value => typeof value === "string" ? value : JSON.stringify(value, null, 2) || "";
  const arr = (value, key) => Array.isArray(value) ? value : Array.isArray(value?.[key]) ? value[key] : [];
  const node = (tag, cls, value) => { const el = document.createElement(tag); if (cls) el.className = cls; if (value !== undefined) el.textContent = String(value); return el; };
  const button = (value, fn, primary = false) => { const el = node("button", primary ? "primary-button" : "secondary-button", value); el.type = "button"; el.addEventListener("click", () => action(fn)); return el; };
  const detail = (title, value) => { const el = node("details"); el.append(node("summary", "", title), node("pre", "", text(value))); return el; };
  const message = (value, error = false) => { $("sec2-status").textContent = value; $("sec2-status").classList.toggle("error", error); };
  async function api(path, json) {
    const response = await fetch(path.startsWith("/api/") ? path : "/api/security/v2" + path, { credentials: "same-origin", cache: "no-store", ...(json === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(json) }) });
    let value; try { value = await response.json(); } catch (_) { throw new Error(`Resposta inválida (HTTP ${response.status}).`); }
    if (!response.ok) throw new Error(typeof value.error === "string" ? value.error : typeof value.detail === "string" ? value.detail : `Operação falhou (HTTP ${response.status}).`);
    return value;
  }
  async function action(fn) { try { await fn(); } catch (error) { message(error.message || String(error), true); } }
  function field(parent, id, label, { value = "", type = "text", options, required = false, rows = 4, help } = {}) {
    const wrap = node("div", "sec2-field"), lab = node("label", "", label); lab.htmlFor = id;
    const el = node(options ? "select" : type === "textarea" ? "textarea" : "input"); el.id = id; el.name = id; el.required = required;
    if (options) for (const [key, name] of options) { const op = node("option", "", name); op.value = key; el.append(op); }
    else if (type === "textarea") { el.rows = rows; el.spellcheck = false; } else { el.type = type; el.autocomplete = "off"; }
    el.value = value; wrap.append(lab, el); if (help) wrap.append(node("p", "sec2-muted", help)); parent.append(wrap); return el;
  }
  function check(parent, id, label) { const wrap = node("label", "sec2-check"), input = node("input"); input.type = "checkbox"; input.id = id; wrap.append(input, node("span", "", label)); parent.append(wrap); return input; }
  const choices = (rows, key = "id", label = "name") => [["", "Selecione…"], ...rows.map(row => [row[key], row[label] || row[key]])];
  const scopes = () => arr(state.base, "scopes").filter(scope => scope.enabled !== false);
  function empty(parent, value) { parent.append(node("p", "sec2-empty", value)); }
  function badge(parent, value, mode = "") { parent.append(node("span", "sec2-badge " + mode, value)); }
  function available(engine) {
    if (["nuclei", "zap", "nmap_service"].includes(engine)) {
      const row = arr(state.inventory?.scanners, "tools").find(item => item.id === engine);
      return { ok: row?.configured === true, reason: row?.note || "Ferramenta ausente ou ainda não aprovada.", row };
    }
    if (engine === "ghidra") return { ok: state.inventory?.ghidra?.available === true, reason: state.inventory?.ghidra?.reason || state.inventory?.ghidra?.error || "Instalação/JDK não configurados; nenhuma decompilação executada." };
    return { ok: arr(state.inventory, "integrated_engines").includes(engine), reason: "Adaptador integrado; a disponibilidade de provedores e permissões é conferida na execução." };
  }
  function selectTab(tab) {
    state.tab = tab; $("sec2-content").replaceChildren(); $("sec2-content").scrollTop = 0;
    document.querySelectorAll("[data-sec2-tab]").forEach(el => { const selected = el.dataset.sec2Tab === tab; el.classList.toggle("selected", selected); if (selected) el.setAttribute("aria-current", "page"); else el.removeAttribute("aria-current"); });
    const root = $("sec2-content");
    if (tab === "dashboard") dashboard(root);
    else if (tab === "targets") targets(root);
    else if (tab === "tools") tools(root);
    else if (tab === "jobs") jobs(root);
    else if (tab === "reports") reports(root);
    else if (tab === "remediation") remediation(root);
    else audit(root, modules.find(row => row[0] === tab));
  }
  function title(root, name, description) { root.append(node("h3", "", name), node("p", "sec2-description", description)); }
  async function refresh() {
    message("Consultando inventário e histórico locais…");
    const results = await Promise.allSettled([api("/status"), api("/api/security/status")]);
    if (results[0].status === "rejected") throw results[0].reason;
    state.inventory = results[0].value;
    if (results[1].status === "fulfilled") state.base = results[1].value;
    else message("Módulos 2.0 carregados; cadastro anterior indisponível: " + results[1].reason.message, true);
    selectTab(state.tab); message("Inventário atualizado. Ferramentas ausentes e cobertura limitada são indicadas abaixo.");
  }
  function dashboard(root) {
    title(root, "Auditoria com evidências", "Ferramentas reais, escopos explícitos e correção supervisionada. Um resultado sem achados informa somente a cobertura executada.");
    const metrics = node("div", "sec2-metrics");
    for (const [value, label] of [[scopes().length, "Escopos ativos"], [arr(state.inventory, "runs").filter(r => ["queued", "running", "cancelling"].includes(r.state)).length, "Tarefas ativas"], [arr(state.base, "reports").length, "Relatórios recentes"], ["1", "Execução por vez"]]) { const card = node("div", "sec2-metric"); card.append(node("strong", "", value), node("span", "", label)); metrics.append(card); }
    root.append(metrics);
    const grid = node("div", "sec2-grid");
    for (const [id, name, engines] of modules) { const card = node("article", "sec2-card"); card.append(node("h4", "", name)); if (engines.length) for (const engine of engines) { const row = available(engine); badge(card, labels[engine] + (row.ok ? " · integrado" : " · indisponível"), row.ok ? "ready" : "unavailable"); } else card.append(node("p", "sec2-muted", id === "remediation" ? "Selecione achados, revise diffs, aprove escritas e revalide." : "Evidências, correlação e exportação JSON/HTML/Markdown; PDF conforme dependência.")); card.append(button("Abrir módulo", () => selectTab(id))); grid.append(card); }
    root.append(grid, detail("Limites e isolamento", state.inventory?.limits || {}));
  }
  function targets(root) {
    title(root, "Alvos e escopos", "Autorize domínios/IPs, portas, ambiente e tipos de teste. Escopo não substitui a aprovação específica de cada execução.");
    const form = node("form", "sec2-form"); form.id = "sec2-scope-form";
    field(form, "sec2-scope-name", "Nome", { required: true });
    field(form, "sec2-scope-targets", "Domínios/IPs · um por linha", { type: "textarea", value: "127.0.0.1", rows: 2, required: true });
    field(form, "sec2-scope-ports", "Portas autorizadas · separadas por vírgula", { value: "8899", required: true });
    field(form, "sec2-scope-env", "Ambiente", { value: "lab", options: [["lab", "Laboratório · dados fictícios"], ["staging", "Homologação"], ["production", "Produção · testes ativos limitados"]] });
    field(form, "sec2-scope-hosting", "Hospedagem", { value: "own", options: [["own", "Infraestrutura própria"], ["shared", "Compartilhada"], ["vercel", "Vercel"], ["other", "Outro provedor"]] });
    field(form, "sec2-scope-purpose", "Finalidade", { value: "Auditoria autorizada de aplicação própria com dados fictícios", required: true });
    const tests = node("fieldset", "sec2-tests"); tests.append(node("legend", "", "Tipos de teste permitidos"));
    for (const key of network) check(tests, "sec2-permission-" + key, labels[key]);
    form.append(tests); check(form, "sec2-scope-subdomains", "Incluir subdomínios do domínio informado.");
    check(form, "sec2-scope-provider", "Tenho autorização do provedor para os testes ativos selecionados.");
    const authorization = check(form, "sec2-scope-authorization", "Confirmo responsabilidade e autorização para os alvos, portas e testes acima."); authorization.required = true;
    const submit = node("button", "primary-button", "Cadastrar escopo"); submit.type = "submit"; form.append(submit);
    form.addEventListener("submit", event => { event.preventDefault(); action(async () => { const allowed = [...network].filter(key => $("sec2-permission-" + key).checked); const environment = $("sec2-scope-env").value; await api("/api/security/scopes", { name: $("sec2-scope-name").value, targets: $("sec2-scope-targets").value.split(/\r?\n/).map(v => v.trim()).filter(Boolean), allowed_ports: $("sec2-scope-ports").value.split(",").map(v => Number(v.trim())), environment, environment_class: environment, hosting: $("sec2-scope-hosting").value, purpose: $("sec2-scope-purpose").value, allowed_tests: allowed, include_subdomains: $("sec2-scope-subdomains").checked, provider_authorization: $("sec2-scope-provider").checked, authorization_confirmed: authorization.checked }); await refresh(); message("Escopo cadastrado; cada execução ainda exige uma aprovação específica."); }); });
    root.append(form, node("h4", "", "Escopos cadastrados"));
    if (!arr(state.base, "scopes").length) empty(root, "Nenhum escopo cadastrado.");
    for (const scope of arr(state.base, "scopes")) { const card = node("article", "sec2-card"); card.append(node("h4", "", scope.name)); badge(card, scope.enabled ? "Ativo" : "Revogado", scope.enabled ? "ready" : "unavailable"); card.append(node("p", "sec2-muted", `${scope.targets.join(", ")} · portas: ${(scope.allowed_ports || []).join(", ") || "não informadas"} · ${scope.environment}`), detail("Permissões do escopo", scope)); if (scope.enabled) card.append(button("Revogar escopo", async () => { const response = await fetch("/api/security/scopes/" + encodeURIComponent(scope.id), { method: "DELETE", credentials: "same-origin" }); if (!response.ok) throw new Error("Falha ao revogar o escopo."); await refresh(); })); root.append(card); }
  }
  function tools(root) {
    title(root, "Inventário e configuração", "Descoberta não executa ferramentas. Revise origem, caminho e hash antes de aprovar a configuração. Nenhum botão inicia download automático.");
    for (const row of [...arr(state.inventory?.scanners, "tools"), { id: "ghidra", ...state.inventory?.ghidra }]) { const card = node("article", "sec2-card"); card.append(node("h4", "", labels[row.id] || row.id)); badge(card, row.configured || row.id === "ghidra" && row.available ? "Configurado · versão conferida ao executar" : row.available ? "Detectado · não aprovado" : "Indisponível", row.configured ? "ready" : "unavailable"); card.append(node("p", "sec2-muted", row.note || row.reason || row.error || "Consulte os detalhes de disponibilidade."), detail("Detalhes observados", row)); root.append(card); }
    const installation = state.inventory?.installation, portable = node("article", "sec2-card"); portable.id = "sec2-installation";
    portable.append(node("h4", "", "Nuclei portátil · instalação opcional"));
    badge(portable, installation?.installed ? "Baixado · configuração exige aprovação separada" : "Download pendente de aprovação", installation?.installed ? "ready" : "unavailable");
    portable.append(node("p", "sec2-muted", "A prévia informa versão, origem, tamanho, hash e destino. Somente sua aprovação inicia o download; instalar não configura nem executa o scanner."));
    if (installation) portable.append(detail("Metadados da instalação portátil", installation));
    if (!installation?.installed) { const install = button("Revisar instalação portátil do Nuclei (46 MB)", async () => showApproval(await api("/installations/preview", { tool: "nuclei" }))); install.id = "sec2-install-nuclei"; portable.append(install); }
    else if (installation.path) portable.append(button("Preencher configuração com caminho instalado", () => { $("sec2-config-engine").value = "nuclei"; const hash = installation.sha256 || installation.exe_sha256; $("sec2-config-json").value = JSON.stringify({ path: installation.path, ...(hash ? { sha256: hash } : {}) }, null, 2); $("sec2-config-json").scrollIntoView({ behavior: "smooth", block: "center" }); message("Caminho preenchido. Revise o hash e aprove a configuração separadamente; nenhum scanner foi iniciado."); }));
    portable.append(node("p", "sec2-muted", "ZAP, Ghidra, Nmap e JDK: instalação manual por fontes oficiais, com aprovação específica para novos downloads. O inventário continua indicando ausência até haver uma instalação válida e configurada."));
    const sources = node("div", "sec2-actions");
    for (const [label, href] of [["ZAP · fonte oficial", "https://www.zaproxy.org/download/"], ["Ghidra · releases oficiais", "https://github.com/NationalSecurityAgency/ghidra/releases"], ["Nmap · fonte oficial", "https://nmap.org/download.html"]]) { const link = node("a", "secondary-button", label); link.href = href; link.target = "_blank"; link.rel = "noopener noreferrer"; sources.append(link); }
    portable.append(sources, node("p", "sec2-muted", "Para Java, escolha a distribuição oficial do fornecedor de JDK e confira a compatibilidade com o ZAP/Ghidra instalado. Nenhum JDK é baixado por este painel.")); root.append(portable);
    const form = node("form", "sec2-form");
    const engine = field(form, "sec2-config-engine", "Motor", { options: [["nuclei", "Nuclei"], ["zap", "OWASP ZAP"], ["nmap_service", "Nmap"], ["ghidra", "Ghidra"]], value: "nuclei" });
    const config = field(form, "sec2-config-json", "Configuração local · JSON", { type: "textarea", rows: 7, value: JSON.stringify({ path: "C:\\Ferramentas\\nuclei.exe" }, null, 2), help: "O servidor calcula o hash observado e exige sua aprovação antes de executar esses bytes. Hash isolado não comprova origem oficial." });
    engine.addEventListener("change", () => { config.value = JSON.stringify(engine.value === "zap" ? { jar: "C:\\Ferramentas\\ZAP\\zap.jar", java: "C:\\Java\\bin\\java.exe" } : engine.value === "ghidra" ? { install_dir: "C:\\Ferramentas\\ghidra", java_home: "C:\\Java", isolation_acknowledged: true } : { path: "C:\\Ferramentas\\" + (engine.value === "nuclei" ? "nuclei.exe" : "nmap.exe") }, null, 2); });
    const submit = node("button", "primary-button", "Revisar configuração e hash"); submit.type = "submit"; form.append(submit); form.addEventListener("submit", event => { event.preventDefault(); action(async () => showApproval(await api("/configuration/preview", { engine: engine.value, config: parseJSON(config.value) }))); });
    root.append(form, detail("Templates revisados · versões e hashes", state.inventory?.scanners?.templates || []));
  }
  function parseJSON(value) { let row; try { row = JSON.parse(value || "{}"); } catch (_) { throw new Error("JSON inválido. Corrija a sintaxe antes de preparar a operação."); } if (!row || Array.isArray(row) || typeof row !== "object") throw new Error("Informe um objeto JSON."); return row; }
  function audit(root, module) {
    if (!module) return;
    title(root, module[1], "Prepare uma operação delimitada. A próxima tela mostra o impacto e pede aprovação humana antes de executar.");
    const form = node("form", "sec2-form"); form.id = "sec2-audit-form";
    const engine = field(form, "sec2-engine", "Mecanismo", { options: module[2].map(key => [key, labels[key]]), value: module[2][0] });
    const availability = node("p", "sec2-note"); form.append(availability);
    field(form, "sec2-profile", "Perfil de auditoria", { options: [["PASSIVE", "PASSIVE · observação limitada"], ["SAFE ACTIVE", "SAFE ACTIVE · interação de baixo impacto"], ["STAGING FULL", "STAGING FULL · laboratório/homologação"]], value: "PASSIVE", help: "PASSIVE ainda pode enviar HTTP/TCP conforme o mecanismo. Testes ativos exigem escopo e aprovação específica; STAGING FULL não habilita operações destrutivas." });
    const scoped = node("div"), local = node("div"), sample = node("div");
    field(scoped, "sec2-job-scope", "Escopo autorizado", { options: choices(scopes()) });
    const target = field(scoped, "sec2-target", "Alvo · URL exata", { value: "http://127.0.0.1:8899/" });
    field(local, "sec2-job-project", "Projeto cadastrado", { options: choices(arr(state.base, "projects")) });
    field(sample, "sec2-job-sample", "Amostra inerte cadastrada", { options: choices(arr(state.base, "samples"), "id", "original_name"), help: "Envie amostras no painel anterior. Nenhuma amostra será executada." });
    form.append(scoped, local, sample);
    const args = field(form, "sec2-job-args", "Parâmetros do mecanismo · JSON", { type: "textarea", rows: 6, help: "Somente os campos aceitos pelo adaptador. Comandos, planos livres e templates externos não são aceitos. Não cole credenciais reais." });
    const synthetic = check(form, "sec2-synthetic", "Confirmo ambiente de laboratório/homologação e uso exclusivo de contas/registros fictícios NEXUS_LAB_* para SQLi/AUTH.");
    function update() { const key = engine.value, row = available(key); availability.textContent = (row.ok ? "Adaptador integrado. " : "Indisponível ou não aprovado. ") + row.reason; availability.classList.toggle("unavailable", !row.ok); scoped.hidden = !network.has(key); local.hidden = key !== "code_audit"; sample.hidden = !["static_file", "investigate", "rea", "ghidra"].includes(key); synthetic.parentElement.hidden = !key.startsWith("appsec_"); args.value = JSON.stringify(key === "tcp_connect" || key === "nmap_service" ? { ports: [8899], ...(key === "nmap_service" ? { service_detection: false } : {}) } : key === "appsec_sqli" ? { parameter: "name", baseline: "NEXUS_LAB_A", marker: "NEXUS_LAB_SQLI_MARKER_A" } : key === "windows" ? { section: "overview" } : key === "cve" ? { cve_id: "CVE-2021-44228" } : key === "osint" ? { domain: "meu-dominio.example", keywords: ["documentação pública"], max_results: 5 } : {}, null, 2); if (key === "appsec_sqli") target.value = "http://127.0.0.1:8899/sqli"; else target.value = "http://127.0.0.1:8899/"; }
    engine.addEventListener("change", update); update();
    const submit = node("button", "primary-button", "Preparar auditoria"); submit.type = "submit"; form.append(submit);
    form.addEventListener("submit", event => { event.preventDefault(); action(async () => { const key = engine.value, parameters = parseJSON(args.value), payload = { engine: key, args: parameters }; if (network.has(key)) { payload.scope_id = $("sec2-job-scope").value; if (!payload.scope_id) throw new Error("Selecione um escopo cadastrado."); if (key !== "osint") parameters.target = $("sec2-target").value; } if (["nuclei", "zap", "nmap_service"].includes(key)) parameters.level = $("sec2-profile").value; if (key.startsWith("appsec_")) { if (!synthetic.checked) throw new Error("Confirme dados fictícios antes do teste ativo."); if ($("sec2-profile").value === "PASSIVE") throw new Error("SQLi/AUTH são testes ativos: selecione SAFE ACTIVE ou STAGING FULL."); parameters.lab_confirmation = true; if (key === "appsec_auth") parameters.synthetic_accounts_confirmed = true; } if (key === "code_audit") payload.project_id = $("sec2-job-project").value; if (["static_file", "investigate", "rea", "ghidra"].includes(key)) payload.sample_id = $("sec2-job-sample").value; await showApproval(await api("/preview", payload)); }); }); root.append(form);
    if (["malware", "reverse"].includes(module[0])) root.append(node("p", "sec2-note", "Análise dinâmica de amostras permanece desativada: não há VM com snapshots e isolamento verificados. Diretório temporário não é sandbox do Windows."));
  }
  async function showApproval(value) {
    if (!value.requires_approval || !value.approval_id) { message("Operação concluída: " + text(value)); return; }
    state.pending = value; const box = $("sec2-approval"); box.replaceChildren(); box.hidden = false;
    box.append(node("h3", "", "Aprovação humana necessária"), node("p", "", "Confira alvo, escopo, impacto e limites. A aprovação vale somente para esta proposta e expira em cinco minutos."), node("pre", "", text(value.preview)));
    const actions = node("div", "sec2-actions");
    for (const [label, approved] of [["Aprovar esta operação", true], ["Negar", false]]) actions.append(button(label, async () => { if (state.busy) return; state.busy = true; actions.querySelectorAll("button").forEach(el => el.disabled = true); try { const result = await api(`/approvals/${encodeURIComponent(value.approval_id)}/decision`, { approved }); state.pending = null; box.hidden = true; if (result.queued) { state.job = result.job.id; selectTab("jobs"); schedule(); } else { await refresh(); if (result.plan) { selectTab("remediation"); showPlan(result.plan); } message(approved ? "Operação aprovada. Confira o resultado registrado." : "Operação negada; não foi executada."); } } finally { state.busy = false; actions.querySelectorAll("button").forEach(el => el.disabled = false); } }, approved));
    box.append(actions); box.scrollIntoView({ behavior: "smooth", block: "start" }); message("Prévia pronta. Nenhuma execução foi iniciada.");
  }
  function jobs(root) { title(root, "Tarefas e eventos", "Execução sequencial, cancelamento cooperativo e histórico persistente. Interromper não desfaz requisições ou alterações já concluídas."); const list = node("div"); list.id = "sec2-run-list"; const selected = node("section"); selected.id = "sec2-run-detail"; root.append(button("Atualizar tarefas", loadRuns), list, selected); action(loadRuns); }
  async function loadRuns() { const rows = arr(await api("/runs"), "runs"); if (state.inventory) state.inventory.runs = rows; const list = $("sec2-run-list"); if (list) { list.replaceChildren(); if (!rows.length) empty(list, "Nenhuma execução registrada."); for (const row of rows) { const card = node("article", "sec2-card"); card.append(node("h4", "", labels[row.engine] || row.engine)); badge(card, row.state, ["failed", "interrupted"].includes(row.state) ? "error" : ""); card.append(node("p", "sec2-muted", `${row.target || row.project_id || row.sample_id || "Inspeção local"} · ${row.created_at}`), button("Ver eventos e evidências", async () => { state.job = row.id; await loadJob(); })); if (["queued", "running", "cancelling"].includes(row.state)) card.append(button("Interromper tarefa", async () => { await api(`/runs/${encodeURIComponent(row.id)}/cancel`, {}); await loadRuns(); })); list.append(card); } } if (state.job && $("sec2-run-detail")) await loadJob(); schedule(); }
  async function loadJob() { const row = await api("/runs/" + encodeURIComponent(state.job)); const root = $("sec2-run-detail"); if (!root) return; root.replaceChildren(node("h4", "", "Execução selecionada"), node("p", "sec2-note", `Estado: ${row.state} · ${row.error || "Consulte eventos, cobertura e evidências."}`)); downloadEvidence(root, row.events || []); root.append(detail("Eventos registrados", row.events || [])); technicalEvidence(root, row.result); root.append(detail("Resultado e recursos", row)); if (row.report_id) root.append(button("Abrir relatório desta execução", async () => { selectTab("reports"); await openReport(row.report_id); })); }
  function downloadEvidence(root, events) {
    const event = [...events].reverse().find(row => row.stage === "download" && Number.isFinite(row.downloaded_bytes)); if (!event) return;
    const section = node("section", "sec2-download"), total = event.total_bytes, progress = node("progress"); progress.setAttribute("aria-label", "Bytes transferidos da instalação"); progress.style.width = "100%";
    if (Number.isFinite(total) && total > 0) { progress.max = total; progress.value = Math.min(event.downloaded_bytes, total); }
    const count = value => Number(value).toLocaleString("pt-BR");
    section.append(node("h4", "", "Download · contagem real de bytes"), progress, node("p", "sec2-muted", `${count(event.downloaded_bytes)} bytes transferidos${Number.isFinite(total) && total > 0 ? " de " + count(total) : " · tamanho total não informado"}. Instalação e configuração são etapas separadas.`)); root.append(section);
  }
  function technicalEvidence(root, value) {
    if (!value || typeof value !== "object") return;
    const result = value.data || value;
    const ports = result.evidence?.ports;
    if (Array.isArray(ports) && ports.length) {
      root.append(node("h4", "", "Portas e serviços observados"), node("p", "sec2-muted", "Porta aberta não confirma vulnerabilidade. Serviço e versão só são exibidos quando constam da evidência."));
      const wrap = node("div", "sec2-table-wrap"), table = node("table", "sec2-table"), head = node("tr");
      for (const label of ["Host / porta / protocolo", "Estado", "Serviço / versão", "Risco / recomendação / evidência"]) head.append(node("th", "", label)); table.append(head);
      for (const row of ports.slice(0, 64)) { const tr = node("tr"); tr.append(node("td", "", `${row.host || result.target || "alvo autorizado"} · ${row.port} · ${row.protocol || "TCP"}`), node("td", "", row.state || "não determinado"), node("td", "", `${row.service || row.service_name || "não comprovado"} · ${row.version || "versão não comprovada"}`)); const evidence = node("td"); evidence.append(node("p", "sec2-muted", row.risk || row.recommendation || "Revisar necessidade de exposição conforme o contexto."), detail("Evidência", row.evidence || row)); tr.append(evidence); table.append(tr); } wrap.append(table); root.append(wrap);
    }
    if (result.source?.startsWith("Ghidra") && Array.isArray(result.functions)) {
      root.append(node("h4", "", "Engenharia reversa · Ghidra headless"), node("p", "sec2-note", `Origem: ${result.source}. Arquitetura: ${result.language_id || "não determinada"}. A amostra não foi executada.`));
      for (const fn of result.functions.slice(0, 200)) { const card = node("article", "sec2-card"); card.append(node("h4", "", `${fn.name || "função"} · ${fn.address || "endereço não informado"}`), node("p", "sec2-muted", fn.signature || "Assinatura não fornecida."), node("p", "sec2-muted", `Origem: ${fn.source || "Ghidra"}`)); if (fn.pseudocode) card.append(detail(`Pseudocódigo · ${fn.pseudocode_source || "decompilador Ghidra"}`, fn.pseudocode)); else card.append(node("p", "sec2-muted", fn.decompile_error || "Pseudocódigo não produzido para esta função.")); root.append(card); }
      root.append(detail("Referências entre funções", result.references || []), detail("Strings · origem Ghidra", result.strings || []), detail("Imports, exports e pontos de entrada", { imports: result.imports, exports: result.exports, entry_points: result.entry_points }), detail("Cobertura e decompilador", { coverage: result.coverage, decompiler: result.decompiler }));
    }
  }
  function schedule() { clearTimeout(state.timer); if ($("security2-dialog").open && arr(state.inventory, "runs").some(row => ["queued", "running", "cancelling"].includes(row.state))) state.timer = setTimeout(() => action(loadRuns), 2000); }
  function reports(root) { title(root, "Report Center", "Evidências redigidas, cobertura declarada e achados correlacionados. A mesma hipótese pode ter mais de uma origem sem constituir confirmações independentes."); const selected = new Set(); const list = node("div"); list.id = "sec2-report-list"; root.append(button("Atualizar relatórios", refresh), button("Correlacionar relatórios selecionados", async () => { const row = await api("/reports/correlate", { report_ids: [...selected] }); await refresh(); selectTab("reports"); await openReport(row.id); }));
    const retention = node("form", "sec2-form"); retention.id = "sec2-retention-form"; retention.append(node("h4", "", "Retenção supervisionada"));
    const cutoff = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    const before = field(retention, "sec2-retention-before", "Tarefas encerradas anteriores a esta data · UTC", { type: "date", value: cutoff, required: true, help: "A prévia lista tarefas e relatórios elegíveis. Preserva tarefas ativas, evidências de planos, painel anterior, arquivos, amostras, branches e backups. Nenhuma exclusão acontece sem aprovação." });
    const clean = node("button", "secondary-button", "Revisar limpeza por data"); clean.type = "submit"; retention.append(clean); retention.addEventListener("submit", event => { event.preventDefault(); action(async () => showApproval(await api("/retention/preview", { before: before.value }))); }); root.append(retention, list);
    for (const row of arr(state.base, "reports")) { const card = node("article", "sec2-card"); const checkbox = check(card, "sec2-report-" + row.id, `${row.operation} · ${row.created_at}`); checkbox.addEventListener("change", () => checkbox.checked ? selected.add(row.id) : selected.delete(row.id)); card.append(node("p", "sec2-muted", `${row.findings_count || 0} achados registrados · ${row.ok ? "execução concluída" : "falha/limitação: veja evidências"}`), button("Abrir relatório", () => openReport(row.id))); list.append(card); } if (!arr(state.base, "reports").length) empty(list, "Nenhum relatório registrado. Isso não é uma avaliação de segurança."); const detailRoot = node("section"); detailRoot.id = "sec2-report-detail"; root.append(detailRoot); }
  async function openReport(id) {
    const row = await api("/reports/" + encodeURIComponent(id)), result = row.result || row, root = $("sec2-report-detail"); if (!root) return;
    state.report = row; root.replaceChildren(node("h3", "", "Relatório selecionado"), node("p", "sec2-note", `Alvo: ${result.target || "local"} · ferramentas: ${(result.tools_used || [row.operation]).join(", ")} · ${result.ok ? "execução concluída" : "verifique falha/limitação"}`));
    const findings = arr(result, "findings"), selected = new Set();
    if (!findings.length) empty(root, "Nenhum achado nesta cobertura. Consulte se o teste foi executado e suas limitações; isso não garante segurança.");
    else { const wrap = node("div", "sec2-table-wrap"), table = node("table", "sec2-table"), head = node("tr"); for (const name of ["Selecionar", "Gravidade / confirmação", "Achado / local", "Evidência e recomendação"]) head.append(node("th", "", name)); table.append(head); findings.forEach((finding, index) => { const tr = node("tr"), pick = node("td"), key = finding.fingerprint || finding.id || String(index); const input = node("input"); input.type = "checkbox"; input.setAttribute("aria-label", "Selecionar " + (finding.title || key)); input.addEventListener("change", () => input.checked ? selected.add(key) : selected.delete(key)); pick.append(input); const severity = node("td"); badge(severity, finding.severity || "não informada", String(finding.severity || "")); severity.append(node("p", "sec2-muted", finding.validation || finding.status || (finding.confirmed ? "confirmado" : "não confirmado"))); const location = node("td"); location.append(node("strong", "", finding.title || finding.id || "Achado"), node("p", "sec2-muted", [finding.file, finding.line, finding.endpoint, finding.cwe, finding.cve].filter(Boolean).join(" · "))); const evidence = node("td"); evidence.append(detail("Evidência redigida", finding.evidence || finding), node("p", "sec2-muted", finding.recommendation || "Revisar o contexto técnico.")); tr.append(pick, severity, location, evidence); table.append(tr); }); wrap.append(table); root.append(wrap); }
    const actions = node("div", "sec2-actions"); for (const format of ["json", "md", "html", "pdf"].filter(key => key !== "pdf" || state.inventory?.export_formats?.pdf === true)) { const link = node("a", "secondary-button", "Exportar " + format.toUpperCase()); link.href = `/api/security/v2/reports/${encodeURIComponent(id)}?format=${format}`; link.download = `nexus-security-${id}.${format}`; actions.append(link); } root.append(actions);
    const project = field(root, "sec2-remediation-project", "Projeto cadastrado para correção", { options: choices(arr(state.base, "projects")), value: result.project_id || "" });
    root.append(button("Deseja que o NEXUS prepare as correções selecionadas?", async () => { if (!selected.size) throw new Error("Selecione pelo menos um achado."); if (!project.value) throw new Error("Selecione o projeto autorizado para preparar correções."); selectTab("remediation"); $("sec2-rem-report").value = id; $("sec2-rem-project").value = project.value; $("sec2-rem-findings").value = [...selected].join("\n"); message("Achados selecionados. Informe propostas e testes do projeto, depois revise o plano antes de aprovar a escrita."); }, true), button("Revisar exclusão deste relatório", async () => showApproval(await api(`/reports/${encodeURIComponent(id)}/delete-preview`, {}))), detail("Cobertura e limitações", { coverage: result.coverage, limitations: result.limitations }), detail("Relatório completo redigido", row));
  }
  function remediation(root) {
    title(root, "Correção supervisionada", "Detecção → seleção de achados → proposta e diff → aprovação de escrita → testes → revalidação. Publicação exige uma autorização separada.");
    const form = node("form", "sec2-form"); form.id = "sec2-remediation-form";
    field(form, "sec2-rem-report", "ID do relatório", { required: true, value: state.report?.id || "" });
    field(form, "sec2-rem-project", "Projeto autorizado", { options: choices(arr(state.base, "projects")) });
    field(form, "sec2-rem-findings", "IDs de achados selecionados · um por linha", { type: "textarea", rows: 3, required: true });
    field(form, "sec2-rem-path", "Arquivo relativo ao projeto", { value: "settings.json", required: true });
    field(form, "sec2-rem-content", "Conteúdo completo proposto", { type: "textarea", rows: 5, value: "{\"fixed\": true}\n", help: "A chave fixed pertence somente ao laboratório didático; aplicações reais exigem correções específicas. O diff será mostrado antes de qualquer aprovação." });
    const advanced = node("details"); advanced.append(node("summary", "", "Vários arquivos e comandos de regressão · avançado"));
    field(advanced, "sec2-rem-proposal", "Parâmetros adicionais · JSON", { type: "textarea", rows: 6, value: "{}", help: "Opcional: edits:[{path,content}] substitui o arquivo acima. tests aceita listas argv python -m pytest/unittest; executar código exige tests_authorized:true e aprovação explícita." }); form.append(advanced);
    const consult = button("Consultar Coder local antes de preparar", async () => { message("Consultando o modelo local de programação. Isso pode consumir RAM e demorar."); const result = await api("/remediation/consult", { task: "Analise a proposta de correção e sugira implementação e testes. Retorne somente uma proposta técnica; não afirme que foi aplicada.", context: text({ report: state.report?.result?.findings || [], path: $("sec2-rem-path").value, content: $("sec2-rem-content").value }).slice(0, 3500) }); const view = $("sec2-coder-result"); view.replaceChildren(detail("Proposta local · nenhuma escrita executada", result)); message(result.ok ? "Proposta do consultor pronta para revisão humana." : result.error || "Consulta não concluída.", !result.ok); });
    const consultant = node("div"); consultant.id = "sec2-coder-result"; form.append(node("p", "sec2-muted", "O consultor recebe somente os primeiros 3.500 caracteres do contexto acima, incluindo achados e proposta. Contexto extenso será truncado; revise a resposta antes de transformar sugestões em alterações."), consult, consultant);
    const submit = node("button", "primary-button", "Preparar plano e diffs"); submit.type = "submit"; form.append(submit); form.addEventListener("submit", event => { event.preventDefault(); action(async () => { const proposal = parseJSON($("sec2-rem-proposal").value); const result = await api("/remediation/preview", { report_id: $("sec2-rem-report").value, project_id: $("sec2-rem-project").value, finding_ids: $("sec2-rem-findings").value.split(/\r?\n/).map(v => v.trim()).filter(Boolean), edits: [{ path: $("sec2-rem-path").value, content: $("sec2-rem-content").value }], ...proposal }); if (result.requires_approval) await showApproval(result); else showPlan(result.plan || result); }); });
    root.append(form, button("Atualizar planos", loadPlans)); const list = node("div"); list.id = "sec2-plan-list"; const selected = node("section"); selected.id = "sec2-plan-detail"; root.append(list, selected); action(loadPlans);
  }
  async function loadPlans() { const rows = arr(await api("/remediation/plans"), "plans"), root = $("sec2-plan-list"); if (!root) return; root.replaceChildren(); if (!rows.length) empty(root, "Nenhum plano preparado. Nenhum arquivo foi alterado por este painel."); for (const row of rows) { const card = node("article", "sec2-card"); card.append(node("h4", "", row.id), node("p", "sec2-muted", `${row.state || row.status || "preparado"} · ${row.created_at || ""}`), button("Ver plano e diffs", async () => showPlan(await api("/remediation/" + encodeURIComponent(row.id))))); root.append(card); } }
  function showPlan(value) { const row = value.plan || value, root = $("sec2-plan-detail"); if (!root) return; root.replaceChildren(node("h4", "", "Plano de correção"), detail("Diffs e plano completos", row)); const id = row.id; if (!id) return; root.append(button("Revisar aprovação de escrita", async () => showApproval(await api(`/remediation/${encodeURIComponent(id)}/apply-preview`, {})), true));
    field(root, "sec2-revalidate-scope", "Escopo da cópia em homologação", { options: choices(scopes()), value: row.scope?.id || "" });
    field(root, "sec2-revalidate-target", "URL da cópia corrigida em execução", { value: row.source_target || "http://127.0.0.1:8899/sqli", help: "Inicie a aplicação corrigida da branch/cópia na porta autorizada antes. O NEXUS não inicia código do projeto automaticamente." });
    root.append(button("Revisar testes e revalidação", async () => showApproval(await api(`/remediation/${encodeURIComponent(id)}/revalidate-preview`, { scope_id: $("sec2-revalidate-scope").value, target: $("sec2-revalidate-target").value })))); }
  function build() {
    const dialog = node("dialog", "sec2-dialog"); dialog.id = "security2-dialog"; dialog.setAttribute("aria-labelledby", "sec2-title");
    const header = node("header", "sec2-header"), heading = node("div"); heading.append(node("span", "sec2-eyebrow", "NEXUS · SECURITY WORKBENCH")); const h = node("h2", "", "Security Center 2.0"); h.id = "sec2-title"; heading.append(h, node("p", "", "Investigue. Revise evidências. Aprove cada alteração.")); const close = button("Fechar", () => dialog.close()); close.id = "sec2-close"; header.append(heading, close);
    const layout = node("div", "sec2-layout"), nav = node("nav", "sec2-nav"); nav.setAttribute("aria-label", "Módulos de segurança 2.0");
    for (const [id, label] of [["dashboard", "Dashboard"], ["targets", "Alvos e escopos"], ["tools", "Ferramentas"], ["jobs", "Tarefas e eventos"], ...modules.map(row => [row[0], row[1]])]) { const item = button(label, () => selectTab(id)); item.dataset.sec2Tab = id; nav.append(item); }
    nav.append(button("Painel anterior", () => { dialog.close(); $("nav-security").click(); })); const body = node("div", "sec2-body"), bar = node("div", "sec2-topbar"), status = node("span"); status.id = "sec2-status"; status.setAttribute("role", "status"); bar.append(status, button("Atualizar", refresh)); const approval = node("section", "sec2-approval"); approval.id = "sec2-approval"; approval.hidden = true; const content = node("main"); content.id = "sec2-content"; body.append(bar, approval, content); layout.append(nav, body); dialog.append(header, layout); document.body.append(dialog); dialog.addEventListener("close", () => clearTimeout(state.timer));
    const open = button("Security Center 2.0 ↗", openDialog); open.id = "security2-open"; $("security-dialog").querySelector(".security-nav").prepend(open);
    window.NexusSecurity2 = { open: () => action(openDialog) };
  }
  async function openDialog() { if ($("security-dialog").open) $("security-dialog").close(); $("security2-dialog").showModal(); await refresh(); schedule(); }
  build();
})();
