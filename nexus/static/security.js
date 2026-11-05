"use strict";

(() => {
  const $ = id => document.getElementById(id);
  const state = { inventory: null, base: null, busy: false, loading: false, pending: null, dork: null, tab: "overview", resourceBusy: false };
  const descriptions = {
    red_team: "Validação técnica de aplicações e serviços em escopo autorizado.",
    osint: "Pesquisa pública com consultas revisáveis e domínio delimitado.",
    rea: "Engenharia reversa estática por integração REA local, conforme provedores disponíveis.",
    malware_lab: "Inspeção estática de amostras inertes, hashes, formatos e indicadores.",
    blue_team: "Postura defensiva e diagnóstico somente leitura do Windows.",
    code_auditor: "Auditoria estática de código, dependências e padrões que exigem validação.",
    architect: "Arquitetura, requisitos e decisões de implementação.", coder: "Implementação de sistemas com ferramentas e resultados verificáveis.",
    debugger: "Investigação de falhas, hipóteses e testes de regressão.", researcher: "Pesquisa técnica com referências consultadas.",
    devops: "Automação, ambiente local e instalações mediante aprovação.", database: "Modelagem de dados, consultas e integridade.",
    writer: "Documentação técnica e comunicação clara.", reviewer: "Revisão técnica e análise de código.", auto: "Roteamento de especialistas conforme a tarefa."
  };
  const labels = { http_headers: "HTTP", tls_certificate: "TLS", tcp_connect: "TCP", nmap_basic: "Nmap", osint: "OSINT" };
  const pretty = value => typeof value === "string" ? value : JSON.stringify(value, null, 2) ?? "";
  const array = (value, key) => Array.isArray(value) ? value : Array.isArray(value?.[key]) ? value[key] : [];
  const n = (tag, cls, text) => { const el = document.createElement(tag); if (cls) el.className = cls; if (text !== undefined) el.textContent = String(text); return el; };
  const btn = (text, cls, action) => { const el = n("button", cls, text); el.type = "button"; el.addEventListener("click", action); return el; };
  const timestamp = value => { const date = new Date(value); return Number.isNaN(date.valueOf()) ? String(value || "Data não informada") : date.toLocaleString("pt-BR"); };
  const bytes = value => Number(value || 0) >= 1048576 ? `${(Number(value) / 1048576).toLocaleString("pt-BR", { maximumFractionDigits: 2 })} MiB` : `${Number(value || 0).toLocaleString("pt-BR")} bytes`;

  async function api(path, options = {}) {
    const { json, ...rest } = options;
    const response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...rest,
      headers: { ...(json !== undefined ? { "Content-Type": "application/json" } : {}), ...rest.headers },
      ...(json !== undefined ? { body: JSON.stringify(json) } : {}) });
    let data;
    try { data = await response.json(); }
    catch (_) {
      const error = new Error(`Resposta inválida do servidor (HTTP ${response.status}).`);
      error.result = { ok: false, error: error.message, code: "invalid_http_response", source: "application", http_status: response.status }; throw error;
    }
    if (!response.ok) {
      const error = new Error(typeof data.error === "string" ? data.error : typeof data.detail === "string" ? data.detail : `A operação falhou (HTTP ${response.status}).`);
      error.result = { ...data, ok: false, http_status: response.status }; throw error;
    }
    return data;
  }

  function status(message, error = false) {
    $("security-load-status").textContent = message;
    $("security-load-status").classList.toggle("error", error);
  }

  function select(id, options, placeholder) {
    const el = $(id), current = el.value;
    const entries = options.map(item => { const option = n("option", "", item.label); option.value = String(item.value); return option; });
    if (!entries.length || placeholder) { const option = n("option", "", placeholder || "Nenhum item disponível"); option.value = ""; entries.unshift(option); }
    el.replaceChildren(...entries);
    if (entries.some(option => option.value === current)) el.value = current;
  }

  function tab(id) {
    state.tab = id;
    document.querySelectorAll(".security-panel").forEach(el => { el.hidden = el.id !== `security-${id}`; });
    document.querySelectorAll("[data-security-tab]").forEach(el => {
      const active = el.dataset.securityTab === id; el.classList.toggle("selected", active);
      if (active) el.setAttribute("aria-current", "page"); else el.removeAttribute("aria-current");
    });
    $("security-content").scrollTop = 0;
  }

  function available(value) { return value === true || value?.available === true; }
  function externalTools() {
    const source = state.inventory?.capabilities?.external_tools;
    if (Array.isArray(source)) return source;
    if (Array.isArray(source?.tools)) return source.tools;
    return Object.entries(source || {}).filter(([, value]) => typeof value === "object").map(([id, value]) => ({ id, ...value }));
  }
  function external(name) { return externalTools().find(tool => tool.id === name || tool.name === name); }

  function renderCapabilities() {
    const caps = state.inventory?.capabilities || {}, host = $("security-capabilities"); host.replaceChildren();
    const entries = [
      { name: "Análise estática local", available: true, reason: "Hashes, formatos e regras de código internas; evidências sem executar o alvo." },
      { name: "REA MCP local", ...caps.rea, reason: caps.rea?.error || (caps.rea?.available ? "Conexão MCP verificada. Cada provedor de análise tem disponibilidade própria." : "Adaptador local não disponível.") },
      ...Object.entries(caps.static || {}).map(([name, data]) => ({ name, ...data })),
      ...externalTools().map(data => ({ ...data, name: `${data.name || data.id} · inventário`, reason: data.note || data.reason, discovered: true })),
      { name: "Análise dinâmica em laboratório", ...caps.dynamic_analysis },
      { name: "VirusTotal", ...caps.virustotal }
    ];
    for (const entry of entries) {
      const card = n("article", "security-capability"), row = n("div", "security-row");
      const ready = available(entry); row.append(n("strong", "", entry.name), n("span", `security-badge${ready ? "" : " unavailable"}`, ready ? entry.discovered ? "Localizado" : "Disponível" : "Indisponível"));
      const details = [entry.reason, entry.mode, entry.version ? `Versão: ${entry.version}` : "", entry.installed && !ready ? "Instalado; integração ainda indisponível." : ""].filter(Boolean).join(" · ");
      card.append(row, n("p", "", details || "Consulte as evidências do inventário para os detalhes desta capacidade."));
      if (entry.path || entry.sha256 || entry.providers || entry.mcp) { const evidence = n("details"); evidence.append(n("summary", "", "Metadados e origem"), n("pre", "", pretty(entry))); card.append(evidence); }
      host.append(card);
    }
    $("security-dynamic-help").textContent = caps.dynamic_analysis?.reason || "Nenhuma VM dedicada e isolada foi configurada.";
    $("security-vt-help").textContent = caps.virustotal?.reason || "Integração não configurada. Nenhum arquivo ou hash é enviado automaticamente.";
    updateActionAvailability();
  }

  function renderAgents() {
    const existing = state.base?.agents || [...$("agent-select").options].map(option => ({ id: option.value, name: option.textContent }));
    const agents = [...new Map([...existing, ...array(state.inventory?.agents)].filter(item => item.id).map(item => [item.id, item])).values()];
    const host = $("security-agent-list"); host.replaceChildren();
    for (const agent of agents) {
      const card = n("article", "security-agent-card");
      card.append(n("h4", "", agent.name), n("p", "", agent.description || descriptions[agent.id] || "Especialista configurado no seu ambiente NEXUS."));
      card.append(btn("Usar agente no chat", "secondary-button", () => {
        if ($("agent-select").disabled || $("model-select").disabled) { status("Aguarde a tarefa atual terminar antes de trocar o agente no chat.", true); return; }
        if (![...$("agent-select").options].some(option => option.value === agent.id)) { const option = n("option", "", agent.name); option.value = agent.id; $("agent-select").append(option); }
        $("agent-select").value = agent.id; $("agent-select").dispatchEvent(new Event("change", { bubbles: true }));
        const model = $("security-model").value;
        if (model && [...$("model-select").options].some(option => option.value === model)) { $("model-select").value = model; $("model-select").dispatchEvent(new Event("change", { bubbles: true })); }
        $("security-dialog").close(); $("prompt").focus();
      })); host.append(card);
    }
    const models = [...$("model-select").options].filter(option => option.value).map(option => ({ value: option.value, label: option.textContent }));
    const chosenModel = $("security-model").value || $("model-select").value;
    select("security-model", models); if ([...$("security-model").options].some(option => option.value === chosenModel)) $("security-model").value = chosenModel;
    $("security-operations").replaceChildren(...array(state.inventory?.operations).map(name => n("code", "", name)));
  }

  function renderScopes() {
    const scopes = array(state.inventory?.scopes), active = scopes.filter(scope => scope.enabled !== false);
    for (const element of document.querySelectorAll(".security-scope-select")) select(element.id, active.map(scope => ({ value: scope.id, label: `${scope.name} · ${scope.targets.join(", ")}` })), "Selecione um escopo autorizado");
    const host = $("security-scope-list"); host.replaceChildren();
    if (!scopes.length) host.append(n("p", "muted-text", "Nenhum escopo cadastrado. Autorize os seus alvos no formulário acima."));
    for (const scope of scopes) {
      const card = n("article", "security-list-card"), row = n("div", "security-row");
      row.append(n("h4", "", scope.name), n("span", `security-badge${scope.enabled === false ? " unavailable" : ""}`, scope.enabled === false ? "Revogado" : `Ativo · rev. ${scope.revision ?? "—"}`));
      card.append(row, n("p", "", `Alvos: ${scope.targets.join(", ")}${scope.include_subdomains ? " · inclui subdomínios" : ""}`), n("p", "", `Testes: ${scope.allowed_tests.map(value => labels[value] || value).join(", ")}`), n("p", "", `${scope.environment} · ${scope.purpose}`));
      if (scope.enabled !== false) card.append(btn("Revogar escopo", "danger-button", () => perform(async () => {
        await api(`/api/security/scopes/${encodeURIComponent(scope.id)}`, { method: "DELETE" });
        status("Escopo revogado. Operações pendentes também serão revalidadas pelo servidor.");
        state.inventory.scopes = array(await api("/api/security/scopes"), "scopes"); renderScopes(); renderSummary(); invalidateDork();
      }, "Revogando escopo…", { allowPending: true })));
      host.append(card);
    }
  }

  function renderSamples() {
    select("security-sample-select", array(state.inventory?.samples).map(sample => ({ value: sample.id, label: `${sample.original_name} · ${bytes(sample.size)}` })), "Selecione uma amostra inerte");
    updateSample();
  }
  function updateSample() {
    const sample = array(state.inventory?.samples).find(item => item.id === $("security-sample-select").value);
    $("security-sample-info").textContent = sample ? `SHA-256: ${sample.sha256}\n${bytes(sample.size)} · armazenado em ${timestamp(sample.created_at)}` : "Escolha uma amostra armazenada para inspecionar os seus bytes.";
    updateActionAvailability();
  }
  function renderProjects() {
    select("security-project-select", array(state.inventory?.projects).map(project => ({ value: project.id, label: project.name })), "Selecione um projeto cadastrado"); updateProject();
  }
  function updateProject() {
    const project = array(state.inventory?.projects).find(item => item.id === $("security-project-select").value);
    $("security-project-path").textContent = project?.path || "Cadastre um projeto na área Projetos do NEXUS para usar esta análise.";
    $("security-code-run").disabled = !project || state.busy;
  }
  function renderSummary() {
    const metrics = [[array(state.inventory?.agents).length, "agentes de segurança"], [array(state.inventory?.scopes).filter(scope => scope.enabled !== false).length, "escopos ativos"], [array(state.inventory?.samples).length, "amostras inertes"], [array(state.inventory?.reports).length, "relatórios locais"]];
    $("security-summary").replaceChildren(...metrics.map(([value, label]) => { const card = n("div", "security-stat"); card.append(n("strong", "", value), n("span", "", label)); return card; }));
  }

  function downloadLinks(id, parent) {
    for (const [format, label] of [["json", "Baixar JSON"], ["md", "Baixar Markdown"]]) {
      const link = n("a", "secondary-button small", label); link.href = `/api/security/reports/${encodeURIComponent(id)}?format=${format}`; link.download = `nexus-security-${id}.${format}`; parent.append(link);
    }
  }
  function renderReports(reports) {
    const host = $("security-report-list"); host.replaceChildren();
    if (!reports.length) host.append(n("p", "muted-text", "Nenhum relatório gerado. As análises executadas ficam registradas aqui."));
    for (const report of reports) {
      const card = n("article", "security-list-card"), row = n("div", "security-row"), actions = n("div", "security-actions");
      row.append(n("h4", "", report.operation || "Análise local"), n("span", `security-badge${report.ok === false ? " error" : ""}`, report.ok === false ? "Erro registrado" : "Registrado"));
      card.append(row, n("p", "", `${timestamp(report.created_at)} · ${Number(report.findings_count || 0)} achados`));
      actions.append(btn("Ver evidências", "secondary-button small", () => perform(async () => { const detail = await api(`/api/security/reports/${encodeURIComponent(report.id)}?format=json`); renderResult({ ...detail.result, report_id: detail.id }); }, "Carregando relatório…")));
      downloadLinks(report.id, actions); card.append(actions); host.append(card);
    }
  }
  async function refreshReports() {
    const reports = array(await api("/api/security/reports"), "reports");
    if (state.inventory) state.inventory.reports = reports; renderReports(reports); renderSummary();
  }

  function updateActionAvailability() {
    const loaded = Boolean(state.inventory), sample = Boolean($("security-sample-select").value), rea = available(state.inventory?.capabilities?.rea);
    $("security-static-run").disabled = !loaded || !sample || state.busy;
    $("security-rea-run").disabled = !loaded || !sample || !rea || state.busy;
    $("security-investigate-run").disabled = !loaded || !sample || state.busy;
    $("security-file-help").textContent = rea ? "REA inspeciona os formatos estáticos suportados pelo adaptador local. Nenhuma amostra é executada." : "REA indisponível: a análise estática local continua disponível. A investigação informa as etapas indisponíveis.";
    const isNmap = $("security-network-tool").value === "security_nmap", nmap = external("nmap");
    $("security-network-run").disabled = !loaded || state.busy || (isNmap && !available(nmap));
    $("security-network-help").textContent = isNmap ? available(nmap) ? "Nmap foi localizado. A execução ainda depende de validação do binário, escopo e aprovação desta operação." : "Nmap não foi localizado. Nenhuma ferramenta será instalada automaticamente; escolha HTTP, TLS ou TCP." : "Redirecionamentos e endereços fora do escopo não são seguidos automaticamente.";
    const portsNeeded = ["security_tcp", "security_nmap"].includes($("security-network-tool").value);
    $("security-network-ports").disabled = !portsNeeded || state.busy;
    $("security-dork-run").disabled = !state.dork || state.busy;
    updateProject();
  }

  function renderFindings(findings) {
    const host = $("security-findings"); host.replaceChildren();
    if (!findings.length) { host.append(n("p", "security-findings-empty", "Nenhum achado estruturado nesta resposta. Isso não comprova ausência de vulnerabilidades; consulte os dados e limitações da ferramenta.")); return; }
    host.append(n("h3", "security-findings-title", `${findings.length} achado${findings.length === 1 ? "" : "s"} · exige validação`));
    const wrap = n("div", "security-table-wrap"), table = n("table", "security-findings-table"), head = n("thead"), hrow = n("tr"), body = n("tbody");
    for (const label of ["Gravidade", "Achado / evidência", "Arquivo / linha", "Impacto e recomendação", "Validação"]) hrow.append(n("th", "", label)); head.append(hrow); table.append(head);
    for (const finding of findings) {
      const row = n("tr"), severity = String(finding.severity || "info"), level = severity.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z]/g, "");
      const s = n("td"); s.append(n("span", `security-severity ${level}`, severity));
      const title = n("td"); title.append(n("strong", "", finding.title || finding.rule || finding.id || "Indicador")); if (finding.evidence) title.append(n("p", "", pretty(finding.evidence)));
      const location = finding.file || finding.path || finding.location || "Não se aplica"; const file = n("td", "", `${typeof location === "object" ? pretty(location) : location}${finding.line ? `:${finding.line}` : ""}`);
      const advice = n("td"); advice.append(n("p", "", finding.impact || "Impacto não determinado."), n("p", "", finding.recommendation || "Revisar o contexto e validar manualmente."));
      row.append(s, title, file, advice, n("td", "", finding.validation || "Não confirmada")); body.append(row);
    }
    table.append(body); wrap.append(table); host.append(wrap);
  }

  function evidenceTable(title, rows, preferred = []) {
    if (!rows.length) return null;
    const columns = [...new Set([...preferred, ...rows.slice(0, 30).flatMap(row => Object.keys(row || {}))])].filter(key => rows.some(row => row?.[key] !== undefined)).slice(0, 7);
    const block = n("div"), wrap = n("div", "security-table-wrap"), table = n("table", "security-findings-table"), head = n("thead"), top = n("tr"), body = n("tbody");
    for (const column of columns) top.append(n("th", "", column)); head.append(top); table.append(head);
    for (const row of rows.slice(0, 30)) {
      const tr = n("tr");
      for (const column of columns) {
        const value = row?.[column], td = n("td", "", value === undefined || value === null ? "—" : typeof value === "object" ? pretty(value).slice(0, 600) : String(value).slice(0, 600));
        if (typeof value === "string" && ["url", "link"].includes(column)) {
          try { const url = new URL(value); if (["http:", "https:"].includes(url.protocol)) { const link = n("a", "", value); link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer"; td.replaceChildren(link); } } catch (_) { /* Evidence remains plain text. */ }
        }
        tr.append(td);
      }
      body.append(tr);
    }
    table.append(body); wrap.append(table); block.append(n("h4", "security-evidence-title", title), wrap);
    if (rows.length > 30) block.append(n("p", "security-note", `Prévia de 30 das ${rows.length} linhas. Os dados completos permanecem nas evidências estruturadas.`));
    return block;
  }

  function renderEvidenceData(result) {
    const payload = result.data || {}, host = $("security-result-data"); host.replaceChildren();
    if (payload.query) host.append(n("div", "security-query", payload.query));
    const fields = ["target", "name", "sha256", "size_bytes", "format", "architecture", "entropy", "section"];
    const labels = { target: "Alvo", name: "Arquivo", sha256: "SHA-256", size_bytes: "Tamanho", format: "Formato", architecture: "Arquitetura", entropy: "Entropia", section: "Área" };
    for (const key of fields) if (payload[key] !== undefined) { const row = n("p", "security-result-datum"); row.append(n("strong", "", labels[key]), document.createTextNode(key === "size_bytes" ? bytes(payload[key]) : typeof payload[key] === "object" ? pretty(payload[key]) : String(payload[key]))); host.append(row); }
    const evidence = payload.evidence || {};
    if (evidence.headers && typeof evidence.headers === "object") {
      const table = evidenceTable(`Cabeçalhos observados${evidence.status ? ` · HTTP ${evidence.status}` : ""}`, Object.entries(evidence.headers).map(([header, value]) => ({ header, value })));
      if (table) host.append(table);
    }
    const candidates = [["Conexões observadas", evidence.ports, ["port", "state", "address"]], ["Resultados públicos", evidence.results || payload.results, ["title", "url", "snippet"]], ["Dados do diagnóstico", payload.data, []]];
    for (const [title, value, keys] of candidates) {
      const rows = Array.isArray(value) ? value.filter(row => row && typeof row === "object") : value && typeof value === "object" ? Object.entries(value).map(([field, content]) => ({ campo: field, valor: content })) : [];
      const table = evidenceTable(title, rows, keys); if (table) host.append(table);
    }
    if (evidence.tls_version || evidence.not_after) {
      const table = evidenceTable("Certificado TLS observado", [evidence], ["tls_version", "verified", "not_before", "not_after", "sha256"]); if (table) host.append(table);
    }
    const limitations = payload.limitations || result.limitations;
    if (Array.isArray(limitations) && limitations.length) host.append(n("p", "security-note", `Limitações: ${limitations.join(" · ")}`));
  }

  function renderResult(result) {
    const host = $("security-result"); host.hidden = false;
    $("security-result-title").textContent = result.tool || "Resultado da operação";
    $("security-result-badge").textContent = result.requires_approval ? "Aguardando sua decisão" : result.ok === false ? "Não concluído" : result.code === "approval_denied" ? "Recusado por você" : "Resposta recebida";
    $("security-result-badge").className = `security-badge${result.requires_approval ? " pending" : result.ok === false ? " error" : ""}`;
    const source = result.source ? `Origem: ${result.source}` : ""; const code = result.code ? `Código: ${result.code}` : "";
    $("security-result-message").textContent = [result.error || result.data?.error || result.data?.summary || result.data?.notice || (result.requires_approval ? "Nada foi executado. Confira os detalhes e escolha aprovar ou recusar." : result.code === "approval_denied" ? "A operação foi recusada. Nenhuma sondagem foi executada." : "Consulte os achados, as evidências e as limitações retornadas pela ferramenta."), [source, code].filter(Boolean).join(" · ")].filter(Boolean).join("\n");
    $("security-evidence").querySelector("pre").textContent = pretty(result);
    renderEvidenceData(result);
    renderFindings(array(result.findings?.length ? result.findings : result.data?.findings || result.data?.indicators));
    $("security-result-links").replaceChildren(); if (result.report_id) downloadLinks(result.report_id, $("security-result-links"));
    $("security-approval").hidden = !result.requires_approval;
    if (result.requires_approval) renderApproval(result);
    status(result.requires_approval ? "Operação preparada. Aguardando sua decisão no quadro de aprovação." : result.ok === false ? result.error || "A ferramenta registrou uma limitação ou erro; consulte a origem e o código abaixo." : result.code === "approval_denied" ? "Operação recusada. Nenhuma sondagem foi executada." : "Resposta da ferramenta recebida. Consulte as evidências e as limitações abaixo.", result.ok === false);
    host.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function renderApproval(result) {
    state.pending = result.approval_id;
    const host = $("security-approval"), preview = result.preview || {}, values = [["Operação", preview.action], ["Alvo", preview.target], ["Consulta", preview.query || preview.args?.query_preview], ["Escopo", preview.scope_name], ["Revisão", preview.scope_revision], ["Portas", preview.ports?.length ? preview.ports.join(", ") : "Conforme protocolo"], ["Risco", preview.risk], ["Impacto", preview.impact], ["Argumentos", pretty(preview.args || {})]];
    const dl = n("dl"); for (const [label, value] of values) if (value !== undefined) dl.append(n("dt", "", label), n("dd", "", value));
    const actions = n("div", "security-actions");
    for (const [label, approved, cls] of [["Aprovar somente esta operação", true, "primary-button"], ["Recusar", false, "secondary-button"]]) actions.append(btn(label, cls, () => perform(async () => {
      const identity = state.pending; if (!identity) return;
      const response = await api(`/api/security/jobs/${encodeURIComponent(identity)}/decision`, { method: "POST", json: { approved } });
      state.pending = null; renderResult(response); await refreshReports();
    }, approved ? "Executando somente a operação aprovada…" : "Recusando operação…", { decision: true })));
    host.replaceChildren(n("h4", "", "Aprovação operacional · uma única execução"), dl, actions);
  }

  async function perform(callback, message = "Consultando…", options = {}) {
    if (state.busy) return;
    if (!state.inventory) { status("Aguarde a leitura inicial das capacidades locais antes de executar uma operação.", true); return; }
    if (state.pending && !options.decision && !options.allowPending) { status("Resolva a operação pendente no quadro de aprovação antes de iniciar outra análise.", true); $("security-result").scrollIntoView({ block: "start" }); return; }
    state.busy = true; status(message); updateActionAvailability();
    document.querySelectorAll("#security-approval button").forEach(el => { el.disabled = true; });
    try { await callback(); }
    catch (error) {
      status(error.message, true);
      if (options.decision && [404, 409].includes(error.result?.http_status)) state.pending = null;
      if (state.pending) {
        $("security-approval").append(n("p", "security-note", `${error.message}${error.result?.code ? ` · ${error.result.code}` : ""}`));
      } else renderResult(error.result || { ok: false, error: error.message, code: "client_error", source: "interface" });
    }
    finally { state.busy = false; document.querySelectorAll("#security-approval button").forEach(el => { el.disabled = false; }); updateActionAvailability(); }
  }
  async function job(tool, args) {
    const result = await api("/api/security/jobs", { method: "POST", json: { tool, args, mode: "AGENT" } });
    renderResult(result); if (!result.requires_approval) await refreshReports();
  }

  async function refreshInventory() {
    if (state.loading) return; state.loading = true; $("security-refresh").disabled = true;
    status("Consultando ferramentas e REA locais… A primeira leitura pode levar alguns segundos; nenhum modelo é carregado.");
    try {
      state.inventory = await api("/api/security/status");
      renderSummary(); renderCapabilities(); renderScopes(); renderSamples(); renderProjects(); renderReports(array(state.inventory.reports)); renderAgents(); invalidateDork();
      status(`Inventário local atualizado às ${new Date().toLocaleTimeString("pt-BR")}. Capacidades ausentes são indicadas abaixo.`);
    } catch (error) { status(error.message, true); }
    finally { state.loading = false; $("security-refresh").disabled = false; }
  }

  async function refreshResources() {
    if (!$("security-dialog").open || state.resourceBusy) return; state.resourceBusy = true;
    try {
      const result = await api("/api/status"); state.base = result;
      const system = result.system || {}, gpu = array(system.gpu, "gpus")[0], used = Number(system.ram_used_gb || 0).toLocaleString("pt-BR", { maximumFractionDigits: 1 }), total = Number(system.ram_total_gb || 0).toLocaleString("pt-BR", { maximumFractionDigits: 1 });
      $("security-resources").textContent = [`RAM ${used} / ${total} GiB`, gpu ? `GPU ${gpu.name}\nVRAM ${bytes(Number(gpu.memory_used_mb || 0) * 1048576)} / ${bytes(Number(gpu.memory_total_mb || 0) * 1048576)}` : "GPU não detectada", `Modelo: ${$("model-select").value || result.settings?.model || "não selecionado"}`, "Atualização leve a cada 18 s."].join("\n");
      const knownAgents = [...$("security-agent-list").querySelectorAll("h4")].map(el => el.textContent).join("|");
      const incomingAgents = [...new Map([...array(result.agents), ...array(state.inventory?.agents)].filter(item => item.id).map(item => [item.id, item])).values()].map(item => item.name).join("|");
      if (knownAgents !== incomingAgents) renderAgents();
    } catch (_) { $("security-resources").textContent = "Recursos locais indisponíveis nesta leitura."; }
    finally { state.resourceBusy = false; }
  }
  function invalidateDork() { state.dork = null; $("security-dork-run").disabled = true; $("security-dork-preview").hidden = true; }
  function dorkArguments() {
    const operators = Object.fromEntries(["intitle", "inurl", "intext"].map(key => [key, $(`security-dork-${key}`).value.trim()]).filter(([, value]) => value));
    return { scope_id: $("security-dork-scope").value, domain: $("security-dork-domain").value.trim(), operators, document_type: $("security-dork-type").value, keywords: $("security-dork-keywords").value.trim(), exclusions: $("security-dork-exclusions").value.split(/\r?\n/).map(value => value.trim()).filter(Boolean), max_results: Number($("security-dork-limit").value) };
  }

  $("nav-security").addEventListener("click", () => {
    const dialog = $("security-dialog"); if (!dialog.open) dialog.showModal();
    $("sidebar").classList.remove("is-open"); $("sidebar-shade").hidden = true; $("sidebar-toggle").setAttribute("aria-expanded", "false");
    if (!state.inventory) refreshInventory(); refreshResources();
  });
  $("security-close").addEventListener("click", () => $("security-dialog").close());
  $("security-dialog").addEventListener("click", event => { if (event.target === $("security-dialog")) { const r = $("security-dialog").getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) $("security-dialog").close(); } });
  document.querySelectorAll("[data-security-tab]").forEach(el => el.addEventListener("click", () => tab(el.dataset.securityTab)));
  $("security-refresh").addEventListener("click", () => refreshInventory());
  $("security-reports-refresh").addEventListener("click", () => perform(async () => { await refreshReports(); status("Relatórios locais atualizados."); }, "Consultando relatórios…"));
  $("security-scope-form").addEventListener("submit", event => { event.preventDefault(); perform(async () => {
    const allowed = [...document.querySelectorAll('input[name="security-tests"]:checked')].map(el => el.value);
    if (!allowed.length) throw new Error("Selecione pelo menos um tipo de teste para o escopo.");
    await api("/api/security/scopes", { method: "POST", json: { name: $("security-scope-name").value.trim(), targets: $("security-scope-targets").value.split(/\r?\n/).map(value => value.trim()).filter(Boolean), allowed_tests: allowed, environment: $("security-scope-environment").value.trim(), purpose: $("security-scope-purpose").value.trim(), authorization_confirmed: $("security-scope-authorized").checked, include_subdomains: $("security-scope-subdomains").checked } });
    $("security-scope-authorized").checked = false; state.inventory.scopes = array(await api("/api/security/scopes"), "scopes"); renderScopes(); renderSummary(); invalidateDork(); status("Escopo salvo. A autorização operacional de cada teste de rede continua sendo solicitada.");
  }, "Validando e salvando seu escopo…"); });
  $("security-network-tool").addEventListener("change", updateActionAvailability);
  $("security-network-form").addEventListener("submit", event => { event.preventDefault(); perform(async () => {
    const tool = $("security-network-tool").value, args = { scope_id: $("security-network-scope").value, target: $("security-network-target").value.trim() };
    if (["security_tcp", "security_nmap"].includes(tool)) {
      const chunks = $("security-network-ports").value.split(",").map(value => value.trim());
      if (chunks.some(value => !/^\d+$/.test(value))) throw new Error("Use portas numéricas explícitas separadas por vírgula.");
      args.ports = [...new Set(chunks.map(Number))];
      const limit = tool === "security_tcp" ? 8 : 16;
      if (!args.ports.length || args.ports.length > limit || args.ports.some(port => port < 1 || port > 65535)) throw new Error(`Informe entre 1 e ${limit} portas de 1 a 65535.`);
    }
    await job(tool, args);
  }, "Preparando prévia da operação e validando escopo…"); });
  $("security-cve-form").addEventListener("submit", event => { event.preventDefault(); perform(() => job("security_cve", { cve_id: $("security-cve-id").value.trim().toUpperCase() }), "Consultando CVE em fonte pública…"); });
  $("security-dork-form").addEventListener("input", invalidateDork); $("security-dork-form").addEventListener("change", invalidateDork);
  $("security-dork-form").addEventListener("submit", event => { event.preventDefault(); perform(async () => {
    const args = dorkArguments(), result = await api("/api/security/dorks/preview", { method: "POST", json: args });
    renderResult(result);
    if (result.ok && typeof result.data?.query === "string") { state.dork = { ...args, ...(Number.isInteger(result.data.scope_revision) ? { scope_revision: result.data.scope_revision } : {}) }; $("security-dork-preview").textContent = `Consulta revisada · domínio ${args.domain}\n${result.data.query}\nSomente os argumentos exibidos serão usados na pesquisa.`; $("security-dork-preview").hidden = false; status("Prévia válida. Confira a consulta e clique em Revisar pesquisa para preparar a aprovação da consulta pública."); }
    else invalidateDork();
    await refreshReports();
  }, "Validando consulta sem realizar a pesquisa…"); });
  $("security-dork-run").addEventListener("click", () => perform(async () => { if (!state.dork) throw new Error("Pré-visualize a consulta atual antes de pesquisar."); await job("security_osint", state.dork); }, "Pesquisando somente a consulta revisada…"));
  $("security-upload-form").addEventListener("submit", event => { event.preventDefault(); perform(async () => {
    const file = $("security-upload-file").files[0]; if (!file) throw new Error("Selecione uma amostra local.");
    const limit = Number(state.inventory?.limits?.sample_bytes || 10 * 1048576); if (!file.size || file.size > limit) throw new Error(`A amostra deve ter entre 1 byte e ${bytes(limit)}.`);
    const sample = await api(`/api/security/samples?name=${encodeURIComponent(file.name)}`, { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: file });
    state.inventory.samples = array(await api("/api/security/samples"), "samples"); renderSamples(); $("security-sample-select").value = sample.id; updateSample(); renderSummary(); $("security-upload-file").value = ""; status(`Amostra armazenada sem execução. SHA-256: ${sample.sha256}`);
  }, "Armazenando bytes da amostra de forma inerte…"); });
  $("security-sample-select").addEventListener("change", updateSample);
  for (const [id, tool] of [["security-static-run", "security_static_file"], ["security-rea-run", "security_rea"], ["security-investigate-run", "security_investigate"]]) $(id).addEventListener("click", () => perform(() => job(tool, { sample_id: $("security-sample-select").value }), "Inspecionando a amostra sem executá-la…"));
  $("security-project-select").addEventListener("change", updateProject);
  $("security-code-form").addEventListener("submit", event => { event.preventDefault(); perform(() => job("security_code_audit", { project_id: $("security-project-select").value }), "Auditando código estaticamente, sem executar o projeto…"); });
  $("security-windows-form").addEventListener("submit", event => { event.preventDefault(); perform(() => job("security_windows", { section: $("security-windows-section").value }), "Consultando diagnóstico local do Windows…"); });
  setInterval(() => { if (!document.hidden && $("security-dialog").open) refreshResources(); }, 18000);
  updateActionAvailability();
})();
