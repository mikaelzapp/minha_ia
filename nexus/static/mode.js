"use strict";

(() => {
  const $ = id => document.getElementById(id);
  const app = window.NEXUSApp;
  const state = { modes: [], agents: [], current: "chat", compatibility: null, check: 0, initializing: true };
  const element = (tag, content, className) => {
    const el = document.createElement(tag);
    if (content !== undefined) el.textContent = String(content);
    if (className) el.className = className;
    return el;
  };
  const list = (value, key) => Array.isArray(value) ? value : Array.isArray(value?.[key]) ? value[key] : [];
  const active = () => state.modes.find(mode => mode.id === state.current);
  function action(label, callback) {
    const button = element("button", label, "secondary-button small"); button.type = "button";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try { await callback(); } catch (error) { app.notify(error.message, true); }
      finally { button.disabled = false; }
    });
    return button;
  }
  function security(tab) {
    $("nav-security").click();
    if (tab) document.querySelector(`[data-security-tab="${tab}"]`)?.click();
  }
  async function researchReports() {
    security("reports");
    const host = $("research-report-list"), project = $("project-select").value;
    host.replaceChildren(element("p", "Consultando relatórios de pesquisa locais…", "field-help"));
    try {
      const data = await app.api(`/api/research/reports${project ? `?project_id=${encodeURIComponent(project)}` : ""}`);
      host.replaceChildren();
      if (!list(data, "reports").length) host.append(element("p", "Nenhuma pesquisa registrada neste contexto. Uma resposta do modelo sem consulta não cria fontes de pesquisa.", "field-help"));
      list(data, "reports").forEach(report => {
        const card = element("article", undefined, "security-list-card");
        card.append(element("h4", report.tool || "Pesquisa"), element("p", `${report.created_at || "Data não informada"} · ${report.ok === false ? "Erro registrado" : "Resultado registrado"}\nConversa: ${report.session_id || "não associada"} · Projeto: ${report.project_id || "sem projeto"}`));
        const actions = element("div", undefined, "security-actions");
        actions.append(action("Ver fontes e evidências", async () => {
          const detail = await app.api(`/api/research/reports/${encodeURIComponent(report.id)}?format=json`);
          card.querySelector(".research-report-evidence")?.remove();
          const evidence = element("div", undefined, "research-report-evidence"), result = detail.result || {};
          evidence.append(element("p", `Coleta: ${result.retrieved_at || detail.created_at || "não informada"} · ${result.via_tor ? "via Tor" : "pesquisa convencional"}`, "field-help"));
          list(result.queries).forEach(query => {
            evidence.append(element("h4", query.query || "Consulta registrada"));
            list(query.results).forEach(source => {
              const line = element("p"); line.append(element("strong", source.title || source.url || "Fonte"));
              line.append(element("span", `\n${source.url || ""}\nData da fonte: ${source.published_date || source.source_date || "não informada"}`)); evidence.append(line);
            });
            if (query.error) evidence.append(element("p", typeof query.error === "string" ? query.error : JSON.stringify(query.error), "field-help"));
          });
          const complete = element("details"); complete.append(element("summary", "Resposta estruturada e procedência"), element("pre", JSON.stringify(detail, null, 2), "mode-diagnostic")); evidence.append(complete); card.append(evidence);
        }));
        [["json", "Baixar JSON"], ["md", "Baixar Markdown"]].forEach(([format, label]) => {
          const link = element("a", label, "secondary-button small"); link.href = `/api/research/reports/${encodeURIComponent(report.id)}?format=${format}`; link.download = `nexus-pesquisa-${report.id}.${format}`; actions.append(link);
        }); card.append(actions); host.append(card);
      });
    } catch (error) { host.replaceChildren(element("p", error.message, "field-help")); }
  }
  function renderContext() {
    const mode = active(), body = $("workspace-context-body"); body.replaceChildren();
    if (!mode) return;
    $("workspace-context-title").textContent = mode.name;
    body.append(element("p", mode.description, "mode-description"));
    const tools = list(mode.tools);
    const chips = element("div", undefined, "mode-tool-list");
    tools.forEach(tool => {
      const name = typeof tool === "string" ? tool : tool.name;
      const item = element("code", name);
      if (tool?.available === false) { item.classList.add("unavailable"); item.title = tool.reason || "Ferramenta indisponível"; }
      chips.append(item);
    });
    body.append(chips);
    const actions = element("div", undefined, "mode-actions");
    if (mode.id === "tor") {
      body.append(element("p", "Deep web inclui conteúdo não indexado. Serviços .onion são uma parte da dark web. A navegação usa um contexto isolado e não compartilha cookies do seu navegador pessoal.", "field-help"));
      const enabled = Boolean(app.getStatus()?.settings?.tor_enabled);
      actions.append(action(enabled ? "Desativar Tor" : "Ativar Tor explicitamente", async () => {
        if (app.isBusy()) throw new Error("Aguarde a geração atual para alterar a conexão.");
        await app.api("/api/settings", { method: "POST", json: { tor_enabled: !Boolean(app.getStatus()?.settings?.tor_enabled) } });
        await app.refreshStatus(); renderContext();
      }));
      actions.append(action("Verificar proxy e saída", async () => {
        const data = await app.api("/api/research/tor/check", { method: "POST", json: {} });
        let output = $("tor-context-status");
        if (!output) { output = element("pre", undefined, "mode-diagnostic"); output.id = "tor-context-status"; body.append(output); }
        output.textContent = JSON.stringify(data, null, 2);
      }));
      body.append(element("p", enabled ? "Tor autorizado. A conectividade precisa ser confirmada; o uso de Tor não garante anonimato absoluto." : "Tor desativado. Selecione Ativar Tor explicitamente antes de pesquisar pela rede.", "field-help"));
      actions.append(action("Consultar configuração local", async () => {
        const data = await app.api("/api/research/tor/status"); app.notify(data.reason || `Proxy ${data.proxy || "não configurado"} · ${data.reachable ? "alcançável" : "não alcançável"}`);
      }));
    }
    if (["pentest", "security"].includes(mode.id)) {
      actions.append(action("Escopos autorizados", () => security("scopes")), action(mode.id === "security" ? "Arquivos e análise estática" : "Verificações de rede", () => security(mode.id === "security" ? "files" : "network")));
      body.append(element("p", "O assunto da conversa e a autorização operacional são independentes. Testes ativos exigem escopo e aprovação; amostras permanecem inertes.", "field-help"));
    }
    if (mode.id === "developer") {
      actions.append(action("Escolher projeto", () => document.querySelector('[data-open="projects"]').click()), action("Pastas e permissões", () => document.querySelector('[data-open="settings"]').click()));
      body.append(element("p", "Use o chat para solicitar comandos, Git, testes e edições. Diffs e aprovações aparecem na conversa. Ferramentas executam com as permissões operacionais configuradas.", "field-help"));
      actions.append(action("Histórico e reversão de arquivos", async () => {
        const data = await app.api("/api/developer/changes");
        body.querySelector(".developer-history")?.remove();
        const history = element("section", undefined, "developer-history"); body.append(history);
        history.append(element("h4", "Alterações aprovadas pelo NEXUS"), element("p", "A reversão cobre escritas de arquivos registradas pelo NEXUS. Comandos arbitrários e suas alterações não podem ser desfeitos automaticamente.", "field-help"));
        if (!list(data.changes).length) history.append(element("p", "Nenhuma alteração de arquivo registrada.", "field-help"));
        list(data.changes).slice(0, 30).forEach(change => {
          const row = element("div", undefined, "developer-change"); row.append(element("strong", change.path), element("small", change.created_at || ""));
          const revise = action(change.restored_at ? "Já revertido" : "Revisar reversão", async () => {
            const result = await app.api(`/api/developer/changes/${encodeURIComponent(change.id)}/preview`, { method: "POST", json: {} });
            row.querySelector(".developer-rollback")?.remove();
            const review = element("div", undefined, "developer-rollback"); review.append(element("pre", result.preview?.diff || JSON.stringify(result.preview, null, 2), "mode-diagnostic"));
            review.append(action("Aprovar esta reversão", async () => {
              await app.api(`/api/developer/changes/${encodeURIComponent(result.approval_id)}/decision`, { method: "POST", json: { approved: true } });
              review.replaceChildren(element("p", "Reversão concluída e registrada.", "field-help"));
            }), action("Cancelar", async () => { await app.api(`/api/developer/changes/${encodeURIComponent(result.approval_id)}/decision`, { method: "POST", json: { approved: false } }); review.remove(); }));
            row.append(review);
          });
          revise.disabled = Boolean(change.restored_at) || Boolean(change.status && change.status !== "applied");
          if (revise.disabled && !change.restored_at) revise.title = `Alteração ${change.status}: somente escritas concluídas podem ser revertidas.`;
          row.append(revise); history.append(row);
        });
      }));
    }
    if (mode.id === "search") body.append(element("p", "As consultas e fontes consultadas aparecem como evidências das ferramentas. Conhecimento do modelo, sozinho, não comprova uma pesquisa na internet.", "field-help"));
    if (["search", "tor"].includes(mode.id)) actions.append(action("Sessões e fontes", researchReports));
    if (mode.recommended_model) body.append(element("p", `Modelo recomendado: ${mode.recommended_model}. A escolha manual permanece independente quando compatível.`, "field-help"));
    if (actions.childNodes.length) body.append(actions);
    renderMonitor();
  }
  function renderMonitor() {
    const mode = active();
    $("monitor-workspace-mode").textContent = mode?.name || state.current;
    $("monitor-agent").textContent = $("agent-select").selectedOptions[0]?.textContent || "—";
    $("monitor-tor").textContent = app.getStatus()?.settings?.tor_enabled ? "Autorizado" : "Desativado";
    $("monitor-tools").textContent = `${list(mode?.tools).length} previstas no modo`;
    $("workspace-agent-label").textContent = $("agent-select").selectedOptions[0]?.textContent || "Agente independente do modelo";
  }
  async function compatibility() {
    const sequence = ++state.check, model = $("model-select").value;
    if (!model || !state.modes.length) return;
    $("workspace-compatibility").textContent = "Verificando modelo…";
    try {
      const result = await app.api("/api/workspace-modes/compatibility", { method: "POST", json: { workspace_mode: state.current, operation_mode: $("mode-select").value, model, agent: $("agent-select").value } });
      if (sequence !== state.check) return;
      state.compatibility = result;
      $("workspace-compatibility").textContent = result.compatible ? "Modelo compatível" : result.reason || "Modelo incompatível";
      $("workspace-compatibility").classList.toggle("incompatible", !result.compatible);
      $("workspace-context-body").querySelector(".mode-compatibility-help")?.remove();
      if (!result.compatible) {
        const help = element("div", undefined, "mode-compatibility-help");
        help.append(element("p", result.reason || "A capacidade exigida não foi declarada pelo modelo.", "field-help"));
        list(result.suggestions).forEach(name => help.append(action(`Usar ${name}`, () => window.NEXUSModes.selectModel(name))));
        $("workspace-context-body").append(help); $("workspace-context").open = true;
      }
    } catch (error) {
      if (sequence !== state.check) return;
      state.compatibility = null; $("workspace-compatibility").textContent = `Compatibilidade indisponível: ${error.message}`;
    }
    renderMonitor();
  }
  function setMode(id, defaults = true) {
    const mode = state.modes.find(item => item.id === id);
    if (!mode || app.isBusy()) return;
    state.current = id; $("workspace-mode-select").value = id;
    document.querySelectorAll("[data-workspace-mode]").forEach(item => {
      item.classList.toggle("active", item.dataset.workspaceMode === id);
      if (item.dataset.workspaceMode === id) item.setAttribute("aria-current", "page"); else item.removeAttribute("aria-current");
    });
    if (defaults) {
      if ([...$("agent-select").options].some(option => option.value === mode.agent)) $("agent-select").value = mode.agent;
      if ([...$("mode-select").options].some(option => option.value === mode.operation_mode)) {
        $("mode-select").value = mode.operation_mode; $("mode-select").dispatchEvent(new Event("change"));
      }
    }
    $("workspace-context").open = id !== "chat";
    renderContext(); compatibility(); app.closeSidebar();
    document.dispatchEvent(new CustomEvent("nexus:workspace-mode", { detail: { id } }));
  }
  async function refreshAgents() {
    const data = await app.api("/api/agents"); state.agents = list(data, "agents");
    const selected = $("agent-select").value;
    if (state.agents.length) {
      $("agent-select").replaceChildren(...state.agents.map(agent => { const option = element("option", agent.name); option.value = agent.id; return option; }));
      $("agent-select").value = state.agents.some(agent => agent.id === selected) ? selected : active()?.agent || "auto";
    }
    renderMonitor();
  }
  window.NEXUSModes = Object.freeze({ getMode: () => state.current, getModes: () => state.modes, setMode, refreshAgents,
    selectModel(name) {
      if (app.isBusy()) throw new Error("Aguarde a geração atual para trocar o modelo.");
      const option = [...$("model-select").options].find(item => item.value === name);
      if (!option) throw new Error("Este modelo não está disponível para conversa. Atualize o inventário.");
      $("model-select").value = name; $("model-select").dispatchEvent(new Event("change"));
    },
    selectAgent(id) {
      if (app.isBusy()) throw new Error("Aguarde a geração atual para trocar o agente.");
      const agent = state.agents.find(item => item.id === id);
      if (!agent) throw new Error("Agente indisponível. Atualize a biblioteca.");
      if (agent.workspace_mode) setMode(agent.workspace_mode, true);
      $("agent-select").value = id; $("agent-select").dispatchEvent(new Event("change"));
    }
  });
  $("workspace-mode-select").addEventListener("change", event => setMode(event.target.value));
  document.querySelectorAll("[data-workspace-mode]").forEach(item => item.addEventListener("click", () => setMode(item.dataset.workspaceMode)));
  $("model-select").addEventListener("change", compatibility);
  $("agent-select").addEventListener("change", () => {
    const agent = state.agents.find(item => item.id === $("agent-select").value);
    if ($("security-dialog").open && agent?.workspace_mode) { setMode(agent.workspace_mode, true); $("agent-select").value = agent.id; }
    renderMonitor(); compatibility();
  });
  $("mode-select").addEventListener("change", compatibility);
  document.addEventListener("nexus:status", () => { renderMonitor(); if (state.initializing) return; compatibility(); });
  document.addEventListener("nexus:busy", event => document.querySelectorAll("[data-workspace-mode]").forEach(item => { item.disabled = event.detail.busy; }));
  document.addEventListener("nexus:session", event => {
    const mode = event.detail.workspace_mode || event.detail.session?.workspace_mode;
    if (mode) setMode(mode, false);
  });
  $("chat-form").addEventListener("submit", event => {
    if (state.compatibility?.compatible === false) { event.preventDefault(); event.stopImmediatePropagation(); app.notify(state.compatibility.reason || "Escolha um modelo compatível com este modo.", true); }
  }, true);
  const researchSection = element("section", undefined, "research-report-section");
  researchSection.append(element("h3", "Pesquisas, sessões e fontes"), element("p", "Resultados de consultas realizadas pelas ferramentas. O filtro respeita o projeto selecionado no chat.", "panel-description"), action("Atualizar pesquisas", researchReports));
  const researchList = element("div", undefined, "security-list"); researchList.id = "research-report-list"; researchSection.append(researchList); $("security-reports").append(researchSection);
  $("nav-reports").addEventListener("click", () => { app.closeSidebar(); researchReports(); });
  (async () => {
    try {
      const data = await app.api("/api/workspace-modes"); state.modes = list(data, "modes");
      $("workspace-mode-select").replaceChildren(...state.modes.map(mode => { const option = element("option", mode.name); option.value = mode.id; return option; }));
      const all = element("option", "Todos os modos"); all.value = "";
      $("sessions-filter-mode").replaceChildren(all, ...state.modes.map(mode => { const option = element("option", mode.name); option.value = mode.id; return option; }));
      await refreshAgents(); state.initializing = false; setMode(data.active || "chat");
    } catch (error) { $("workspace-compatibility").textContent = `Modos indisponíveis: ${error.message}`; }
  })();
})();
