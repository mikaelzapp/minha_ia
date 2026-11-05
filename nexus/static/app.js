"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const defaultProfiles = [
    { id: "standard", name: "NEXUS PADRÃO", preserve_original: false },
    { id: "unrestricted_local", name: "NEXUS UNRESTRICTED — LOCAL", preserve_original: true }
  ];
  const state = { status: null, profiles: defaultProfiles, profile: null, activeInference: null, computer: null, sessions: [], projects: [], session: null, project: "", busy: false, abort: null, attachments: [], approvals: new Map(), panel: "settings", pollBusy: false, activity: [] };
  const modeDescriptions = {
    CHAT: "Chat · conversa sem modificar arquivos", PLAN: "Plan · arquitetura e planejamento",
    CODE: "Code · alterações com diffs revisáveis", AGENT: "Agent · planejar, implementar e testar",
    REVIEW: "Review · análise de código e segurança", RESEARCH: "Research · pesquisa com fontes"
  };
  let toastTimer;
  let renderFrame;
  let initialized = false;
  const nf = new Intl.NumberFormat("pt-BR", { maximumFractionDigits: 1 });

  function node(tag, className, content) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (content !== undefined) element.textContent = String(content);
    return element;
  }

  function icon(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.classList.add("icon");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#i-${name}`);
    svg.append(use);
    return svg;
  }

  function button(label, className, handler, iconName) {
    const result = node("button", className);
    result.type = "button";
    if (iconName) result.append(icon(iconName));
    if (label) result.append(document.createTextNode(label));
    result.addEventListener("click", handler);
    return result;
  }

  function listOf(value, ...keys) {
    if (Array.isArray(value)) return value;
    for (const key of keys) if (Array.isArray(value?.[key])) return value[key];
    return [];
  }

  function pretty(value) {
    return typeof value === "string" ? value : JSON.stringify(value, null, 2) ?? "";
  }

  function inferenceLabel(metadata = {}, profileName) {
    const used = Array.isArray(metadata.models_used) ? [...new Set(metadata.models_used.filter(value => typeof value === "string" && value))] : [];
    const model = used.length ? used.join(" + ") : typeof metadata.model === "string" ? metadata.model : "";
    const profile = profileName || (typeof metadata.profile === "object" ? metadata.profile?.name : state.profiles.find(item => item.id === metadata.profile)?.name);
    return [model, metadata.review_model ? `Revisão: ${metadata.review_model}` : "", metadata.agent_name || metadata.agent, metadata.workspace_mode, profile].filter(Boolean).join(" · ");
  }

  async function api(path, options = {}) {
    const { json, ...rest } = options;
    const response = await fetch(path, {
      credentials: "same-origin", cache: "no-store", ...rest,
      headers: { ...(json !== undefined ? { "Content-Type": "application/json" } : {}), ...rest.headers },
      ...(json !== undefined ? { body: JSON.stringify(json) } : {})
    });
    if (!response.ok) {
      let detail, code, source;
      try { const data = await response.json(); detail = data.detail || data.error || data.message; code = data.code; source = data.source; } catch (_) { /* HTTP status remains available. */ }
      const message = typeof detail === "string" ? detail : `A operação falhou (HTTP ${response.status}).`;
      throw new Error(`${message}${code || source ? ` [${[source, code].filter(Boolean).join(" / ")}]` : ""}`);
    }
    if (response.status === 204) return null;
    return response.json();
  }

  function notify(message, error = false) {
    clearTimeout(toastTimer);
    $("toast").textContent = message;
    $("toast").classList.toggle("error", error);
    $("toast").hidden = false;
    toastTimer = setTimeout(() => { $("toast").hidden = true; }, error ? 8000 : 4200);
  }

  function dialogStatus(message, error = false) {
    $("dialog-status").textContent = message;
    $("dialog-status").classList.toggle("error", error);
    $("dialog-status").hidden = !message;
  }

  async function action(target, callback, pendingText) {
    if (target.disabled) return;
    target.disabled = true;
    const oldNodes = [...target.childNodes];
    if (pendingText) target.textContent = pendingText;
    try { await callback(); }
    catch (error) {
      if ($("manage-dialog").open) dialogStatus(error.message, true);
      else notify(error.message, true);
    } finally {
      target.disabled = false;
      if (pendingText) target.replaceChildren(...oldNodes);
    }
  }

  function safeLink(url) {
    try {
      const parsed = new URL(url);
      return ["http:", "https:"].includes(parsed.protocol) ? parsed.href : null;
    } catch (_) { return null; }
  }

  // Every model response, tool result and filename enters the DOM as text.
  function inlineMarkdown(parent, value) {
    const pattern = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\[[^\]\n]+\]\(https?:\/\/[^\s)]+\)|https?:\/\/[^\s<>]+)/g;
    let start = 0;
    for (const match of value.matchAll(pattern)) {
      parent.append(document.createTextNode(value.slice(start, match.index)));
      const part = match[0];
      if (part.startsWith("`")) parent.append(node("code", "", part.slice(1, -1)));
      else if (part.startsWith("**")) parent.append(node("strong", "", part.slice(2, -2)));
      else {
        const markdownLink = part.match(/^\[([^\]]+)\]\((.+)\)$/);
        const label = markdownLink ? markdownLink[1] : part;
        const href = safeLink(markdownLink ? markdownLink[2] : part);
        if (href) {
          const link = node("a", "", label);
          link.href = href;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          parent.append(link);
        } else parent.append(document.createTextNode(label));
      }
      start = match.index + part.length;
    }
    parent.append(document.createTextNode(value.slice(start)));
  }

  function copyText(text, target) {
    if (!navigator.clipboard) { notify("A cópia automática não está disponível neste navegador. Selecione o texto para copiar.", true); return; }
    navigator.clipboard.writeText(text).then(() => {
      const oldNodes = [...target.childNodes];
      target.replaceChildren(icon("check"), document.createTextNode("Copiado"));
      setTimeout(() => target.replaceChildren(...oldNodes), 1600);
    }).catch(() => notify("O navegador bloqueou a cópia para a área de transferência.", true));
  }

  function codeBlock(text, language = "código", diff = false) {
    const block = node("div", "code-block");
    const header = node("div", "code-header");
    header.append(node("span", "", language));
    const copy = button("Copiar", "code-copy", () => copyText(text, copy), "copy");
    header.append(copy);
    const pre = node("pre");
    const code = node("code");
    if (diff) {
      for (const line of text.split("\n")) code.append(node("span", line.startsWith("+") ? "diff-add" : line.startsWith("-") ? "diff-remove" : "", `${line}\n`));
    } else code.textContent = text;
    pre.append(code);
    block.append(header, pre);
    return block;
  }

  function renderMarkdown(container, content) {
    const fragment = document.createDocumentFragment();
    const fences = /```([^\n`]*)\n([\s\S]*?)(?:```|$)/g;
    let start = 0;
    const prose = (text) => {
      let paragraph = [];
      let list;
      const flush = () => {
        if (paragraph.length) { const p = node("p"); inlineMarkdown(p, paragraph.join("\n")); fragment.append(p); paragraph = []; }
      };
      for (const line of text.split("\n")) {
        const heading = line.match(/^(#{1,4})\s+(.+)$/);
        const item = line.match(/^\s*(?:([-*])\s+|(\d+)\.\s+)(.+)$/);
        if (heading) {
          flush(); list = null;
          const h = node(`h${Math.min(heading[1].length + 1, 4)}`); inlineMarkdown(h, heading[2]); fragment.append(h);
        } else if (item) {
          flush(); const type = item[2] ? "OL" : "UL";
          if (!list || list.tagName !== type) { list = node(type.toLowerCase()); fragment.append(list); }
          const li = node("li"); inlineMarkdown(li, item[3]); list.append(li);
        } else if (!line.trim()) { flush(); list = null; }
        else { list = null; paragraph.push(line); }
      }
      flush();
    };
    for (const match of content.matchAll(fences)) {
      prose(content.slice(start, match.index));
      fragment.append(codeBlock(match[2].replace(/\n$/, ""), match[1].trim() || "código"));
      start = match.index + match[0].length;
    }
    prose(content.slice(start));
    container.replaceChildren(fragment);
  }

  function nearBottom() {
    const scroll = $("chat-scroll");
    return scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 150;
  }

  function scrollBottom(force = false) {
    if (force || nearBottom()) $("chat-scroll").scrollTop = $("chat-scroll").scrollHeight;
  }

  function addMessage(role, content = "", timestamp) {
    $("welcome").hidden = true;
    const section = node("article", `message ${role === "user" ? "user" : "assistant"}`);
    const header = node("div", "message-header");
    header.append(node("span", "message-avatar", role === "user" ? "M" : "N"), node("span", "", role === "user" ? "Você" : "NEXUS AI"));
    if (timestamp) {
      const date = new Date(timestamp);
      if (!Number.isNaN(date.valueOf())) {
        const time = node("time", "", date.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }));
        time.dateTime = date.toISOString(); header.append(time);
      }
    }
    const body = node("div", "message-body");
    section.append(header, body);
    $("messages").append(section);
    renderMarkdown(body, content);
    return { section, body, content };
  }

  function addCopyTool(message) {
    if (!message.content) return;
    const tools = node("div", "message-tools");
    const copy = button("Copiar resposta", "", () => copyText(message.content, copy), "copy");
    tools.append(copy); message.section.append(tools);
  }

  function renderSessions() {
    const fragment = document.createDocumentFragment();
    if (!state.sessions.length) fragment.append(node("p", "sidebar-empty", "Seu próximo projeto começa\ncom uma conversa."));
    for (const session of state.sessions) {
      const item = node("div", `session-item${String(session.id) === String(state.session) ? " selected" : ""}`);
      const open = button("", "session-button", () => { if (!state.busy) loadSession(session.id); });
      open.disabled = state.busy;
      open.append(icon("chat"), node("span", "", session.title || "Conversa sem título"));
      open.title = session.title || "Conversa sem título";
      const remove = button("", "icon-button session-delete", () => action(remove, async () => {
        if (!confirm(`Excluir a conversa “${session.title || "sem título"}” e seu histórico?`)) return;
        await api(`/api/sessions/${encodeURIComponent(session.id)}`, { method: "DELETE" });
        if (String(session.id) === String(state.session)) newConversation();
        await refreshSessions();
      }), "trash");
      remove.setAttribute("aria-label", `Excluir conversa ${session.title || "sem título"}`);
      remove.disabled = state.busy;
      item.append(open, remove); fragment.append(item);
    }
    $("sessions").replaceChildren(fragment);
  }

  async function refreshSessions() {
    const query = new URLSearchParams();
    for (const [id, key] of [["sessions-filter-mode", "workspace_mode"], ["sessions-filter-agent", "agent"], ["sessions-filter-model", "model"], ["sessions-filter-date", "start_date"]]) {
      if ($(id)?.value) query.set(key, $(id).value);
    }
    const data = await api(`/api/sessions${query.size ? `?${query}` : ""}`);
    state.sessions = listOf(data, "sessions", "items"); renderSessions();
  }

  async function loadSession(id) {
    try {
      const data = await api(`/api/sessions/${encodeURIComponent(id)}`);
      if (state.busy) return;
      state.session = id;
      $("messages").replaceChildren();
      const messages = listOf(data, "messages");
      $("welcome").hidden = messages.length > 0;
      for (const message of messages) {
        if (!["user", "assistant"].includes(message.role)) continue;
        const rendered = addMessage(message.role, String(message.content || ""), message.created_at);
        if (message.role === "assistant") {
          addCopyTool(rendered);
          const metadata = message.metadata || message.meta || {};
          const source = { ...metadata, ...(message.model ? { model: message.model } : {}), ...(message.agent ? { agent: message.agent } : {}), ...(message.workspace_mode ? { workspace_mode: message.workspace_mode } : {}) };
          const label = inferenceLabel(source);
          if (label) rendered.section.insertBefore(node("div", "message-inference", label), rendered.body);
        }
      }
      const projectId = data.project_id ?? state.sessions.find(s => String(s.id) === String(id))?.project_id;
      if (projectId !== undefined) {
        state.project = projectId ? String(projectId) : "";
        $("project-select").value = state.project; updateProjectHint();
      }
      $("session-title").textContent = data.title || state.sessions.find(s => String(s.id) === String(id))?.title || "Conversa";
      renderSessions(); closeSidebar(); scrollBottom(true);
      document.dispatchEvent(new CustomEvent("nexus:session", { detail: data }));
    } catch (error) { notify(error.message, true); }
  }

  function newConversation() {
    if (state.busy) return;
    state.session = null;
    state.attachments = [];
    $("attachments").replaceChildren();
    $("messages").replaceChildren();
    $("welcome").hidden = false;
    $("session-title").textContent = "Nova conversa";
    $("speed-label").textContent = "— tok/s";
    $("latency-label").textContent = "—";
    $("prompt").value = ""; resizePrompt(); renderSessions(); closeSidebar();
    $("prompt").focus();
  }

  function fillSelect(target, options, selected) {
    target.replaceChildren();
    for (const option of options) {
      const item = node("option", "", option.label); item.value = option.value; target.append(item);
    }
    if (options.some(o => String(o.value) === String(selected))) target.value = selected;
  }

  function selectedProfile(id = state.profile) {
    return state.profiles.find(profile => profile.id === id) || state.profiles[0];
  }

  function updateActiveProfile() {
    const profile = selectedProfile();
    $("profile-select").title = `${profile.name} · ativo para as próximas mensagens`;
    $("profile-select").classList.toggle("original-profile", Boolean(profile.preserve_original));
    $("model-select").title = $("model-select").value ? `Modelo ativo: ${$("model-select").value}` : "Nenhum modelo local disponível";
    $("profile-description").textContent = profile.preserve_original
      ? "Resposta original do modelo · sem revisão automática. Permissões do computador preservadas."
      : state.status?.settings?.quality_mode === "careful"
        ? "Perfil padrão · revisão automática ativa. Permissões do computador preservadas."
        : "Perfil padrão · resposta direta. Permissões do computador preservadas.";
    $("active-inference").hidden = !state.busy || !state.activeInference;
    if (state.busy && state.activeInference) $("active-inference").textContent = state.activeInference.provenance || `Em uso: ${state.activeInference.model} · ${state.activeInference.profile.name}`;
  }

  function updateProfileSettings() {
    const original = Boolean(selectedProfile($("settings-profile").value).preserve_original);
    $("settings-quality").disabled = original;
    $("quality-help").textContent = original
      ? "Este perfil entrega a resposta original sem revisão automática. A escolha de qualidade fica salva para o perfil padrão."
      : "Cuidadoso prioriza análise, verificação e clareza. Pode demorar mais; revise os resultados importantes.";
  }

  function showStatus(data) {
    state.status = data;
    const running = Boolean(data.ollama?.connected ?? data.ollama?.available ?? data.ollama?.ok ?? (Array.isArray(data.ollama?.running) ? data.ollama.running.length > 0 : data.ollama?.running));
    $("connection-status").className = `connection ${running ? "ready" : "offline"}`;
    $("connection-status").lastElementChild.textContent = running ? "Ollama conectado" : "Ollama indisponível";
    $("connection-status").title = data.ollama?.error || (running ? "Motor de inferência local disponível" : "Inicie o Ollama e instale um modelo para conversar.");
    const models = listOf(data.ollama?.models, "models").filter(model => {
      const name = typeof model === "string" ? model : model.name || "";
      const capabilities = typeof model === "object" && Array.isArray(model.capabilities) ? model.capabilities : [];
      return !(/(?:embed|all-minilm|^bge-|^e5-)/i.test(name) || (capabilities.includes("embedding") && !capabilities.includes("completion")));
    }).map(model => typeof model === "string" ? model : model.name).filter(Boolean);
    const currentModel = $("model-select").value || data.settings?.model || "";
    const modelOptions = models.map(name => ({ value: name, label: name }));
    if (!modelOptions.length) modelOptions.push({ value: "", label: "Nenhum modelo disponível" });
    fillSelect($("model-select"), modelOptions, currentModel);
    fillSelect($("sessions-filter-model"), [{ value: "", label: "Todos os modelos" }, ...modelOptions.filter(option => option.value)], $("sessions-filter-model").value);
    if (Array.isArray(data.agents)) fillSelect($("sessions-filter-agent"), [{ value: "", label: "Todos os agentes" }, ...data.agents.map(agent => ({ value: agent.id, label: agent.name }))], $("sessions-filter-agent").value);
    const profiles = listOf(data.profiles, "profiles").filter(profile => typeof profile?.id === "string" && typeof profile?.name === "string");
    state.profiles = profiles.length ? profiles : defaultProfiles;
    if (!state.profiles.some(profile => profile.id === state.profile)) {
      state.profile = state.profiles.find(profile => profile.id === data.settings?.profile)?.id || state.profiles[0].id;
    }
    const profileOptions = state.profiles.map(profile => ({ value: profile.id, label: profile.name }));
    fillSelect($("profile-select"), profileOptions, state.profile);
    updateActiveProfile();
    if (!$("manage-dialog").open) {
      fillSelect($("settings-model"), modelOptions, data.settings?.model || currentModel);
      fillCodingModels(data.settings?.coding_model || "");
      fillSelect($("settings-profile"), profileOptions, data.settings?.profile || state.profile);
      updateProfileSettings();
    }
    if (!initialized) {
      if (Array.isArray(data.agents) && data.agents.length) fillSelect($("agent-select"), data.agents.map(a => ({ value: a.id, label: a.name })), "auto");
      if (Array.isArray(data.modes) && data.modes.length) fillSelect($("mode-select"), data.modes.map(m => ({ value: m, label: m })), "CHAT");
      initialized = true;
    }
    const system = data.system || {};
    const gpus = listOf(system.gpu, "gpus");
    const gpu = gpus[0];
    if (gpu) {
      $("gpu-name").textContent = gpu.name || "GPU detectada";
      const used = Number(gpu.memory_used_mb || 0), total = Number(gpu.memory_total_mb || 0);
      $("gpu-memory").textContent = `${nf.format(used / 1024)} / ${nf.format(total / 1024)} GB`;
      $("gpu-util").textContent = gpu.utilization != null ? `${nf.format(Number(gpu.utilization))}%` : "—";
      $("gpu-meter").style.width = `${Math.min(100, total ? used / total * 100 : 0)}%`;
    } else {
      $("gpu-name").textContent = "GPU não detectada";
      $("gpu-util").textContent = "—";
      $("gpu-memory").textContent = "Dados indisponíveis";
      $("gpu-meter").style.width = "0%";
    }
    const ramTotal = Number(system.ram_total_gb || 0), ramUsed = Number(system.ram_used_gb || 0);
    $("ram-used").textContent = ramTotal ? `${nf.format(ramUsed)} GB de ${nf.format(ramTotal)} GB` : "Dados indisponíveis";
    $("ram-percent").textContent = ramTotal ? `${Math.round(ramUsed / ramTotal * 100)}%` : "—";
    $("ram-meter").style.width = `${Math.min(100, ramTotal ? ramUsed / ramTotal * 100 : 0)}%`;
    $("ram-free").textContent = system.ram_available_gb != null ? `${nf.format(Number(system.ram_available_gb))} GB` : "—";
    $("context-label").textContent = `${Number(data.settings?.context || 4096).toLocaleString("pt-BR")} tokens`;
    $("temperature-label").textContent = nf.format(Number(data.settings?.temperature ?? 0.3));
    $("workspace-root").textContent = data.workspace_root || "Não informado pelo servidor";
    updateTor();
    updateSend();
    document.dispatchEvent(new CustomEvent("nexus:status", { detail: data }));
  }

  async function refreshStatus() {
    if (state.pollBusy) return;
    state.pollBusy = true;
    try { showStatus(await api("/api/status")); }
    catch (_) {
      $("connection-status").className = "connection offline";
      $("connection-status").lastElementChild.textContent = "Servidor indisponível";
      $("connection-status").title = "Não foi possível consultar o servidor NEXUS. Verifique se o serviço está em execução.";
    } finally { state.pollBusy = false; }
  }

  function updateTor() {
    const enabled = Boolean(state.status?.settings?.tor_enabled);
    $("tor-badge").textContent = enabled ? "Ativado" : "Desativado";
    $("tor-badge").classList.toggle("enabled", enabled);
    $("tor-toggle").textContent = enabled ? "Desativar Tor Research" : "Ativar explicitamente";
    $("tor-detail").textContent = enabled ? "Módulo autorizado. A disponibilidade do proxy será validada em cada consulta." : "Desativado por padrão. A conexão será verificada antes da navegação.";
  }

  function fillCodingModels(selected) {
    const models = [...$("model-select").options].filter(option => option.value).map(option => ({ value: option.value, label: option.textContent }));
    fillSelect($("settings-coding-model"), [{ value: "", label: "Usar modelo atual" }, ...models], selected);
  }

  function renderComputer() {
    const computer = state.computer;
    const enabled = Boolean(computer?.enabled);
    $("computer-enabled").checked = enabled;
    $("computer-enabled").disabled = !computer;
    $("computer-badge").textContent = computer ? enabled ? "Ativado" : "Desativado" : "Indisponível";
    $("computer-badge").classList.toggle("enabled", enabled);
    $("computer-root-path").disabled = !enabled;
    $("computer-root-add").disabled = !enabled;
    $("computer-install-help").textContent = computer?.winget_available
      ? "Para instalar um programa, use o modo AGENT com NEXUS DEVOPS e peça a instalação no chat. Você revisará o pacote e o comando antes de aprovar."
      : "Instalações pelo chat precisam do Gerenciador de Pacotes do Windows (winget), que não está disponível neste momento. As ferramentas de projetos continuam disponíveis nas pastas autorizadas.";
    const fragment = document.createDocumentFragment();
    const roots = listOf(computer, "roots");
    if (!roots.length) fragment.append(node("div", "empty-state", computer ? "Nenhuma pasta adicional autorizada. Adicione uma pasta para trabalhar em projetos fora do workspace." : "Não foi possível consultar as pastas autorizadas. Reabra as configurações para tentar novamente."));
    for (const root of roots) {
      const card = node("article", "management-card computer-root-card");
      const details = node("div");
      details.append(node("h4", "", root.name || "Pasta autorizada"), node("code", "", root.path || ""));
      const revoke = button("Revogar", "danger-button small", () => action(revoke, async () => {
        await api(`/api/computer/roots/${encodeURIComponent(root.id)}`, { method: "DELETE" });
        await refreshComputer();
        dialogStatus("Autorização da pasta revogada.");
      }, "Revogando…"));
      revoke.setAttribute("aria-label", `Revogar acesso à pasta ${root.name || root.path || "autorizada"}`);
      card.append(details, revoke); fragment.append(card);
    }
    $("computer-roots").replaceChildren(fragment);
  }

  async function refreshComputer() {
    state.computer = await api("/api/computer");
    renderComputer();
  }

  async function refreshProjects() {
    const data = await api("/api/projects");
    state.projects = listOf(data, "projects", "items");
    $("projects-count").textContent = state.projects.length;
    if (state.project && !state.projects.some(p => String(p.id) === state.project)) state.project = "";
    fillSelect($("project-select"), [{ value: "", label: "Nenhum projeto" }, ...state.projects.map(p => ({ value: String(p.id), label: p.name }))], state.project);
    updateProjectHint(); renderProjects();
  }

  function updateProjectHint() {
    const project = state.projects.find(p => String(p.id) === state.project);
    $("project-hint").textContent = project ? (project.path || "Contexto do projeto ativo nesta conversa.") : "Selecione um projeto para consultar seus arquivos e sua memória.";
    $("project-hint").title = project?.path || "";
  }

  function renderProjects() {
    const fragment = document.createDocumentFragment();
    if (!state.projects.length) fragment.append(node("div", "empty-state", "Nenhum projeto adicionado. Crie ou selecione uma pasta no diretório de trabalho para começar."));
    for (const project of state.projects) {
      const card = node("article", "management-card");
      card.append(node("h4", "", project.name), node("code", "", project.path || ""));
      const actions = node("div", "management-actions");
      const select = button("Usar na conversa", "secondary-button small", () => {
        if (state.busy) { dialogStatus("Aguarde a geração atual para trocar de projeto.", true); return; }
        state.project = String(project.id); $("project-select").value = state.project; updateProjectHint();
        dialogStatus(`Projeto “${project.name}” selecionado.`);
      });
      const index = button("Indexar arquivos", "secondary-button small", () => action(index, async () => {
        dialogStatus("Indexando arquivos autorizados. Isso pode levar alguns instantes…");
        const result = await api(`/api/projects/${encodeURIComponent(project.id)}/index`, { method: "POST" });
        dialogStatus(result.message || `Indexação concluída. ${result.indexed ?? result.files_indexed ?? result.files ?? ""} arquivos processados.`);
        await refreshProjects();
      }, "Indexando…"));
      actions.append(select, index); card.append(actions);
      if (project.indexed_at || project.file_count != null) card.append(node("div", "management-meta", `${project.file_count != null ? `${project.file_count} arquivos · ` : ""}${project.indexed_at ? `Indexado em ${new Date(project.indexed_at).toLocaleString("pt-BR")}` : "Aguardando indexação"}`));
      fragment.append(card);
    }
    $("projects-list").replaceChildren(fragment);
  }

  async function searchMemory() {
    const query = new URLSearchParams({ q: $("memory-query").value.trim() });
    if (state.project) query.set("project_id", state.project);
    $("memory-list").replaceChildren(node("p", "muted-text", "Consultando memória local…"));
    const data = await api(`/api/memory/search?${query}`);
    const memories = listOf(data, "results", "memories", "items");
    const fragment = document.createDocumentFragment();
    if (!memories.length) fragment.append(node("div", "empty-state", $("memory-query").value.trim() ? "Nenhuma memória encontrada para esta busca." : "Digite uma palavra para recuperar suas memórias. Você também pode adicionar uma preferência ou exportar os registros armazenados."));
    for (const memory of memories) {
      const card = node("article", "management-card");
      card.append(node("h4", "", memory.path || memory.source || memory.title || ({ preference: "Preferência", decision: "Decisão técnica", note: "Anotação" })[memory.kind] || memory.kind || "Memória"));
      card.append(node("p", "", memory.text ?? memory.content ?? ""));
      const meta = [memory.created_at ? new Date(memory.created_at).toLocaleString("pt-BR") : "", memory.score != null ? `Relevância: ${nf.format(Number(memory.score))}` : ""].filter(Boolean).join(" · ");
      if (meta) card.append(node("div", "management-meta", meta));
      if (memory.id != null && !["file", "chunk", "project"].includes(memory.kind)) {
        const remove = button("Excluir memória", "text-button", () => action(remove, async () => {
          if (!confirm("Excluir esta memória permanentemente?")) return;
          await api(`/api/memory/${encodeURIComponent(memory.id)}`, { method: "DELETE" });
          await searchMemory(); dialogStatus("Memória excluída.");
        }));
        card.append(remove);
      }
      fragment.append(card);
    }
    $("memory-list").replaceChildren(fragment);
  }

  function openPanel(panel) {
    state.panel = panel;
    $("dialog-title").textContent = ({ settings: "Configurações", projects: "Seus projetos", memory: "Sua memória" })[panel];
    document.querySelectorAll(".dialog-panel").forEach(p => { p.hidden = p.id !== `panel-${panel}`; });
    document.querySelectorAll("[data-panel]").forEach(tab => { tab.classList.toggle("selected", tab.dataset.panel === panel); tab.setAttribute("aria-current", tab.dataset.panel === panel ? "page" : "false"); });
    dialogStatus("");
    if (panel === "settings") {
      const settings = state.status?.settings || {};
      fillSelect($("settings-model"), [...$("model-select").options].map(o => ({ value: o.value, label: o.textContent })), settings.model || $("model-select").value);
      fillSelect($("settings-profile"), state.profiles.map(profile => ({ value: profile.id, label: profile.name })), settings.profile || state.profile);
      fillCodingModels(settings.coding_model || "");
      $("settings-quality").value = settings.quality_mode === "balanced" ? "balanced" : "careful";
      updateProfileSettings();
      const context = String(settings.context || 4096);
      if (![...$("settings-context").options].some(o => o.value === context)) {
        const option = node("option", "", `${Number(context).toLocaleString("pt-BR")} tokens`); option.value = context; $("settings-context").append(option);
      }
      $("settings-context").value = context;
      $("settings-temperature").value = settings.temperature ?? 0.3;
      $("settings-thinking").checked = Boolean(settings.thinking);
      $("temperature-output").value = nf.format(Number($("settings-temperature").value)); updateTor();
      refreshComputer().catch(error => { state.computer = null; renderComputer(); dialogStatus(error.message, true); });
    }
    if (!$("manage-dialog").open) $("manage-dialog").showModal();
    closeSidebar();
    if (panel === "projects") refreshProjects().catch(e => dialogStatus(e.message, true));
    if (panel === "memory") searchMemory().catch(e => dialogStatus(e.message, true));
  }

  function renderActivity() {
    const fragment = document.createDocumentFragment();
    if (!state.activity.length) fragment.append(node("p", "muted-text", "As ações das ferramentas aparecem aqui."));
    for (const item of state.activity.slice(0, 12)) {
      const row = node("div", `activity-item${item.error ? " error" : ""}`);
      const details = node("details");
      const auditLabels = { generation: "Resposta gerada", settings: "Configurações atualizadas", project_registered: "Projeto adicionado", project_indexed: "Projeto indexado", approval_requested: "Aprovação solicitada", approval_decision: "Aprovação respondida", upload: "Arquivo anexado", error: "Erro registrado" };
      details.append(node("summary", "", item.title || item.action || item.tool || item.name || auditLabels[item.kind] || item.event || item.kind || "Operação registrada"));
      details.append(node("pre", "", pretty(item.detail || item.arguments || item.result || item)));
      row.append(details);
      const date = item.created_at || item.timestamp;
      if (date) { const parsed = new Date(date); if (!Number.isNaN(parsed.valueOf())) row.append(node("span", "", parsed.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }))); }
      fragment.append(row);
    }
    $("activity-list").replaceChildren(fragment);
  }

  function logActivity(title, detail, error = false) {
    state.activity.unshift({ title, detail, error, created_at: new Date().toISOString() }); renderActivity();
  }

  async function refreshAudit() {
    const data = await api("/api/audit?limit=30");
    state.activity = listOf(data, "events", "entries", "logs", "items"); renderActivity();
  }

  function showTool(message, event) {
    const details = node("details", "tool-event");
    details.append(node("summary", "", `Ferramenta · ${event.name || "operação"}`));
    if (event.arguments !== undefined) details.append(node("pre", "", pretty(event.arguments)));
    if (event.result !== undefined) {
      const result = node("div", "tool-result"); inlineMarkdown(result, pretty(event.result)); details.append(result);
      const screenshot = typeof event.result?.screenshot === "string" ? event.result.screenshot.match(/^screenshots\/([a-f0-9]{32}\.png)$/) : null;
      if (screenshot) {
        const link = node("a", "tool-screenshot", "Abrir captura de tela ↗");
        link.href = `/api/screenshots/${screenshot[1]}`;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        details.append(link);
      }
    }
    message.section.append(details);
    logActivity(event.name || "Ferramenta", { arguments: event.arguments, result: event.result });
    scrollBottom();
  }

  function showApproval(message, event) {
    const id = String(event.id);
    if (state.approvals.has(id)) return;
    const card = node("section", "approval-card");
    card.setAttribute("aria-label", "Aprovação de ferramenta pendente");
    card.append(node("h4", "", "Sua aprovação é necessária"));
    card.append(node("p", "", typeof event.action === "string" ? event.action : pretty(event.action)));
    if (event.reason) card.append(node("p", "", event.reason));
    if (event.path) card.append(node("p", "", `Arquivo: ${event.path}`));
    if (event.diff_truncated) card.append(node("p", "message-error", "O diff foi truncado pelo servidor. Revise o conteúdo completo nos argumentos antes de decidir."));
    if (event.diff) card.append(codeBlock(pretty(event.diff), "diff para revisão", true));
    const metadata = event.metadata && typeof event.metadata === "object" ? event.metadata : {};
    const approvalArguments = event.arguments ?? event.args;
    const fields = [
      ["Pacote", event.package_id ?? metadata.package_id],
      ["Publicador", event.publisher ?? metadata.publisher],
      ["Licença", event.license ?? metadata.license],
      ["Escopo", event.scope ?? metadata.scope],
      ["Versão", event.version ?? metadata.version]
    ].filter(([, value]) => value !== undefined && value !== null && value !== "");
    if (fields.length) {
      const facts = node("dl", "approval-metadata");
      for (const [label, value] of fields) facts.append(node("dt", "", label), node("dd", "", pretty(value)));
      card.append(facts);
    }
    const command = event.command ?? metadata.command ?? approvalArguments?.command ?? (Array.isArray(event.args) ? event.args : undefined);
    if (command) card.append(codeBlock(pretty(command), "comando para aprovação"));
    if (event.package_details) {
      const details = node("details", "approval-package-details");
      details.append(node("summary", "", "Detalhes do aplicativo e licença"), node("pre", "", pretty(event.package_details)));
      card.append(details);
    }
    const risks = Array.isArray(event.risks) ? event.risks : event.risks ? [event.risks] : [];
    if (risks.length) {
      const list = node("ul", "approval-risks");
      for (const risk of risks) list.append(node("li", "", pretty(risk)));
      card.append(list);
    }
    if (approvalArguments) card.append(codeBlock(pretty(approvalArguments), "argumentos"));
    const actions = node("div", "approval-actions");
    const decision = node("p", "approval-decision");
    decision.setAttribute("role", "status");
    const approve = button("Aprovar esta ação", "primary-button", () => decide(true));
    const deny = button("Recusar", "secondary-button", () => decide(false));
    const decide = async (approved) => {
      approve.disabled = true; deny.disabled = true;
      try {
        await api(`/api/approvals/${encodeURIComponent(id)}`, { method: "POST", json: { approved } });
        decision.textContent = approved ? "Ação autorizada. Aguardando resultado da ferramenta." : "Ação recusada.";
        state.approvals.delete(id); actions.replaceChildren();
        logActivity(approved ? "Aprovação concedida" : "Aprovação recusada", event.action);
        streamStatus(approved ? "Executando a ação autorizada…" : "Continuando após a recusa…");
      } catch (error) { approve.disabled = false; deny.disabled = false; decision.textContent = error.message; }
    };
    actions.append(approve, deny); card.append(actions, decision); message.section.append(card);
    state.approvals.set(id, { decide, card, decision, actions });
    streamStatus("Aguardando sua aprovação. Revise a ação e o diff na conversa.");
    scrollBottom(true);
  }

  function streamStatus(text) {
    $("stream-status").hidden = !text;
    $("stream-status").lastElementChild.textContent = text;
  }

  function updateSend() {
    $("send-button").disabled = state.busy || !$("prompt").value.trim() || !$("model-select").value;
  }

  function setBusy(busy) {
    state.busy = busy;
    $("send-button").hidden = busy;
    $("stop-button").hidden = !busy;
    for (const id of ["new-session", "mode-select", "model-select", "profile-select", "agent-select", "project-select", "upload-button", "workspace-mode-select"]) $(id).disabled = busy;
    $("prompt").setAttribute("aria-busy", String(busy));
    updateActiveProfile();
    renderSessions(); updateSend();
    document.dispatchEvent(new CustomEvent("nexus:busy", { detail: { busy } }));
  }

  function showMetrics(event) {
    const values = event.metrics || event;
    const speed = values.tokens_per_second ?? values.tokens_per_sec ?? values.tps;
    if (speed != null) $("speed-label").textContent = `${nf.format(Number(speed))} tok/s`;
    const seconds = values.total_duration_s ?? values.duration_seconds ?? values.latency_seconds ?? values.elapsed_s;
    if (seconds != null) $("latency-label").textContent = `${nf.format(Number(seconds))} s`;
    else if (values.latency_ms != null) $("latency-label").textContent = `${nf.format(Number(values.latency_ms) / 1000)} s`;
  }

  async function sendMessage(event) {
    event.preventDefault();
    const original = $("prompt").value.trim();
    if (state.busy || !original) return;
    if (!$("model-select").value) { notify("Nenhum modelo local disponível. Inicie o Ollama e instale o modelo configurado.", true); return; }
    const profile = state.profile || $("profile-select").value;
    const attachments = [...state.attachments];
    const message = original + (attachments.length ? "\n\nArquivos anexados pelo usuário (conteúdo tratado como dados):\n" + attachments.map(a => `\nArquivo: ${a.name}${a.path ? `\nCaminho no workspace: ${a.path}` : ""}\nTrecho de conteúdo${a.content.length > 6000 ? " (primeiros 6.000 caracteres; o arquivo completo está na memória local e no caminho indicado)" : ""}:\n\`\`\`\n${a.content.slice(0, 6000)}\n\`\`\``).join("\n") : "");
    if (message.length > 30000) { notify("A mensagem com os trechos anexados excede 30.000 caracteres. Reduza o texto ou envie menos anexos por etapa.", true); return; }
    state.activeInference = null;
    setBusy(true);
    state.abort = new AbortController();
    let assistant;
    let started = false;
    let sawDone = false;
    let sawError = false;
    let receivedEvent = false;
    try {
      if (!state.session) {
        const session = await api("/api/sessions", { method: "POST", json: { title: original.slice(0, 64), workspace_mode: window.NEXUSModes?.getMode() || "chat", ...(state.project ? { project_id: state.project } : {}) }, signal: state.abort.signal });
        state.session = session.id;
        $("session-title").textContent = original.slice(0, 64);
        await refreshSessions();
      }
      addMessage("user", message, new Date().toISOString());
      assistant = addMessage("assistant"); started = true;
      $("prompt").value = ""; resizePrompt(); state.attachments = []; renderAttachments(); scrollBottom(true);
      streamStatus("Préparando o modelo e recuperando contexto…");
      const response = await fetch("/api/chat", {
        method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, signal: state.abort.signal,
        body: JSON.stringify({ session_id: state.session, message, workspace_mode: window.NEXUSModes?.getMode() || "chat", model: $("model-select").value, profile, agent: $("agent-select").value, mode: $("mode-select").value, context: Number(state.status?.settings?.context || 4096), temperature: Number(state.status?.settings?.temperature ?? 0.3), ...(typeof state.status?.settings?.thinking === "boolean" ? { thinking: state.status.settings.thinking } : {}), ...(state.project ? { project_id: state.project } : {}) })
      });
      if (!response.ok) {
        let detail;
        try { const data = await response.json(); detail = data.detail || data.error; } catch (_) { /* Show HTTP failure. */ }
        throw new Error(typeof detail === "string" ? detail : `Não foi possível iniciar a conversa (HTTP ${response.status}).`);
      }
      if (!response.body) throw new Error("Este navegador não permite receber a resposta em streaming.");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      const consume = (line) => {
        if (!line.trim()) return;
        let data;
        try { data = JSON.parse(line); } catch (_) { throw new Error("O servidor retornou um evento de streaming inválido."); }
        receivedEvent = true;
        switch (data.type) {
          case "token": {
            const follow = nearBottom();
            assistant.content += String(data.content ?? "");
            if (!renderFrame) renderFrame = requestAnimationFrame(() => {
              renderFrame = null; renderMarkdown(assistant.body, assistant.content); if (follow) scrollBottom(true);
            });
            streamStatus("NEXUS está respondendo…"); break;
          }
          case "status": streamStatus(data.content || "Processando…"); break;
          case "research_status": {
            const evidence = node("div", `research-evidence${data.performed ? " performed" : ""}`);
            evidence.textContent = data.performed ? `Pesquisa ${data.via_tor ? "via Tor" : "na internet"} realizada · ${Number(data.sources_count || 0)} fontes · ${Array.isArray(data.queries) ? data.queries.length : 0} consultas` : "Nenhuma busca na internet foi realizada nesta resposta.";
            assistant.section.append(evidence); break;
          }
          case "profile": {
            const profile = data.profile;
            if (profile && typeof profile.name === "string" && typeof data.model === "string") {
              state.activeInference = { profile, model: data.model };
              updateActiveProfile();
              if (!assistant.inference) {
                assistant.inference = node("div", "message-inference");
                assistant.section.insertBefore(assistant.inference, assistant.body);
              }
              assistant.inferenceMetadata = { model: data.model, agent: data.agent || $("agent-select").selectedOptions[0]?.textContent, workspace_mode: data.workspace_mode || window.NEXUSModes?.getMode(), profile: profile.id };
              assistant.inference.textContent = inferenceLabel(assistant.inferenceMetadata, profile.name);
            }
            break;
          }
          case "provenance": {
            const metadata = data.metadata;
            if (metadata && typeof metadata === "object" && !Array.isArray(metadata)) {
              assistant.inferenceMetadata = { ...(assistant.inferenceMetadata || {}), ...metadata };
              if (!assistant.inference) { assistant.inference = node("div", "message-inference"); assistant.section.insertBefore(assistant.inference, assistant.body); }
              assistant.inference.textContent = inferenceLabel(assistant.inferenceMetadata);
              if (state.activeInference) { state.activeInference.provenance = `Modelos utilizados: ${inferenceLabel(assistant.inferenceMetadata, state.activeInference.profile.name)}`; updateActiveProfile(); }
            }
            break;
          }
          case "notice": {
            const notice = node("div", "generation-notice");
            notice.append(node("strong", "", data.source === "model" ? "Aviso do modelo" : "Aviso do aplicativo"), node("p", "", data.content || "O servidor informou uma limitação nesta geração."));
            assistant.section.append(notice);
            break;
          }
          case "tool": showTool(assistant, data); break;
          case "approval": showApproval(assistant, data); break;
          case "metrics": showMetrics(data); break;
          case "error": sawError = true; assistant.section.append(node("div", "message-error", data.content || data.message || "O motor local encontrou um erro.")); logActivity("Erro de geração", data.content, true); break;
          case "done": sawDone = true; break;
          default: break;
        }
      };
      while (true) {
        const { done, value } = await reader.read();
        buffer += decoder.decode(value, { stream: !done });
        let newline;
        while ((newline = buffer.indexOf("\n")) !== -1) { consume(buffer.slice(0, newline).replace(/\r$/, "")); buffer = buffer.slice(newline + 1); }
        if (done) { if (buffer.trim()) consume(buffer); break; }
      }
      if (!receivedEvent) throw new Error("O servidor encerrou a conexão sem retornar uma resposta.");
      if (!sawDone && !sawError) throw new Error("A conexão terminou antes da conclusão. A resposta pode estar incompleta.");
    } catch (error) {
      const stopped = error.name === "AbortError";
      if (assistant) assistant.section.append(node("div", stopped ? "muted-text" : "message-error", stopped ? "Geração interrompida. O conteúdo já produzido foi preservado." : error.message));
      else notify(stopped ? "Operação interrompida." : error.message, !stopped);
      if (!started) { $("prompt").value = original; state.attachments = attachments; renderAttachments(); }
    } finally {
      if (renderFrame) { cancelAnimationFrame(renderFrame); renderFrame = null; }
      if (assistant) { renderMarkdown(assistant.body, assistant.content); addCopyTool(assistant); }
      for (const pending of state.approvals.values()) {
        pending.actions.replaceChildren(); pending.decision.textContent = "A conversa foi encerrada. Esta ação não foi autorizada pela interface.";
      }
      state.approvals.clear(); state.abort = null; setBusy(false); streamStatus("");
      refreshSessions().catch(() => {}); refreshStatus();
      scrollBottom(); $("prompt").focus();
    }
  }

  async function stopGeneration() {
    $("stop-button").disabled = true;
    try {
      await Promise.allSettled([...state.approvals.keys()].map(id => api(`/api/approvals/${encodeURIComponent(id)}`, { method: "POST", json: { approved: false } })));
    } finally { state.abort?.abort(); $("stop-button").disabled = false; }
  }

  function renderAttachments() {
    const fragment = document.createDocumentFragment();
    state.attachments.forEach((attachment, index) => {
      const chip = node("div", "attachment"); chip.append(icon("clip"), node("span", "", attachment.name));
      const remove = button("", "", () => { state.attachments.splice(index, 1); renderAttachments(); }, "close");
      remove.setAttribute("aria-label", `Remover ${attachment.name} da próxima mensagem`); chip.append(remove); fragment.append(chip);
    });
    $("attachments").replaceChildren(fragment);
  }

  async function uploadFiles() {
    const files = [...$("file-input").files];
    if (!files.length) return;
    await action($("upload-button"), async () => {
      for (const file of files) {
        if (file.size > 2 * 1024 * 1024) { notify(`${file.name}: o limite da interface é 2 MB por arquivo de texto.`, true); continue; }
        if (/(?:^|[.\-_])(?:env|credentials?|secrets?|id_rsa|id_ed25519)(?:$|[.\-_])|\.(?:pem|key|pfx|p12)$/i.test(file.name)) { notify(`${file.name}: arquivos com credenciais não podem ser anexados.`, true); continue; }
        const content = await file.text();
        if (content.includes("\u0000")) { notify(`${file.name}: selecione um arquivo de texto, código ou documentação.`, true); continue; }
        if (content.length > 20000) { notify(`${file.name}: envie até 20.000 caracteres por anexo. Para arquivos maiores, adicione e indexe o projeto.`, true); continue; }
        if (!content.trim()) { notify(`${file.name}: o arquivo está vazio.`, true); continue; }
        const result = await api("/api/upload", { method: "POST", json: { name: file.name, content, ...(state.project ? { project_id: state.project } : {}) } });
        state.attachments.push({ name: file.name, id: result.id || result.memory_id || result.memory?.id, path: result.path, content }); renderAttachments();
        notify(`${file.name} adicionado à memória local.`);
      }
    });
    $("file-input").value = "";
  }

  function resizePrompt() {
    $("prompt").style.height = "auto";
    $("prompt").style.height = `${Math.min(240, $("prompt").scrollHeight)}px`;
    updateSend();
  }

  function closeSidebar() {
    $("sidebar").classList.remove("is-open"); $("sidebar-shade").hidden = true; $("sidebar-toggle").setAttribute("aria-expanded", "false");
  }

  document.querySelectorAll("[data-open]").forEach(el => el.addEventListener("click", () => openPanel(el.dataset.open)));
  document.querySelectorAll("[data-panel]").forEach(el => el.addEventListener("click", () => openPanel(el.dataset.panel)));
  document.querySelectorAll(".suggestion").forEach(el => el.addEventListener("click", () => {
    if (el.dataset.mode) $("mode-select").value = el.dataset.mode;
    $("mode-description").textContent = modeDescriptions[$("mode-select").value] || $("mode-select").value;
    $("prompt").value = el.dataset.prompt; resizePrompt(); $("prompt").focus();
  }));
  $("new-session").addEventListener("click", newConversation);
  $("nav-chat").addEventListener("click", () => { closeSidebar(); $("prompt").focus(); });
  $("chat-form").addEventListener("submit", sendMessage);
  $("stop-button").addEventListener("click", stopGeneration);
  $("prompt").addEventListener("input", resizePrompt);
  $("prompt").addEventListener("keydown", event => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) { event.preventDefault(); if (!state.busy) $("chat-form").requestSubmit(); }
  });
  $("model-select").addEventListener("change", () => { updateActiveProfile(); updateSend(); });
  $("profile-select").addEventListener("change", () => { state.profile = $("profile-select").value; updateActiveProfile(); });
  $("mode-select").addEventListener("change", () => { $("mode-description").textContent = modeDescriptions[$("mode-select").value] || $("mode-select").value; });
  $("project-select").addEventListener("change", () => {
    const selected = $("project-select").value;
    if (state.session && selected !== state.project) { newConversation(); notify("Nova conversa para o projeto selecionado. O histórico anterior foi preservado."); }
    state.project = selected; $("project-select").value = selected; updateProjectHint();
  });
  for (const id of ["sessions-filter-mode", "sessions-filter-agent", "sessions-filter-model", "sessions-filter-date"]) $(id).addEventListener("change", () => refreshSessions().catch(error => notify(error.message, true)));
  $("upload-button").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", uploadFiles);
  $("dialog-close").addEventListener("click", () => $("manage-dialog").close());
  $("manage-dialog").addEventListener("click", event => { if (event.target === $("manage-dialog")) { const rect = $("manage-dialog").getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) $("manage-dialog").close(); } });
  $("sidebar-toggle").addEventListener("click", () => {
    const open = $("sidebar").classList.toggle("is-open"); $("sidebar-shade").hidden = !open; $("sidebar-toggle").setAttribute("aria-expanded", String(open));
  });
  $("sidebar-shade").addEventListener("click", closeSidebar);
  $("monitor-toggle").addEventListener("click", () => {
    const mobile = window.matchMedia("(max-width:1080px)").matches;
    if (mobile) {
      document.body.classList.remove("monitor-collapsed");
      const open = document.body.classList.toggle("monitor-overlay"); $("monitor-toggle").setAttribute("aria-pressed", String(open));
    } else {
      document.body.classList.remove("monitor-overlay");
      const closed = document.body.classList.toggle("monitor-collapsed"); $("monitor-toggle").setAttribute("aria-pressed", String(!closed));
    }
  });
  $("refresh-audit").addEventListener("click", () => action($("refresh-audit"), refreshAudit));
  document.addEventListener("keydown", event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k" && !$("manage-dialog").open) { event.preventDefault(); newConversation(); }
    if (event.key === "Escape") { closeSidebar(); document.body.classList.remove("monitor-overlay"); }
  });
  $("settings-temperature").addEventListener("input", () => { $("temperature-output").value = nf.format(Number($("settings-temperature").value)); });
  $("settings-profile").addEventListener("change", updateProfileSettings);
  $("settings-form").addEventListener("submit", event => {
    event.preventDefault(); const submit = event.currentTarget.querySelector("[type=submit]");
    action(submit, async () => {
      if (state.busy) throw new Error("Aguarde a geração atual para alterar o motor local.");
      await api("/api/settings", { method: "POST", json: { model: $("settings-model").value, profile: $("settings-profile").value, coding_model: $("settings-coding-model").value, quality_mode: $("settings-quality").value, context: Number($("settings-context").value), temperature: Number($("settings-temperature").value), thinking: $("settings-thinking").checked } });
      $("model-select").value = $("settings-model").value;
      state.profile = $("settings-profile").value;
      await refreshStatus(); dialogStatus("Configurações salvas para as próximas mensagens.");
    }, "Salvando…");
  });
  $("computer-enabled").addEventListener("change", () => {
    const enabled = $("computer-enabled").checked;
    const previous = Boolean(state.computer?.enabled);
    action($("computer-enabled"), async () => {
      try {
        await api("/api/settings", { method: "POST", json: { computer_enabled: enabled } });
        await refreshComputer();
        await refreshStatus();
        dialogStatus(enabled ? "Acesso ao computador ativado. Revise as pastas autorizadas abaixo." : "Acesso ao computador desativado.");
      } catch (error) { $("computer-enabled").checked = previous; throw error; }
    });
  });
  $("computer-root-form").addEventListener("submit", event => {
    event.preventDefault();
    action($("computer-root-add"), async () => {
      const path = $("computer-root-path").value.trim();
      if (!path) throw new Error("Informe o caminho completo da pasta.");
      await api("/api/computer/roots", { method: "POST", json: { path } });
      $("computer-root-form").reset();
      await refreshComputer();
      dialogStatus("Pasta autorizada para as ferramentas do NEXUS.");
    }, "Autorizando…");
  });
  $("tor-toggle").addEventListener("click", () => action($("tor-toggle"), async () => {
    const enabled = !Boolean(state.status?.settings?.tor_enabled);
    await api("/api/settings", { method: "POST", json: { tor_enabled: enabled } });
    await refreshStatus(); updateTor(); dialogStatus(enabled ? "Tor Research ativado explicitamente. A conexão do proxy será validada antes da consulta." : "Tor Research desativado.");
  }));
  $("project-form").addEventListener("submit", event => {
    event.preventDefault(); const submit = event.currentTarget.querySelector("[type=submit]");
    action(submit, async () => {
      const result = await api("/api/projects", { method: "POST", json: { name: $("project-name").value.trim(), path: $("project-path").value.trim() } });
      $("project-form").reset(); await refreshProjects();
      if (result.id && !state.busy) { state.project = String(result.id); $("project-select").value = state.project; updateProjectHint(); }
      dialogStatus("Projeto adicionado. Use “Indexar arquivos” para disponibilizar o código na memória.");
    }, "Adicionando…");
  });
  $("memory-search-form").addEventListener("submit", event => { event.preventDefault(); searchMemory().catch(e => dialogStatus(e.message, true)); });
  $("memory-form").addEventListener("submit", event => {
    event.preventDefault(); const submit = event.currentTarget.querySelector("[type=submit]");
    action(submit, async () => {
      await api("/api/memory", { method: "POST", json: { text: $("memory-text").value.trim(), kind: $("memory-kind").value, ...(state.project ? { project_id: state.project } : {}) } });
      $("memory-query").value = $("memory-text").value.trim().slice(0, 120); $("memory-text").value = ""; await searchMemory(); dialogStatus("Memória armazenada localmente.");
    }, "Salvando…");
  });
  $("export-memory").addEventListener("click", () => action($("export-memory"), async () => {
    const data = await api("/api/memory/export");
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json;charset=utf-8" }));
    const link = node("a"); link.href = url; link.download = `nexus-memoria-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    dialogStatus("Exportação da memória preparada para download.");
  }));

  window.NEXUSApp = Object.freeze({ api, notify, refreshStatus, closeSidebar, isBusy: () => state.busy, getStatus: () => state.status });
  $("monitor-toggle").setAttribute("aria-pressed", String(!window.matchMedia("(max-width:1080px)").matches));
  updateSend();
  Promise.allSettled([refreshStatus(), refreshSessions(), refreshProjects(), refreshAudit()]).then(results => {
    const failures = results.filter(result => result.status === "rejected");
    if (failures.length) notify("Alguns dados do ambiente não puderam ser carregados. Verifique se o serviço NEXUS está em execução.", true);
  });
  setInterval(() => { if (!document.hidden) refreshStatus(); }, 10000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshStatus(); });
})();
