"use strict";

(() => {
  const $ = id => document.getElementById(id), app = window.NEXUSApp;
  const state = { area: "models", tab: "installed", models: null, agents: null, editing: null, approval: null, job: null, polling: null, busy: false };
  const array = (value, key) => Array.isArray(value) ? value : Array.isArray(value?.[key]) ? value[key] : [];
  const text = (tag, content, className) => { const el = document.createElement(tag); if (content !== undefined) el.textContent = String(content); if (className) el.className = className; return el; };
  const bytes = value => {
    if (value == null) return "Não informado";
    const number = Number(value), unit = number >= 1073741824 ? [1073741824, "GiB"] : number >= 1048576 ? [1048576, "MiB"] : number >= 1024 ? [1024, "KiB"] : [1, "B"];
    return `${(number / unit[0]).toLocaleString("pt-BR", { maximumFractionDigits: 2 })} ${unit[1]}`;
  };
  function button(label, callback, className = "secondary-button small") {
    const el = text("button", label, className); el.type = "button";
    el.addEventListener("click", () => perform(callback)); return el;
  }
  function field(parent, id, label, kind = "input", options = {}) {
    const wrap = text("div", undefined, "library-field"), caption = text("label", label); caption.htmlFor = id;
    const input = text(kind); input.id = id;
    for (const [key, value] of Object.entries(options)) {
      if (key === "items") array(value).forEach(item => { const option = text("option", typeof item === "string" ? item : item.name); option.value = typeof item === "string" ? item : item.id; input.append(option); });
      else if (key === "checked" || key === "required" || key === "disabled") input[key] = value;
      else if (key === "value") input.value = value;
      else input.setAttribute(key, String(value));
    }
    wrap.append(caption, input); parent.append(wrap); return input;
  }
  function check(parent, id, label, checked = false) {
    const labelNode = text("label", undefined, "library-checkbox"), input = text("input"); input.id = id; input.type = "checkbox"; input.checked = checked;
    labelNode.append(input, text("span", label)); parent.append(labelNode); return input;
  }
  function note(parent, content) { parent.append(text("p", content, "field-help")); }
  function status(message, error = false) { $("library-status").textContent = message; $("library-status").classList.toggle("error", error); }
  async function perform(callback) {
    if (state.busy) return;
    state.busy = true; $("library-dialog").setAttribute("aria-busy", "true");
    try { await callback(); } catch (error) { status(error.message, true); }
    finally { state.busy = false; $("library-dialog").setAttribute("aria-busy", "false"); }
  }
  function form(parent, id, title, description, submit, callback) {
    const el = text("form", undefined, "library-form"); el.id = id;
    el.append(text("h3", title)); if (description) note(el, description);
    el.addEventListener("submit", event => { event.preventDefault(); perform(callback); });
    parent.append(el);
    if (submit) { const send = text("button", submit, "primary-button"); send.type = "submit"; el.append(send); }
    return el;
  }
  function submit(parent, label) { const el = text("button", label, "primary-button"); el.type = "submit"; parent.append(el); }
  function details(parent, title, data) { const el = text("details"), pre = text("pre", JSON.stringify(data, null, 2)); el.append(text("summary", title), pre); parent.append(el); }
  function tags(parent, values) { const el = text("div", undefined, "library-tags"); values.forEach(value => el.append(text("span", value))); parent.append(el); }
  function card(parent, title, subtitle) { const el = text("article", undefined, "library-card"); el.append(text("h4", title)); if (subtitle) el.append(text("p", subtitle)); parent.append(el); return el; }
  function actions(parent) { const el = text("div", undefined, "library-actions"); parent.append(el); return el; }
  function optionsModels(input, selected, includeEmpty = false) {
    input.replaceChildren();
    if (includeEmpty) { const option = text("option", "Herdar modelo selecionado"); option.value = ""; input.append(option); }
    array(state.models?.models).filter(model => !array(model.capabilities).includes("embedding") || array(model.capabilities).includes("completion")).forEach(model => {
      const option = text("option", model.name); option.value = model.name; input.append(option);
    });
    if (selected && ![...input.options].some(item => item.value === selected)) { const option = text("option", `${selected} · não instalado`); option.value = selected; input.append(option); }
    if (selected != null) input.value = selected;
  }
  function setTab(id) {
    state.tab = id;
    $("library-tabs").querySelectorAll("button").forEach(el => { el.classList.toggle("selected", el.dataset.tab === id); el.setAttribute("aria-selected", String(el.dataset.tab === id)); });
    $("library-content").replaceChildren(); $("library-approval").hidden = true; state.approval = null;
    if (state.area === "agents") { if (id === "editor") renderAgentEditor(state.editing); else renderAgents(); return; }
    if (id === "installed") renderModels();
    else if (id === "add") renderAdd();
    else if (id === "import") renderImport();
    else if (id === "variant") renderVariant();
    else if (id === "jobs") renderJobs();
  }
  function tabs(items) {
    $("library-tabs").replaceChildren(...items.map(([id, name]) => { const el = button(name, () => { if (id === "editor") state.editing = null; setTab(id); }, ""); el.dataset.tab = id; el.setAttribute("role", "tab"); return el; }));
  }
  async function open(area) {
    state.area = area; state.editing = null;
    $("library-title").textContent = area === "models" ? "AI Library" : "Agent Library";
    $("library-subtitle").textContent = area === "models" ? "Coleção de inteligências artificiais · Ollama local" : "Especialistas, instruções e ferramentas · modelos independentes";
    tabs(area === "models" ? [["installed", "Instalados"], ["add", "Adicionar"], ["import", "Importar GGUF"], ["variant", "Criar variante"], ["jobs", "Operações"]] : [["agents", "Especialistas"], ["editor", "Criar agente"]]);
    if (!$("library-dialog").open) $("library-dialog").showModal(); app.closeSidebar();
    $("library-content").replaceChildren(text("p", "Consultando inventário local…", "field-help")); status("Consultando dados reais do NEXUS e do Ollama…");
    await refresh(); setTab(area === "models" ? "installed" : "agents");
  }
  async function refresh() {
    if (state.area === "models") state.models = await app.api("/api/library/models");
    else {
      const result = await Promise.all([app.api("/api/library/agents"), app.api("/api/library/models")]);
      state.agents = result[0]; state.models = result[1];
    }
    const resources = state.models?.resources || {};
    $("library-resources").textContent = [`Ollama ${state.models?.connected ? "conectado" : "desconectado"}`, resources.ram_available_gb != null ? `RAM livre ${Number(resources.ram_available_gb).toLocaleString("pt-BR", { maximumFractionDigits: 1 })} GiB` : "RAM não informada", resources.disk_free_gb != null ? `Disco livre ${Number(resources.disk_free_gb).toLocaleString("pt-BR", { maximumFractionDigits: 1 })} GiB` : "Disco não informado"].join(" · ");
    status(`Inventário atualizado às ${new Date().toLocaleTimeString("pt-BR")}. Nenhum modelo foi carregado por esta consulta.`);
  }
  function renderModels() {
    const parent = $("library-content"), models = array(state.models?.models);
    parent.append(text("h3", "Modelos instalados"));
    note(parent, "Modelos são os pesos usados na inferência. Um mesmo modelo pode atender a vários agentes. Capacidade declarada não comprova qualidade em uma tarefa.");
    if (!models.length) { note(parent, state.models?.error || "Nenhum modelo encontrado. Verifique o Ollama ou adicione um modelo."); return; }
    const list = text("div", undefined, "library-model-grid"); parent.append(list);
    for (const model of models) {
      const item = card(list, model.name, `${bytes(model.size)} em disco · ${model.parameter_size || model.details?.parameter_size || "Parâmetros não informados"}`);
      tags(item, [model.default ? "Padrão" : null, model.loaded ? "Carregado" : "Descarregado", model.quantization || model.details?.quantization_level || "Quantização não informada", model.tools ? "Ferramentas declaradas" : "Sem ferramentas declaradas", model.vision ? "Imagens declaradas" : null].filter(Boolean));
      const facts = text("dl", undefined, "library-facts");
      [["Contexto declarado", model.context_length ? `${Number(model.context_length).toLocaleString("pt-BR")} tokens` : "Não informado"], ["Capacidades", array(model.capabilities).join(", ") || "Não informadas"], ["VRAM carregada", model.size_vram == null ? "Não informada" : bytes(model.size_vram)]].forEach(([name, value]) => facts.append(text("dt", name), text("dd", value)));
      item.append(facts);
      if (model.metadata_error) note(item, `Falha ao consultar metadados: ${model.metadata_error}`);
      const controls = actions(item), chat = button("Usar na conversa", () => { window.NEXUSModes.selectModel(model.name); $("library-dialog").close(); });
      const embedding = array(model.capabilities).includes("embedding") && !array(model.capabilities).includes("completion");
      chat.disabled = embedding; if (embedding) chat.title = "Modelo de embeddings: não gera respostas de chat.";
      controls.append(chat, button("Tornar padrão", () => preview({ action: "default", model: model.name })), button("Testar carregamento", () => preview({ action: "test", model: model.name })), button("Descarregar", () => preview({ action: "unload", model: model.name })), button("Remover", () => preview({ action: "delete", model: model.name }), "danger-button small"));
      details(item, "Metadados e procedência", model);
    }
  }
  function renderAdd() {
    const parent = $("library-content");
    const pull = form(parent, "library-pull-form", "Adicionar da biblioteca Ollama", "Informe o nome completo e a tag. A prévia consulta o tamanho quando disponível e verifica os recursos antes de solicitar sua aprovação.", null, () => preview({ action: "pull", model: $("library-pull-name").value.trim() }));
    field(pull, "library-pull-name", "Nome e tag", "input", { required: true, maxlength: 200, placeholder: "qwen3:4b", spellcheck: false, autocomplete: "off" }); submit(pull, "Consultar e revisar download");
    const hf = form(parent, "library-hf-form", "Referência GGUF do Hugging Face", "Use um repositório e um arquivo GGUF explícitos. A prévia identifica a revisão e o hash quando disponíveis; scripts do repositório não são executados.", null, () => preview({ action: "hf", model: $("library-hf-model").value.trim(), repo: $("library-hf-repo").value.trim(), filename: $("library-hf-file").value.trim(), revision: $("library-hf-revision").value.trim() || "main" }));
    field(hf, "library-hf-model", "Nome local no Ollama", "input", { required: true, placeholder: "meu-modelo:gguf", maxlength: 200 });
    field(hf, "library-hf-repo", "Repositório confiável · autor/repositório", "input", { required: true, placeholder: "autor/repositorio-GGUF", maxlength: 200 });
    field(hf, "library-hf-file", "Caminho exato do arquivo GGUF", "input", { required: true, placeholder: "modelo-Q4_K_M.gguf", maxlength: 300 });
    field(hf, "library-hf-revision", "Revisão ou commit", "input", { value: "main", maxlength: 100 }); submit(hf, "Verificar origem e revisar");
  }
  function renderImport() {
    const parent = $("library-content");
    const el = form(parent, "library-import-form", "Importar arquivo GGUF local", "O arquivo é enviado somente ao NEXUS local para validar o formato e calcular SHA-256. Criar o modelo no Ollama é uma etapa separada, com aprovação.", null, async () => {
      const file = $("library-gguf-file").files[0]; if (!file) throw new Error("Selecione um arquivo GGUF.");
      status(`Enviando ${file.name} ao armazenamento local (${bytes(file.size)}). O navegador não informa progresso deste envio.`);
      const hash = $("library-gguf-hash").value.trim();
      const upload = await app.api(`/api/library/models/uploads?name=${encodeURIComponent(file.name)}${hash ? `&sha256=${encodeURIComponent(hash)}` : ""}`, { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: file });
      $("library-import-result").replaceChildren(text("p", `GGUF validado · SHA-256 ${upload.sha256}`, "field-help")); details($("library-import-result"), "Metadados do GGUF", upload);
      await preview({ action: "import", model: $("library-gguf-model").value.trim(), upload_id: upload.id, context: Number($("library-gguf-context").value), temperature: Number($("library-gguf-temperature").value) });
    });
    field(el, "library-gguf-file", "Arquivo GGUF", "input", { type: "file", accept: ".gguf", required: true });
    field(el, "library-gguf-model", "Nome local e tag", "input", { required: true, placeholder: "meu-modelo:local", maxlength: 200 });
    field(el, "library-gguf-hash", "SHA-256 esperado · opcional", "input", { maxlength: 64, pattern: "[a-fA-F0-9]{64}", placeholder: "Hash publicado por uma fonte confiável" });
    field(el, "library-gguf-context", "Contexto inicial", "input", { type: "number", min: 512, max: 32768, value: 4096, required: true });
    field(el, "library-gguf-temperature", "Temperatura", "input", { type: "number", min: 0, max: 2, step: 0.1, value: 0.3, required: true });
    submit(el, "Validar arquivo e revisar criação"); const result = text("div"); result.id = "library-import-result"; parent.append(result);
    const uploads = array(state.models?.uploads);
    if (uploads.length) {
      parent.append(text("h3", "Cópias GGUF armazenadas localmente")); note(parent, "Estas cópias são independentes das tags do Ollama. Remover uma cópia libera espaço local e preserva o modelo já criado no Ollama.");
      uploads.forEach(upload => {
        const item = card(parent, upload.name, `${bytes(upload.size)} · SHA-256 ${upload.sha256}`);
        actions(item).append(button("Remover cópia local", async () => {
          if (!confirm(`Remover a cópia local “${upload.name}”? O modelo no Ollama será preservado.`)) return;
          await app.api(`/api/library/models/uploads/${encodeURIComponent(upload.id)}`, { method: "DELETE" }); await refresh(); setTab("import"); status("Cópia GGUF local removida.");
        }, "danger-button small"));
      });
    }
  }
  function renderVariant() {
    const parent = $("library-content");
    const el = form(parent, "library-variant-form", "Criar uma variante personalizada", "Uma variante configura instruções e parâmetros de um modelo base. Ela não treina novos pesos. A prévia mostra o Modelfile equivalente.", null, () => preview({ action: "variant", model: $("library-variant-name").value.trim(), base: $("library-variant-base").value, system: $("library-variant-system").value, context: Number($("library-variant-context").value), temperature: Number($("library-variant-temperature").value) }));
    field(el, "library-variant-name", "Nome da variante e tag", "input", { required: true, maxlength: 200, placeholder: "nexus-dev:local" });
    const base = field(el, "library-variant-base", "Modelo base instalado", "select", { required: true }); optionsModels(base, $("model-select").value);
    field(el, "library-variant-system", "Instruções de sistema", "textarea", { rows: 6, maxlength: 16000, placeholder: "Responda com precisão técnica e use ferramentas para verificar resultados." });
    field(el, "library-variant-context", "Contexto", "input", { type: "number", min: 512, max: 32768, value: 4096, required: true });
    field(el, "library-variant-temperature", "Temperatura", "input", { type: "number", min: 0, max: 2, step: 0.1, value: 0.3, required: true }); submit(el, "Revisar variante");
  }
  async function preview(payload) {
    if (app.isBusy()) throw new Error("Aguarde a geração atual antes de administrar modelos.");
    status("Validando a operação e consultando informações disponíveis…");
    const result = await app.api("/api/library/models/preview", { method: "POST", json: payload }); state.approval = result;
    const parent = $("library-approval"); parent.replaceChildren(); parent.hidden = false;
    const data = result.preview || {};
    parent.append(text("h3", "Revise antes de aprovar"), text("p", `${data.action || payload.action} · ${data.model || payload.model}`));
    note(parent, data.estimated_download_bytes != null ? `Download estimado: ${bytes(data.estimated_download_bytes)}` : "Tamanho do download não informado pela fonte. Nenhum progresso será estimado artificialmente.");
    array(data.warnings).forEach(warning => parent.append(text("p", typeof warning === "string" ? warning : JSON.stringify(warning), "library-warning")));
    details(parent, "Prévia completa, recursos e procedência", data);
    if (data.modelfile) { const pre = text("pre", data.modelfile); parent.append(pre); }
    if (payload.action === "delete") field(parent, "library-delete-confirmation", "Digite o nome completo do modelo para confirmar a remoção", "input", { autocomplete: "off", spellcheck: false });
    const controls = actions(parent);
    controls.append(button("Aprovar somente esta operação", async () => {
      const confirmation = $("library-delete-confirmation")?.value;
      if (payload.action === "delete" && confirmation !== payload.model) throw new Error("Digite o nome completo do modelo exibido na prévia.");
      const submitted = await app.api("/api/library/models/jobs", { method: "POST", json: { approval_id: result.approval_id, approved: true, ...(confirmation !== undefined ? { confirmation } : {}) } });
      state.approval = null; parent.hidden = true; state.job = submitted.job || { id: submitted.job_id }; setTab("jobs"); await pollJob(submitted.job_id || submitted.job?.id);
    }, "primary-button"), button("Cancelar aprovação", async () => { await app.api("/api/library/models/jobs", { method: "POST", json: { approval_id: result.approval_id, approved: false } }); parent.hidden = true; state.approval = null; status("Operação não autorizada."); }));
    note(parent, `Esta prévia expira em ${Number(result.expires_in || 300)} segundos. A aprovação vale apenas para os argumentos exibidos.`);
    parent.scrollIntoView({ behavior: "smooth", block: "nearest" }); status("Prévia pronta. Confira os recursos, a origem e a operação.");
  }
  function jobCard(parent, job) {
    const jobLabel = { queued: "aguardando", running: "em execução", completed: "concluída", failed: "falhou", cancelled: "cancelada" };
    const item = card(parent, `${job.action || "Operação"} · ${job.model || ""}`, `Estado: ${jobLabel[job.status] || job.status || "consultando"}`);
    const progress = job.progress || {};
    if (progress.status) note(item, progress.status);
    if (Number(progress.total) > 0 && Number(progress.completed) >= 0) {
      const meter = text("progress"); meter.max = Number(progress.total); meter.value = Math.min(Number(progress.completed), Number(progress.total)); meter.setAttribute("aria-label", "Bytes confirmados pelo Ollama"); item.append(meter);
      note(item, `${bytes(progress.completed)} / ${bytes(progress.total)} · ${(100 * meter.value / meter.max).toLocaleString("pt-BR", { maximumFractionDigits: 1 })}% desta camada`);
    } else note(item, "Sem percentual informado pela operação.");
    if (job.error) item.append(text("p", typeof job.error === "string" ? job.error : JSON.stringify(job.error), "library-warning"));
    if (["queued", "running"].includes(job.status)) actions(item).append(button("Solicitar cancelamento", async () => { const result = await app.api(`/api/library/models/jobs/${encodeURIComponent(job.id)}/cancel`, { method: "POST" }); state.job = result.job || result; status("Cancelamento solicitado. A confirmação depende da operação; o Ollama pode conservar camadas já recebidas."); await pollJob(job.id); }));
    details(item, "Eventos reais e resultado", job); return item;
  }
  async function pollJob(id) {
    if (!id) return;
    if (state.polling) clearTimeout(state.polling);
    const job = await app.api(`/api/library/models/jobs/${encodeURIComponent(id)}`); state.job = job.job || job;
    if (state.area === "models" && state.tab === "jobs") renderJobs(false);
    if (["queued", "running"].includes(state.job.status)) {
      status("Operação em andamento. Os eventos abaixo vêm do backend e do Ollama.");
      state.polling = setTimeout(() => perform(() => pollJob(id)), 1100);
    } else {
      status(`Operação ${state.job.status || "encerrada"}${state.job.error ? `: ${typeof state.job.error === "string" ? state.job.error : JSON.stringify(state.job.error)}` : "."}`, state.job.status === "failed");
      await app.refreshStatus();
      if (state.area === "models") {
        state.models = await app.api("/api/library/models");
        if (state.tab === "installed") { $("library-content").replaceChildren(); renderModels(); }
      }
    }
  }
  async function renderJobs(load = true) {
    const parent = $("library-content"); parent.replaceChildren(text("h3", "Operações e progresso"));
    note(parent, "O percentual representa bytes confirmados da camada atual quando o Ollama informa total e recebido. Cancelar pode preservar arquivos parciais em cache.");
    if (state.job) jobCard(parent, state.job);
    if (!load) return;
    try {
      const result = await app.api("/api/library/models/jobs");
      if (state.area !== "models" || state.tab !== "jobs") return;
      array(result, "jobs").filter(job => job.id !== state.job?.id).slice(0, 30).forEach(job => jobCard(parent, job));
      if (!state.job && !array(result, "jobs").length) note(parent, "Nenhuma operação registrada nesta execução do servidor.");
    } catch (error) { status(error.message, true); }
  }
  function exportAgent(agent) {
    const link = text("a"); link.href = `/api/library/agents/${encodeURIComponent(agent.id)}/export`; link.download = `nexus-agente-${agent.id}.json`; link.className = "secondary-button small"; link.textContent = "Exportar JSON"; return link;
  }
  function renderAgents() {
    const parent = $("library-content"), agents = array(state.agents, "agents");
    parent.append(text("h3", "Especialistas reutilizáveis")); note(parent, "Agentes definem instruções, memória e ferramentas. As permissões são limitadas pelas autorizações do computador e pelos escopos do Security Center.");
    const importForm = form(parent, "library-agent-import-form", "Importar especialista", "Selecione um JSON exportado pelo NEXUS. A configuração será validada antes de ser cadastrada.", null, async () => {
      const file = $("library-agent-import-file").files[0]; if (!file) throw new Error("Selecione um arquivo JSON.");
      if (file.size > 262144) throw new Error("A configuração deve ter no máximo 256 KiB.");
      let payload; try { payload = JSON.parse(await file.text()); } catch (_) { throw new Error("O arquivo não contém JSON válido."); }
      const agent = await app.api("/api/library/agents/import", { method: "POST", json: payload }); await refresh(); await window.NEXUSModes.refreshAgents(); state.editing = agent; setTab("editor"); status("Agente importado e validado. Revise a configuração antes de usá-lo.");
    });
    field(importForm, "library-agent-import-file", "Arquivo de configuração", "input", { type: "file", accept: ".json,application/json", required: true }); submit(importForm, "Validar e importar");
    const list = text("div", undefined, "library-agent-grid"); parent.append(list);
    for (const agent of agents) {
      const item = card(list, `${agent.icon || "◇"} ${agent.name}`, agent.description || "Sem descrição.");
      tags(item, [agent.builtin ? "Integrado · somente leitura" : "Personalizado", agent.workspace_mode || "chat", agent.default_model || "Modelo da conversa"]);
      note(item, `${array(agent.tool_allowlist).length} ferramentas permitidas · memória ${agent.memory?.scope || "do projeto"}`);
      const controls = actions(item);
      controls.append(button("Usar agente", async () => { await window.NEXUSModes.refreshAgents(); window.NEXUSModes.selectAgent(agent.id); $("library-dialog").close(); }), button(agent.builtin ? "Ver configuração" : "Editar", () => { state.editing = agent; setTab("editor"); }), button("Duplicar", async () => { const duplicate = await app.api(`/api/library/agents/${encodeURIComponent(agent.id)}/duplicate`, { method: "POST", json: {} }); await refresh(); await window.NEXUSModes.refreshAgents(); state.editing = duplicate; setTab("editor"); status("Cópia personalizada criada. Edite as instruções e permissões."); }), exportAgent(agent));
      if (!agent.builtin) controls.append(button("Excluir", async () => {
        if (!confirm(`Excluir o agente “${agent.name}”? As conversas e os modelos são preservados.`)) return;
        await app.api(`/api/library/agents/${encodeURIComponent(agent.id)}?revision=${encodeURIComponent(agent.revision)}`, { method: "DELETE" }); await refresh(); await window.NEXUSModes.refreshAgents(); setTab("agents"); status("Agente excluído.");
      }, "danger-button small"));
    }
  }
  function renderAgentEditor(agent) {
    const parent = $("library-content"), builtin = Boolean(agent?.builtin), permissions = agent?.permissions || {}, memory = agent?.memory || {}, search = agent?.search || {};
    const el = form(parent, "library-agent-form", builtin ? "Configuração do especialista integrado" : agent ? "Editar especialista" : "Criar especialista", builtin ? "Os agentes integrados são somente leitura. Duplique um agente para personalizar suas instruções." : "A configuração define um limite de capacidades. Ela não concede pastas, acesso a redes nem autorizações operacionais adicionais.", null, async () => {
      const payload = { name: $("library-agent-name").value.trim(), description: $("library-agent-description").value.trim(), icon: $("library-agent-icon").value.trim(), workspace_mode: $("library-agent-mode").value, prompt: $("library-agent-prompt").value, default_model: $("library-agent-model").value, tool_allowlist: [...el.querySelectorAll('input[data-agent-tool]:checked')].map(input => input.dataset.agentTool), memory: { read: $("library-agent-memory-read").checked, write: $("library-agent-memory-write").checked, scope: $("library-agent-memory-scope").value }, permissions: { file_read: $("library-agent-file-read").checked, file_write: $("library-agent-file-write").checked, terminal: $("library-agent-terminal").checked, external_network: $("library-agent-network").checked }, search: { provider: $("library-agent-search-provider").value, max_results: Number($("library-agent-search-limit").value), tor_enabled: $("library-agent-search-tor").checked } };
      const result = await app.api(agent ? `/api/library/agents/${encodeURIComponent(agent.id)}` : "/api/library/agents", { method: agent ? "PUT" : "POST", json: { ...payload, ...(agent ? { revision: agent.revision } : {}) } });
      await refresh(); await window.NEXUSModes.refreshAgents(); state.editing = result; setTab("editor"); status("Especialista salvo e validado. As permissões globais continuam sendo aplicadas.");
    });
    field(el, "library-agent-name", "Nome", "input", { value: agent?.name || "", required: true, maxlength: 120 });
    field(el, "library-agent-description", "Descrição", "textarea", { value: agent?.description || "", rows: 2, maxlength: 2000 });
    field(el, "library-agent-icon", "Ícone · texto ou emoji", "input", { value: agent?.icon || "◇", maxlength: 24 });
    field(el, "library-agent-mode", "Modo associado", "select", { items: array(state.agents?.modes), value: agent?.workspace_mode || "developer" });
    field(el, "library-agent-prompt", "Instruções de sistema", "textarea", { value: agent?.prompt || "", rows: 7, required: true, maxlength: 24000 });
    const model = field(el, "library-agent-model", "Modelo padrão sugerido", "select"); optionsModels(model, agent?.default_model || "", true);
    el.append(text("h4", "Ferramentas permitidas"));
    const toolset = text("div", undefined, "library-tool-checks"); el.append(toolset);
    array(state.agents?.tools).forEach((tool, index) => {
      const input = check(toolset, `library-agent-tool-${index}`, `${tool.name}${tool.available === false ? " · indisponível" : ""}`, array(agent?.tool_allowlist).includes(tool.name)); input.dataset.agentTool = tool.name;
      input.parentElement.title = tool.reason || tool.description || tool.name;
    });
    el.append(text("h4", "Memória"));
    check(el, "library-agent-memory-read", "Consultar memória do contexto autorizado", memory.read ?? true); check(el, "library-agent-memory-write", "Permitir sugestões de escrita na memória", memory.write ?? false);
    field(el, "library-agent-memory-scope", "Escopo da memória", "select", { items: [{ id: "project", name: "Projeto selecionado" }, { id: "conversation", name: "Somente esta conversa" }], value: memory.scope || "project" });
    el.append(text("h4", "Permissões operacionais · teto redutivo"));
    [["file-read", "Leitura de arquivos autorizados", permissions.file_read ?? true], ["file-write", "Escrita mediante controles operacionais", permissions.file_write ?? false], ["terminal", "Terminal mediante aprovação", permissions.terminal ?? false], ["network", "Acesso externo pelas ferramentas autorizadas", permissions.external_network ?? false]].forEach(([id, label, checked]) => check(el, `library-agent-${id}`, label, checked));
    el.append(text("h4", "Pesquisa"));
    field(el, "library-agent-search-provider", "Provedor preferido", "select", { items: [{ id: "auto", name: "Automático" }, { id: "duckduckgo", name: "DuckDuckGo" }, { id: "searxng", name: "SearXNG configurado" }], value: search.provider || "auto" });
    field(el, "library-agent-search-limit", "Máximo de resultados", "input", { type: "number", min: 1, max: 10, value: search.max_results || 5, required: true });
    check(el, "library-agent-search-tor", "Permitir Tor se o módulo global estiver explicitamente ativado", search.tor_enabled || false);
    if (builtin) {
      el.querySelectorAll("input,select,textarea").forEach(input => { input.disabled = true; });
      actions(el).append(button("Duplicar e personalizar", async () => { const result = await app.api(`/api/library/agents/${encodeURIComponent(agent.id)}/duplicate`, { method: "POST", json: {} }); await refresh(); await window.NEXUSModes.refreshAgents(); state.editing = result; setTab("editor"); }));
    } else submit(el, agent ? "Salvar alterações do agente" : "Validar e criar agente");
    if (agent) actions(el).append(exportAgent(agent));
  }
  const dialog = text("dialog", undefined, "library-dialog"); dialog.id = "library-dialog"; dialog.setAttribute("aria-labelledby", "library-title");
  const header = text("header", undefined, "library-header"), heading = text("div"); heading.append(text("span", "NEXUS · COLEÇÃO LOCAL", "eyebrow"));
  const title = text("h2", "AI Library"); title.id = "library-title"; const subtitle = text("p"); subtitle.id = "library-subtitle"; heading.append(title, subtitle);
  const close = button("×", () => dialog.close(), "icon-button library-close"); close.id = "library-close"; close.setAttribute("aria-label", "Fechar biblioteca"); header.append(heading, close);
  const nav = text("nav", undefined, "library-tabs"); nav.id = "library-tabs"; nav.setAttribute("aria-label", "Áreas da biblioteca"); nav.setAttribute("role", "tablist");
  const body = text("div", undefined, "library-body"), top = text("div", undefined, "library-topline"), resources = text("span"); resources.id = "library-resources";
  const refreshButton = button("Atualizar inventário", async () => { await refresh(); setTab(state.tab); }); refreshButton.id = "library-refresh"; top.append(resources, refreshButton);
  const feedback = text("p", undefined, "library-status"); feedback.id = "library-status"; feedback.setAttribute("role", "status");
  const content = text("div"); content.id = "library-content"; const approval = text("section", undefined, "library-approval"); approval.id = "library-approval"; approval.hidden = true;
  body.append(top, feedback, content, approval); dialog.append(header, nav, body); document.body.append(dialog);
  dialog.addEventListener("click", event => { if (event.target === dialog) { const rect = dialog.getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) dialog.close(); } });
  $("nav-ai-library").addEventListener("click", () => perform(() => open("models")));
  $("nav-agent-library").addEventListener("click", () => perform(() => open("agents")));
})();
