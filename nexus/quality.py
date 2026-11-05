"""Revisão adicional com evidências locais; não promete correção garantida."""
from .context import compact_json
from .profiles import role_instructions


def _excerpt(text, limit):
    if len(text) <= limit:
        return text
    marker = "\n[trecho intermediário omitido por limite de contexto]\n"
    room = max(0, limit - len(marker))
    first = (room + 1) // 2
    last = room // 2
    return text[:first] + marker + (text[-last:] if last else "")

def choose_model(requested, default_model, coding_model, agent, mode, available):
    preferred = requested or default_model
    # O especialista é consultor: as chamadas nativas de ferramentas falharam
    # nos testes reais. Preserva o principal para operações com ferramentas.
    if preferred == coding_model and coding_model and mode != "CHAT":
        return default_model
    return preferred

def review_messages(question, draft, evidence, context):
    budget = max(2400, (context - 1200) * 2)
    # Cada resultado recente recebe espaço: um arquivo grande não pode apagar
    # a saída do teste ou uma falha que veio depois. O registro continua JSON válido.
    recent = evidence[-4:]
    facts_budget = max(800, budget // 3)
    per_result = max(100, (facts_budget - 2 - 2 * max(0, len(recent) - 1)) // max(1, len(recent)))
    facts = "[" + ", ".join(compact_json(row, per_result) for row in recent) + "]"
    question_budget = min(3000, max(800, budget // 3))
    question_part = _excerpt(question, question_budget)
    draft_budget = max(800, budget - len(facts) - len(question_part))
    return [
        {"role": "system", "content": role_instructions("reviewer")},
        {"role": "user", "content": "Pergunta:\n" + question_part + "\nProposta:\n" + _excerpt(draft, draft_budget) + "\nEvidências reais de ferramentas (podem estar incompletas):\n" + facts},
    ]
