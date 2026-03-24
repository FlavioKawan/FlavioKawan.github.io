# 🛡️ OWASP WSTG Pentest Tracker

<p align="center">
  <img src="https://img.shields.io/badge/OWASP-WSTG%20v4.2-00ff88?style=for-the-badge&logo=owasp&logoColor=white" alt="OWASP WSTG v4.2"/>
  <img src="https://img.shields.io/badge/Tests-91+-00e5ff?style=for-the-badge" alt="91+ Tests"/>
  <img src="https://img.shields.io/badge/React-18-61dafb?style=for-the-badge&logo=react&logoColor=white" alt="React 18"/>
  <img src="https://img.shields.io/badge/Vite-5-646cff?style=for-the-badge&logo=vite&logoColor=white" alt="Vite 5"/>
</p>

<p align="center">
  Checklist interativo e guia prático para pentest web baseado no <a href="https://owasp.org/www-project-web-security-testing-guide/stable/">OWASP Web Security Testing Guide v4.2</a>.<br/>
  Todos os 91 testes da seção 4 com resumos em PT-BR, comandos reais e passo a passo para cada validação.
</p>

---

## 🎯 O que é

Um portal local para acompanhar seus pentests web seguindo a metodologia OWASP WSTG. Para cada teste você tem:

- **📖 O que é** — Resumo em português explicando o teste e por que ele importa
- **🎯 Como executar** — Comandos reais com `curl`, `nmap`, `ffuf`, `sqlmap`, `nuclei`, `Burp Suite`, etc. Tudo prático, copy-paste no terminal
- **🔧 Ferramentas** — Tools recomendadas para aquele teste específico
- **📝 Notas** — Campo para anotar seus findings e evidências
- **✅ Checklist** — Status por teste: Pendente, Parcial, Feito, N/A

## 📸 Features

- **91 testes** organizados em 12 categorias do WSTG seção 4
- **Gerenciamento de projetos** — crie um projeto por engagement, com nome e target
- **Progresso visual** — barra de progresso geral e por categoria
- **Filtros e busca** — filtre por status ou busque por ID/nome do teste
- **Persistência local** — dados salvos em `localStorage`, sobrevivem entre sessões
- **Interface hacker-themed** — dark mode com visual profissional
- **100% offline** — roda local, seus dados nunca saem do seu PC

## 🗂️ Categorias Cobertas (WSTG Seção 4)

| # | Categoria | Testes |
|---|-----------|--------|
| 4.1 | 🔍 Information Gathering | 10 |
| 4.2 | ⚙️ Configuration & Deploy Management | 11 |
| 4.3 | 🪪 Identity Management | 5 |
| 4.4 | 🔐 Authentication | 10 |
| 4.5 | 🛡️ Authorization | 4 |
| 4.6 | 🍪 Session Management | 9 |
| 4.7 | 💉 Input Validation | 19 |
| 4.8 | ⚠️ Error Handling | 2 |
| 4.9 | 🔑 Weak Cryptography | 4 |
| 4.10 | 🧠 Business Logic | 9 |
| 4.11 | 🌐 Client-side | 13 |
| 4.12 | 🔌 API Testing | 1 |

## 🚀 Instalação

```bash
git clone https://github.com/rafaelchriss/wstg-pentest-tracker.git
cd wstg-pentest-tracker
npm install
```

### Rodar em desenvolvimento

```bash
npm run dev
```

### Build para produção

```bash
npm run build
npx serve dist
```

### Rodar automaticamente ao ligar o PC (Linux/systemd)

```bash
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/wstg-tracker.service << 'EOF'
[Unit]
Description=WSTG Pentest Tracker
After=network.target

[Service]
Type=simple
WorkingDirectory=/caminho/para/wstg-pentest-tracker
ExecStart=/usr/bin/npx serve dist -l 4444
Restart=on-failure

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable wstg-tracker
systemctl --user start wstg-tracker
```

Acesse em `http://localhost:4444`

## 🛠️ Tech Stack

- **React 18** — UI reativa
- **Vite 5** — Build tool rápido
- **localStorage** — Persistência client-side
- **IBM Plex Mono + DM Sans** — Typography

## 📚 Referências

- [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/stable/)
- [OWASP WSTG GitHub](https://github.com/OWASP/wstg)
- [OWASP WSTG Checklist](https://github.com/OWASP/wstg/blob/master/checklists/checklist.md)

## 📝 Licença

MIT — Use livremente em seus pentests.
