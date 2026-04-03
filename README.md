# CyberGuard — demo SIEM / SOAR (UI)

Interface de demonstração de um painel **SIEM + SOAR** com dados fictícios. É um front-end em **React** só para explorar o layout e interagir localmente — **não** monitoriza redes reais nem grava dados no servidor.

## Requisitos

- [Node.js](https://nodejs.org/) (LTS recomendado, v18+)

## Como executar

```bash
npm install
npm run dev
```

Abre o endereço que o Vite indicar (geralmente `http://localhost:5173`).

### Outros comandos

| Comando | Descrição |
|--------|-----------|
| `npm run build` | Gera a pasta `dist/` para produção |
| `npm run preview` | Serve o build localmente |

## Funcionalidades (demo)

- Dashboard com gráficos (Recharts)
- Vistas: mapa de ataques, alertas, SOAR, vulnerabilidades, IAM, motor de IA, arquitetura
- **Simulador** (menu *Simulador*): criar alertas à mão ou aleatórios, ajustar barras de CPU/MEM/DISK na UI, ligar/desligar o efeito scanline; *Repor alertas iniciais* volta aos dados de exemplo

## Estrutura principal

| Ficheiro / pasta | Conteúdo |
|------------------|----------|
| `CyberGuard-SIEM-SOAR.jsx` | Componente principal da aplicação |
| `src/main.jsx` | Entrada React |
| `CyberGuard-Technical-Docs.md` | Documentação narrativa da arquitetura (não implementada neste repo) |

## Licença

Uso livre para fins de aprendizado e demonstração.

## Repositório

https://github.com/kadunet0/cyberguard-siem-demo
