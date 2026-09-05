# healthD

Painel local de saúde da máquina: journal do systemd, serviços, CPU/RAM/disco, gargalos de hardware e frota na LAN.

Sem dependências extras: só Python 3 (e `journalctl` / `systemctl` no Linux).

## O que o painel mostra

- Faróis de saúde (sistema, crítico, erros, avisos)
- Erros mais frequentes, percentual e aplicação de origem
- Impacto estimado no sistema e potencial de melhoria se forem corrigidos
- Filtros por texto, severidade e aplicação
- Gráficos de linha do tempo, distribuição e unidades systemd
- Aba **Sistema**: CPU, load average, RAM, PSI (pressão de memória/I/O), disco (read/write), rede (in/out) em tempo real, com top 10 ofensores por recurso e top 5 do load
- Aba **Disco**: mapa em anéis (sunburst) dos diretórios que mais ocupam espaço, com inspeção e abertura da pasta
- Correlação journal ↔ métricas: o drawer mostra CPU, RAM, I/O e PSI no horário da última ocorrência; o farol **Journal** na aba Sistema acende quando o log está barulhento
- Aba **Serviços**: unidades systemd running/stopped/failed, `systemctl --failed`, journal por unidade (`journalctl -u`), IA nos failed e Disable só se a unidade **não** for essencial
- Aba **Máquina**: inventário de hardware (CPU, RAM, swap, discos, GPU, bateria, térmico), uso observado, gargalos locais e **IA** com sugestões de software (swappiness, governor, serviços, disco) e de hardware (RAM, SSD, CPU, bateria)
- **Hosts da rede**: cadastre outras máquinas (`ip:porta`) com um nome; o seletor no topo troca o painel sem abrir outro endereço
- OOM: processos mortos por falta de memória, lidos do journal
- Diff entre boots: o que surgiu neste boot e não estava no anterior
- **IA Tips**: para cada problema agrupado, envia o contexto à Groq (plano gratuito) e devolve causa provável, passos e comandos

O percentual de melhoria é uma **heurística** (frequência × severidade × criticidade da unidade × palavras como OOM, I/O, timeout). Não é medição real de performance.

## IA Tips (plano gratuito)

O painel usa a API da [Groq](https://console.groq.com/keys) no free tier (Llama, sem cartão). Também aceita Gemini e OpenRouter.

1. Crie uma chave em [console.groq.com/keys](https://console.groq.com/keys)
2. No dashboard, clique em **Configurar IA** e cole a chave  
   ou rode `python3 healthd.py --ai-provider groq --ai-key gsk_...`

A chave fica em `~/.config/healthd/ai.json` (ainda lê a pasta antiga `~/.config/journalctl-obs/` se existir). Nada é enviado até você clicar em **IA Tips**.

## Uso

```bash
python3 healthd.py
```

Abra [http://127.0.0.1:9999](http://127.0.0.1:9999).

```bash
python3 healthd.py --help
python3 healthd.py --user          # só o journal do usuário
python3 healthd.py --demo          # dados sintéticos
python3 healthd.py --port 9999
```

Se o journal do sistema exigir permissão, entre no grupo `systemd-journal` ou rode com um usuário que já leia `/var/log/journal`.

## Várias máquinas na rede

Em cada computador da LAN:

```bash
python3 healthd.py --host 0.0.0.0 --port 9999
```

No painel que você usa no dia a dia, clique em **Hosts**, dê um nome (ex.: `servidor-lab`) e o endereço `192.168.1.20:9999`. O seletor acima do título lista os hosts; dá para filtrar pelo nome. A lista fica em `~/.config/healthd/hosts.json`.

Não há autenticação: exponha só na rede em que você confia (firewall / VPN).

## English

healthD is a local Linux health dashboard (journal, systemd, live metrics, disk, hardware, LAN hosts). Run `python3 healthd.py` and open localhost:9999.

## Licença

MIT
