# Quantas
Deception Technology Project

## tpot:
Codice collegato al framework [T-Pot](https://github.com/telekom-security/tpotce)

### Pre-Requisiti
- python3

### Configurazione
Per il corretto funzionamento del codice collegato al famework [T-Pot](https://github.com/telekom-security/tpotce) occorre eseguire il seguente comando:
```bash
  ./tpot_configuration
```
### Sandbox Scripts
Analisi dati Cowrie:
```bash
  ./sandbox_analysis cowrie
```
Analisi dati Dionaea:
```bash
  ./sandbox_analysis dionaea
```
Generazione report Cowrie:
```bash
  python3 sandbox_scripts/cowrie_report_generator.py cowrie
```
Generazione report Dionaea:
```bash
  python3 sandbox_scripts/dionaea_report_generator.py dionaea
```

## Autori
- [@9carlo6](https://www.github.com/9carlo6)
