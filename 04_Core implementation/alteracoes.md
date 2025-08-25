# Alterações implementadas na semana 4

Comparando com a semana 2, as seguintes novidades foram implementadas:

- Adição dos módulos:
  - `analysis/incident_analyzer.py`: análise de incidentes.
  - `detection/`: deteção de ameaças, incluindo:
    - `log_detector.py`
    - `network_detector.py`
    - `threat_detector.py`
  - `playbooks/`: automação de respostas, incluindo:
    - `block_bruteforce.yml`
    - `block_exfiltration.yml`
    - `investigate.yml`
    - `policy_violation.yml`
    - `quarantine.yml`
  - `prediction/threat_predictor.py`: previsão de ameaças.
  - `response/`: resposta automatizada, incluindo:
    - `automated_responder.py`
    - `orchestrator.py`
    - `actions/` (firewall, isolation, notify)
- Expansão da estrutura do projeto para suportar análise, deteção, previsão e resposta a incidentes.
- Manutenção dos ficheiros base da semana 2.

Estas alterações representam uma evolução significativa, tornando o sistema mais completo e funcional.
