"""Detector de anomalias (camada de IA) do validador.

Papel: *complementar* a atestação determinística, nunca substituí-la. A matriz
de decisão continua sendo a autoridade (PASS/FAIL explicável); a IA aponta
comportamento atípico que não viola nenhuma regra (ex.: carga e número de
processos fora do padrão, como um minerador, duração de ciclo anormal, jitter de chegada
que sugere atraso proposital dos vereditos) e coloca o dispositivo em SUSPECT
para revisão humana.

Modelo: Isolation Forest (scikit-learn) treinado no próprio histórico do
dispositivo após um período de aquecimento. Se o scikit-learn não estiver
disponível, cai para z-score robusto (mediana/MAD), que roda até na placa.
O treino acontece no validador, não na BeagleBone (512 MB de RAM).
"""
from __future__ import annotations

import statistics

FEATURES = ("cycle_ms", "l2_entries", "modules", "procs_total", "load1", "mem_avail_kb", "arrival_jitter_s")

try:  # opcional
    from sklearn.ensemble import IsolationForest  # type: ignore
    _HAS_SK = True
except Exception:  # pragma: no cover
    _HAS_SK = False


class AnomalyDetector:
    def __init__(self, warmup: int = 20, threshold: float = 6.0, use_sklearn: bool = True, max_hist: int = 500):
        self.warmup = warmup
        self.threshold = threshold
        self.use_sklearn = use_sklearn and _HAS_SK
        self.max_hist = max_hist
        self.hist = []
        self._model = None
        self._since_fit = 0

    @staticmethod
    def vector(tel: dict) -> list:
        return [float(tel.get(k, 0) or 0) for k in FEATURES]

    def _robust(self, v):
        worst, which = 0.0, None
        for i, name in enumerate(FEATURES):
            col = [h[i] for h in self.hist]
            med = statistics.median(col)
            mad = statistics.median(abs(x - med) for x in col) or 1e-9
            # piso relativo evita alarme por variação mínima em série quase constante
            scale = max(1.4826 * mad, 0.05 * abs(med), 1.0 if name != "load1" else 0.1)
            z = abs(v[i] - med) / scale
            if z > worst:
                worst, which = z, name
        return worst, which

    def score(self, tel: dict, ignore=()) -> dict:
        """`ignore`: sinais sem significado neste ciclo. Valem a mediana do histórico, os
        demais continuam avaliados, e o ciclo não entra no treino."""
        v = self.vector(tel)
        if self.hist:
            for name in ignore:
                i = FEATURES.index(name)
                v[i] = statistics.median(h[i] for h in self.hist)
        res = {"ready": len(self.hist) >= self.warmup, "anomaly": False, "score": 0.0,
               "feature": None, "model": "isolation_forest" if self.use_sklearn else "robust_z"}
        if res["ready"]:
            z, feat = self._robust(v)
            res["feature"] = feat
            if self.use_sklearn:
                if self._model is None or self._since_fit >= 50:
                    self._model = IsolationForest(n_estimators=100, contamination="auto",
                                                  random_state=0).fit(self.hist)
                    self._since_fit = 0
                s = float(-self._model.score_samples([v])[0])  # maior = mais anômalo (~0.3 normal, >0.6 raro)
                res["score"] = round(s, 3)
                res["z"] = round(z, 2)
                # Com pouco histórico o Isolation Forest é instável; o z-score robusto
                # garante a detecção desde o aquecimento e o IF ganha peso com os dados.
                res["anomaly"] = z > self.threshold or (len(self.hist) >= 50 and s > 0.65)
            else:
                res["score"] = round(z, 2)
                res["anomaly"] = z > self.threshold
        if not res["anomaly"] and not ignore:  # não contamina o histórico com outliers
            self.hist.append(v)
            self.hist = self.hist[-self.max_hist:]
            self._since_fit += 1
        return res
