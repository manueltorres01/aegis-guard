const GATES = Object.freeze([
  ['portableEngine', 'Motor de análisis portable validado', true],
  ['quarantineRecovery', 'Cuarentena cifrada y recuperación probada', true],
  ['signedInstaller', 'Instalador y binarios firmados', false],
  ['signedDefinitions', 'Definiciones firmadas con una clave de producción provisionada', false],
  ['nativeWindowsService', 'Servicio Windows de privilegios mínimos', false],
  ['realtimeTelemetry', 'Telemetría continua de archivos y procesos', false],
  ['performanceEvidence', 'Evidencias de rendimiento en hardware representativo', false],
  ['detectionCorpus', 'Métricas públicas de detección y falsos positivos', false],
  ['independentAudit', 'Auditoría de seguridad independiente', false],
  ['incidentSupport', 'Proceso operativo de respuesta y soporte', false]
]);

export function inspectProtectionReadiness({ signals = {}, now = new Date() } = {}) {
  const gates = GATES.map(([id, label, defaultValue]) => {
    const value = typeof signals[id] === 'boolean' ? signals[id] : defaultValue;
    return {
      id,
      label,
      status: value ? 'passed' : 'blocked',
      evidenceRequired: !value,
      note: value ? 'Evidencia disponible en esta fase.' : 'No está validado para sustituir a Defender.'
    };
  });
  const passed = gates.filter(gate => gate.status === 'passed').length;
  const blockers = gates.filter(gate => gate.status !== 'passed').map(gate => gate.id);
  const ready = blockers.length === 0;
  return {
    schemaVersion: 1,
    generatedAt: new Date(now).toISOString(),
    productMode: ready ? 'primary-endpoint-candidate' : 'complementary-scanner',
    ready,
    canReplaceDefender: ready,
    keepDefenderEnabled: !ready,
    summary: { passed, total: gates.length, blockers: blockers.length },
    blockers,
    gates,
    policy: ready
      ? 'La sustitución requiere una decisión operativa posterior y pruebas de actualización y recuperación.'
      : 'Mantén Microsoft Defender activo. Aegis todavía debe considerarse una segunda opinión.'
  };
}
