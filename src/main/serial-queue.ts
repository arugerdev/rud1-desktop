/**
 * Cola de exclusión mutua para operaciones que no toleran solaparse.
 *
 * Nació de un fallo real de conexión VPN: hay dos orígenes que llaman a
 * `vpnConnect` —el clic del usuario y el auto-reconector— y el arranque
 * tarda segundos antes de publicar el proceso activo. Solapados, ambos
 * lanzaban openvpn y el segundo pisaba al primero: uno moría con "torn down
 * before initialization" y el otro quedaba huérfano reteniendo el adaptador
 * TAP, dejando la VPN inutilizable hasta reiniciar.
 */
export function createSerialQueue() {
  let chain: Promise<unknown> = Promise.resolve();

  /**
   * Encola `fn` detrás de lo que haya pendiente. Un fallo NO rompe la cola:
   * la siguiente operación se ejecuta igual (si no, un error dejaría la VPN
   * bloqueada para siempre).
   */
  return function runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const result = chain.then(
      () => fn(),
      () => fn(),
    );
    // La cadena ignora el resultado: solo marca "ya no estoy ocupada".
    chain = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  };
}
