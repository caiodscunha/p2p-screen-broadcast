const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const electronPath = require('electron');

const env = { ...process.env };
const args = ['.'];

// O binário chrome-sandbox precisa ser root:root + modo 4755 (setuid) pro
// Electron usar o sandbox normal do Chromium no Linux — sem isso ele aborta
// com "FATAL setuid_sandbox_host". Uma instalação via npm nunca deixa isso
// configurado (não tem como setar setuid sem privilégio), e rodar sem
// sandbox (a alternativa) se mostrou instável nesta máquina: crash de glibc
// em tpp.c/__pthread_tpp_change_priority e até flicker de tela em eventos
// do compositor (ex: Alt+Tab) alheios ao app. Por isso corrige de verdade
// em vez de só contornar: tenta ajustar a permissão sozinho via pkexec (o
// equivalente gráfico do sudo, com diálogo de senha — não precisa de
// terminal) toda vez que detectar que ainda não está certo (ex: depois de
// um novo `npm install`, que reinstala o Electron do zero). Só cai pro modo
// sem sandbox se isso não for possível.
function sandboxIsFixed(sandboxPath) {
  try {
    const stat = fs.statSync(sandboxPath);
    const mode = stat.mode & 0o7777;
    return stat.uid === 0 && mode === 0o4755;
  } catch {
    return false;
  }
}

function tryFixSandboxWithPkexec(sandboxPath) {
  const hasPkexec = spawnSync('which', ['pkexec']).status === 0;
  if (!hasPkexec) return false;

  const result = spawnSync(
    'pkexec',
    ['sh', '-c', `chown root:root '${sandboxPath}' && chmod 4755 '${sandboxPath}'`],
    { stdio: 'inherit' }
  );
  return result.status === 0 && sandboxIsFixed(sandboxPath);
}

if (process.platform === 'linux') {
  const sandboxPath = path.join(path.dirname(electronPath), 'chrome-sandbox');
  let sandboxOk = sandboxIsFixed(sandboxPath);

  if (!sandboxOk) {
    console.log('[sinal-p2p] Ajustando a permissão do sandbox do Electron (vai pedir sua senha)...');
    sandboxOk = tryFixSandboxWithPkexec(sandboxPath);
  }

  // O processo de GPU usa uma camada de sandbox separada (baseada em
  // namespace sem privilégio), diferente da que o chrome-sandbox acima
  // corrige. Distros recentes (Ubuntu 23.10+) restringem essa criação de
  // namespace via AppArmor por padrão para binários sem perfil registrado
  // (kernel.apparmor_restrict_unprivileged_userns=1) — o Electron instalado
  // via npm não tem esse perfil, então essa camada falha e derruba o app
  // ("GPU process isn't usable. Goodbye.") mesmo com o sandbox principal
  // certo. --disable-gpu-sandbox tira só essa camada específica, mantendo
  // aceleração de hardware e o sandbox principal (setuid) intactos.
  args.push('--disable-gpu-sandbox');

  if (!sandboxOk) {
    console.warn(
      '[sinal-p2p] Não deu pra ajustar o sandbox automaticamente; rodando ' +
        'sem ele (pode ser instável). Pra corrigir na mão:\n' +
        `  sudo chown root:root "${sandboxPath}" && sudo chmod 4755 "${sandboxPath}"`
    );

    // Precisa ser variável de ambiente do processo ANTES do Electron subir
    // — setar via app.commandLine.appendSwitch('no-sandbox') dentro do
    // main.js roda tarde demais, porque o check do sandbox acontece antes
    // do JS do app carregar.
    env.ELECTRON_DISABLE_SANDBOX = '1';

    // O cliente PipeWire embutido no Chromium carrega por padrão o módulo
    // libpipewire-module-rt, que pede prioridade real-time via RTKit — em
    // certas versões de glibc isso bate num bug conhecido (assert em
    // tpp.c/__pthread_tpp_change_priority) que derruba o processo inteiro.
    // Só testamos isso rodando sem sandbox (não dá pra confirmar se o crash
    // também ocorreria com o sandbox principal ligado), então por precaução
    // só liga esse contorno junto com o resto do modo degradado.
    env.DISABLE_RTKIT = '1';
  }
}

const child = spawn(electronPath, args, { stdio: 'inherit', env });
child.on('exit', (code) => process.exit(code ?? 0));
