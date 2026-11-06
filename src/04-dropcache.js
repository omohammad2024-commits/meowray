
// dropcache helper: a tiny hand-assembled static x86-64 ELF (186 bytes) that
// asks the kernel to drop ONE file from the page cache:
//   fd = open(argv[1], O_RDONLY); posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
//   exit_group(0 on success, 1 on failure)
// Assembly (offsets verified by unit test executing it):
//   cmp qword [rsp],2 ; jb fail ; mov rdi,[rsp+16] ; xor esi,esi ;
//   mov eax,2 ; syscall ; test rax,rax ; js fail ; mov edi,eax ;
//   xor esi,esi ; xor edx,edx ; mov r10d,4 ; mov eax,221 ; syscall ;
//   test rax,rax ; jnz fail ; xor edi,edi ; jmp done ; fail: mov edi,1 ;
//   done: mov eax,231 ; syscall
// Written for MeowRay (not copied from any other project); its SHA-256 is
// pinned in VERSIONS.dropcacheSha256 and re-verified on every write.
const DROPCACHE_HEX =
  "7f454c4602010100000000000000000002003e0001000000780040000000000040000000000000000000000000000000" +
  "000000004000380001000000000000000100000005000000000000000000000000004000000000000000400000000000" +
  "ba00000000000000ba00000000000000001000000000000048833c2402722f488b7c241031f6b8020000000f054885c0" +
  "781c89c731f631d241ba04000000b8dd0000000f054885c0750431ffeb05bf01000000b8e70000000f05";

function dropcacheBuffer() { return Buffer.from(DROPCACHE_HEX, "hex"); }

function ensureDropcache() {
  const file = P.dropcacheFile;
  let ok = false;
  try { ok = fs.existsSync(file) && sha256Buffer(fs.readFileSync(file)) === VERSIONS.dropcacheSha256; } catch (e) {}
  if (!ok) {
    fs.rmSync(file, { force: true });
    fs.writeFileSync(file, dropcacheBuffer());
  }
  // A restored state keeps the right bytes but may lose the exec bit
  // (bundle extraction does not restore modes for helper binaries).
  try { fs.chmodSync(file, 0o755); } catch (e) {}
  return file;
}

let dropcacheWarned = false;
function dropFileCache(file) {
  if (!file || !fs.existsSync(file)) return;
  try {
    const r = spawnSync(ensureDropcache(), [file], { timeout: 4000, stdio: "ignore" });
    if ((r.error || r.status !== 0) && !dropcacheWarned) {
      dropcacheWarned = true;
      log("page-cache drop skipped (harmless, slightly higher RAM): " + (r.error ? r.error.message : "exit " + r.status));
    }
  } catch (e) {
    if (!dropcacheWarned) { dropcacheWarned = true; log("page-cache drop skipped: " + e.message); }
  }
}
