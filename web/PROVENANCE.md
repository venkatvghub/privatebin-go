# Provenance of the copied front-end files

Everything under `css/`, `js/`, `img/` and `i18n/`, plus `manifest.json`, `browserconfig.xml` and
`robots.txt`, was copied unchanged from the PrivateBin 2.1.0 release
(https://github.com/PrivateBin/PrivateBin/releases/tag/2.1.0). The files are not edited here, so they
carry no extra header comments; instead `PRIVATEBIN_FILES.sha256` records the SHA-256 of every one, and
`TestCopiedFilesMatchRecordedSums` (run by `go test`, locally and in CI) fails if any file differs. The
same test covers `vendor/CHECKSUMS.txt` (Swagger UI). To upgrade, copy a newer PrivateBin release and
regenerate the sums in the same commit.

The JavaScript libraries inside, as named by their own headers:

| File | Library | Upstream | How it relates to upstream |
|---|---|---|---|
| `js/privatebin.js`, `js/legacy.js`, `js/zlib.js`, `js/dark-mode-switch.js` | PrivateBin | https://github.com/PrivateBin/PrivateBin | the files themselves |
| `js/zlib-1.3.2.js`, `js/zlib-1.3.2.wasm` | zlib 1.3.2 compiled to WebAssembly | https://zlib.net | built by PrivateBin |
| `js/bootstrap-5.3.8.js` | Bootstrap v5.3.8 (header says so) | https://github.com/twbs/bootstrap | PrivateBin's build; not byte-identical to the npm `dist` files |
| `js/kjua-0.10.0.js` | kjua v0.10.0 | https://github.com/lrsjng/kjua | byte-identical to `kjua@0.10.0/dist/kjua.min.js` on npm |
| `js/showdown-2.1.0.js` | Showdown 2.1.0 | https://github.com/showdownjs/showdown | PrivateBin's build; not byte-identical to the npm `dist` file |
| `js/purify-3.4.17.js` | DOMPurify 3.4.17 | https://github.com/cure53/DOMPurify | PrivateBin's build; not byte-identical to the npm `dist` file |
| `js/base-x-5.0.1.js` | base-x 5.0.1 | https://github.com/cryptocoinjs/base-x | PrivateBin's adaptation |
| `js/prettify.js` | google-code-prettify | https://github.com/googlearchive/code-prettify | PrivateBin's bundled copy (carries no version header) |

"PrivateBin's build" means the file is the one PrivateBin ships in its tagged release, which is what the
checksums pin; it is not claimed to be the upstream project's own artifact.
