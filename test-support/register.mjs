// Registra il loader che permette di importare worker.js in Node (vedi
// loader.mjs). Si usa con: node --import ./test-support/register.mjs --test test/worker.test.mjs
import { register } from "node:module";

register("./loader.mjs", import.meta.url);
