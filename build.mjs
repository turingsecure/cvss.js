import dts from "bun-plugin-dts";

const output = await Bun.build({
  entrypoints: ["index.ts"],
  outdir: "./dist",
  target: "browser",
  minify: false,
  plugins: [dts()],
  define: {
    global: "window",
  },
});

if (!output.success) {
  for (const log of output.logs) {
    console.error(log);
  }
}

const output2 = await Bun.build({
  entrypoints: ["index.ts"],
  outdir: "./dist_node",
  target: "node",
  minify: false,
  plugins: [dts()],
  define: {
    window: "undefined",
  },
});

if (!output2.success) {
  for (const log of output2.logs) {
    console.error(log);
  }
}
