# Evading Detection On The Blockchain

Smart contracts are core tools for scammers and protocol attackers to steal digital assets.

As there is now more scrutiny by both users and security tools, scammers are answering with deception.

There is a long history of malware detection and evasion growing side-by-side in the binary and web spaces.

It is very likely the blockchain will follow the same path: this repository will detail the latest developments.

## Report

### Exports

The current version of the report is available in PDF in the [report subfolder](../report).

It has 3 different variants based on the theme: dark / Forta / light.

The figures are also exported separately in the [figures subfolder](../figures).

### Compiling with LaTeX

From the root directory of the repository:

```shell
cd sources/
lualatex --output-directory ../report/ dark.tex
lualatex --output-directory ../figures/ figures/light.tex
```

The report can be built with `pdflatex`, `xetex` or `lualatex`.

The Forta theme requires either `xetex` or `lualatex` since it is using specific fonts.

## Malware Samples

Some techniques are illustrated with [POC / real-world examples](../samples).

The goal is to build a labeled dataset of malicious code.
