# Model files that can run code when loaded (30 September 2026)

C4.1.2 asks that loading a model allows only formats that cannot run code while being read. The code rule
`ast.model-loaded-with-pickle` reads the loading calls; `config.model-file-can-run-code`
(`crates/sv-check/src/model_files.rs`) reads the model files in the app's folder, by their own bytes rather than by
name, since `.bin` and `.pt` hold many things. Files named `.pt`, `.pth`, `.ckpt`, `.bin`, `.pkl`, `.pickle`, or
`.joblib` count when they are a Python pickle (the `PROTO` opcode and a protocol from 2 to 5), a PyTorch file (a zip
holding `data.pkl`, which `torch.save` writes: read in PyTorch 2.14's `torch/serialization.py`, fetched from its
wheel on PyPI), or a `.joblib` file opening with one of the prefixes joblib writes for its compressors (joblib 1.5's
`compressor.py`), since `joblib.load` always unpickles.

It is only ever a finding. PyTorch 2.6 and later load with `weights_only` on unless told otherwise, which refuses the
code a pickle can carry, and the finding says so; `pickle.load` and `joblib.load` refuse nothing. A Git LFS pointer is
counted in what was looked at but not judged, since the file it stands for is not there, and a model downloaded
when the app runs is not seen. A pickle saved under another name, such as `.dat`, is not read: the extensions keep
the check from opening every file in the app. Hugging Face's own servers, where a real PyTorch file could have been
read, are refused by this session's network, so the PyTorch layout rests on PyTorch's source rather than a
downloaded file.
