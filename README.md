## ANGR Note

**angr** is a great binary analysis framework that has saved me a lot of time during CTFs. Initially, **angr** gave me a really hard-core impression, but ***"practice makes perfect"***. When exploring it deeper, I am even more motivated and create this repo to document my journey. 

Many thanks to these two fantastic tutorials helping me a lot in my first steps into **angr**.
- [angr_ctf](https://github.com/jakespringer/angr_ctf)
- [angr Tutorials (Youtube playlist)](https://www.youtube.com/playlist?list=PL-nPhof8EyrGKytps3g582KNiJyIAOtBG)

Also check out my [angr_helper](./angr_helper.md), which may help you get familiar with **angr** instructions.

## Installation

Here is the script to setup **angr**.

```shell
#!/bin/bash

# Download and install the latest Miniconda
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh -b -p $HOME/miniconda3
source $HOME/miniconda3/etc/profile.d/conda.sh

# Create and activate a new Conda environment with Python 3.12
conda create -n angr python=3.12 -y
conda activate angr

# Install angr and dependencies via pip
pip install --upgrade pip
pip install angr

# Install IPython for an interactive shell
conda install -c conda-forge ipython -y

# Verify installations
python -c "import angr; print(f'angr {angr.__version__} installed successfully')"
python -c "import IPython; print(f'IPython {IPython.__version__} installed successfully')"

# Clean up
rm Miniconda3-latest-Linux-x86_64.sh
```

## Running ANGR

To run an `angr` script, activate the environment and execute your script with `python`:

```shell
conda activate angr
python <script_name>.py
```

## Additional Resources

- [angr Documentation: Examples](https://docs.angr.io/examples)
- [angr GitHub: More Examples](https://github.com/angr/angr-doc/blob/master/docs/more-examples.md)
- [ANGR API Reference](https://docs.angr.io/en/latest/api.html)
- [angr_ctf](https://github.com/jakespringer/angr_ctf)
- [angr YouTube Playlist](https://www.youtube.com/playlist?list=PL-nPhof8EyrGKytps3g582KNiJyIAOtBG)
- [PwnDiary: HappyTree Example](https://pwndiary.com/0ctf-2020-happytree)
- [Defeating Code Obfuscation with Angr](https://napongizero.github.io/blog/Defeating-Code-Obfuscation-with-Angr)