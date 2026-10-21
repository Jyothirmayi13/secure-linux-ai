# The auditor container: the same program the Procfile starts, for hosts that
# build images instead of running a buildpack.
#
# This image deliberately contains ONE LESS thing than the project: the modules
# under app/ are the whole program. There is no CLI, no capability tools, no
# model client and no host ledger here, so there is nothing in this container
# for a request to reach. deploy/make_auditor.py checks that this file list is
# exactly what console.py imports and nothing more.
FROM python:3.12-slim

# PaaS containers of this kind run as UID 1000; a matching user avoids
# permission fights.
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR $HOME/app

# Dependencies first, so editing a .py file does not reinstall anything.
COPY --chown=user requirements.txt $HOME/app/requirements.txt
RUN pip install --no-cache-dir -r $HOME/app/requirements.txt

COPY --chown=user app $HOME/app/app
COPY --chown=user Dockerfile README.md Procfile $HOME/app/

RUN mkdir -p $HOME/uploads

# Report mode is the only mode safe to routably bind: it reads no host state.
# $PORT is honoured when the platform sets one; 7860 otherwise.
CMD python app/console.py --serve-reports \
    --bind 0.0.0.0 --port ${PORT:-7860} --uploads $HOME/uploads
