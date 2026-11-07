ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements-dev.lock ./
RUN python -m pip install --index-url https://pypi.org/simple --timeout 120 --retries 3 --require-hashes --only-binary=:all: -r requirements-dev.lock
COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts/wheel_metadata.py ./scripts/wheel_metadata.py
RUN python -m build --wheel --no-isolation

FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY --from=build /build/dist/ /wheels/
RUN python -m pip install --no-index --no-deps /wheels/*.whl && python -m pip uninstall --yes pip
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["k8s-triage"]
