FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

# The base image ships a yarn apt source with no signing key, which breaks
# `apt-get update` for every feature layered on top (e.g. docker-in-docker).
# This project doesn't need yarn, so just drop the source.
RUN rm -f /etc/apt/sources.list.d/yarn.list
