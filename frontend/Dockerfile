# Phase 14: containerized SOC dashboard, serving the real Vite build (Phase
# 10) through nginx -- not a dev server. Multi-stage: `build` compiles the
# app with the exact toolchain `npm run build` already uses locally
# (tsc -b && vite build, see package.json), then `nginx` serves only the
# resulting static `dist/` output -- the build stage's node_modules, source
# TypeScript, and dev tooling never ship in the final image.
#
# Not build-verified in this project's development sandbox: this
# environment's network policy blocks every container registry it was
# tried against (Docker Hub, ghcr.io, mcr.microsoft.com, gcr.io all
# returned 403 Forbidden, confirmed by actually trying to pull
# python:3.12-slim for backend/Dockerfile, which failed the same way) --
# there is no base image this sandbox can pull, for any Dockerfile, so
# nothing in this repo's Docker setup has ever been build-tested here, this
# one included. Written and reviewed against the real `npm run build`
# output and the real `src/api/client.ts` default URL, not run end-to-end;
# see docker-compose.yml's top comment and README.md's "Docker" section for
# the full disclosure and what verifying this for real requires.

FROM node:22-alpine AS build
WORKDIR /app

# Dependency layer cached separately from source so a source-only change
# doesn't repeat the (slower) npm install.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Vite inlines `import.meta.env.VITE_*` at build time (there is no runtime
# env step for a static build), so the backend URL the compiled JS calls
# has to be set here, not in the final nginx stage. Defaults to exactly
# `src/api/client.ts`'s own hardcoded fallback (`http://localhost:8000`) --
# docker-compose.yml overrides this build arg only when `API_PORT` is
# customized away from its own default, so the two stay consistent without
# this Dockerfile needing to know compose's variable names.
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
