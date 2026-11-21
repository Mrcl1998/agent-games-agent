#!/bin/bash
set -a
. ./.env
set +a
exec node server.mjs
