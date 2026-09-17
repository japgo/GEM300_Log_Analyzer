#!/bin/bash
set -e
project_dir="$(cd "$(dirname "$0")" && pwd)/dotnet"
cd "$project_dir"
if [ -n "${GEM300_DOTNET:-}" ]; then
  sdk="$GEM300_DOTNET"
elif command -v dotnet >/dev/null 2>&1 && dotnet --list-sdks | /usr/bin/grep -q '^10\.'; then
  sdk="$(command -v dotnet)"
elif [ -x /private/tmp/gem300-dotnet/dotnet ]; then
  sdk=/private/tmp/gem300-dotnet/dotnet
else
  echo '.NET 10 SDK가 필요합니다. https://dotnet.microsoft.com/download/dotnet/10.0'
  read -r -p 'Enter를 누르면 닫힙니다. '
  exit 1
fi
export DOTNET_CLI_HOME="${DOTNET_CLI_HOME:-$project_dir/.cli}"
if [ -z "${NUGET_PACKAGES:-}" ] && [ -d /private/tmp/gem300-nuget ]; then
  export NUGET_PACKAGES=/private/tmp/gem300-nuget
fi
exec "$sdk" run --project Gem300.Desktop -c Release -- "$@"
