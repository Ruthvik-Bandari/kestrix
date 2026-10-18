# Sourced by Slurm jobs that need the pinned Elasticsearch. Starts Elasticsearch 8.19.3 (from
# hpc/fetch_engine.sh) for this job only, on 127.0.0.1 with a job-scoped data directory, and stops
# it and deletes its data when the job exits. Sets ES_URL.
# The engine has security disabled on a shared compute node, so it may hold only public benchmark data.
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1
# The cluster sets http(s)_proxy without NO_PROXY; keep loopback traffic off the proxy.
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
# Gives the bundled S3 repository plugin a region so it does not probe cloud metadata at startup.
export AWS_REGION=us-east-1
DATA="${AEGIS_DATA:-/scratch/$USER/aegis-sec/data}"  # override for a separate run, e.g. the sensitivity check
ES_HOME="/scratch/$USER/aegis-sec/engine/elasticsearch-8.19.3"
PORT=$((19200 + SLURM_JOB_ID % 700))
ES_URL="http://127.0.0.1:$PORT"
RUN=$(mktemp -d "/scratch/$USER/aegis-sec/engine/run-$SLURM_JOB_ID-XXXX")
cleanup() {
  [ -f "$RUN/pid" ] && kill "$(cat "$RUN/pid")" 2>/dev/null && sleep 5
  rm -rf "$RUN"
}
trap cleanup EXIT
ES_JAVA_OPTS="-Xms4g -Xmx4g" "$ES_HOME/bin/elasticsearch" -d -p "$RUN/pid" \
  -E path.data="$RUN/data" -E path.logs="$RUN/logs" \
  -E discovery.type=single-node -E network.host=127.0.0.1 -E http.port="$PORT" \
  -E xpack.security.enabled=false -E xpack.ml.enabled=false -E cluster.name="aegis-$SLURM_JOB_ID"
for _ in $(seq 1 90); do
  curl -fs --noproxy '*' "$ES_URL/_cluster/health?wait_for_status=yellow&timeout=1s" >/dev/null && break
  sleep 2
done
curl -fs --noproxy '*' "$ES_URL/" | grep '"number"'
