#!/usr/bin/env bash
# Tags: replica

# CREATE AS SELECT for Replicated database is broken (https://github.com/ClickHouse/ClickHouse/issues/35408).
# This should be fixed and this test should eventually be deleted.

CURDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../shell_config.sh
. "$CURDIR"/../shell_config.sh

${CLICKHOUSE_CLIENT} --allow_experimental_database_replicated=1 --query "CREATE DATABASE ${CLICKHOUSE_DATABASE}_db engine = Replicated('/clickhouse/databases/${CLICKHOUSE_TEST_ZOOKEEPER_PREFIX}/${CLICKHOUSE_DATABASE}_db', '{shard}', '{replica}')"
${CLICKHOUSE_CLIENT} --query "CREATE TABLE ${CLICKHOUSE_DATABASE}_db.test (id UInt64) ENGINE = MergeTree() ORDER BY id AS SELECT 1" |& grep -cm1 "SUPPORT_IS_DISABLED"
${CLICKHOUSE_CLIENT} --query "DROP DATABASE ${CLICKHOUSE_DATABASE}_db"
