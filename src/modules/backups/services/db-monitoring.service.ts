/* eslint-disable */
import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';

@Injectable()
export class DbMonitoringService {
  constructor(
    @InjectDataSource('adminConnection')
    private readonly dataSource: DataSource,
  ) {}

  async getActiveConnections() {
    return this.dataSource.query(`
      SELECT
        pid,
        usename,
        datname,
        application_name,
        client_addr,
        state,
        query,
        backend_start,
        xact_start,
        query_start
      FROM pg_stat_activity
      WHERE datname = current_database()
      ORDER BY state = 'active' DESC, pid;
    `);
  }

  async getDetailedLocks() {
    return this.dataSource.query(`
      SELECT 
        l.pid,
        a.usename,
        a.datname,
        l.locktype,
        l.relation::regclass AS tabla,
        l.mode,
        l.granted
      FROM pg_locks l
      LEFT JOIN pg_stat_activity a ON l.pid = a.pid
      WHERE a.datname = current_database()
      ORDER BY l.pid;
    `);
  }

  async getBlockingLocks() {
    return this.dataSource.query(`
      SELECT
        blocked.pid AS blocked_pid,
        blocked.usename AS blocked_user,
        blocking.pid AS blocking_pid,
        blocking.usename AS blocking_user,
        blocked.query AS blocked_query,
        blocking.query AS blocking_query,
        blocked.wait_event_type,
        blocked.wait_event
      FROM pg_locks bl
      JOIN pg_stat_activity blocked ON blocked.pid = bl.pid
      JOIN pg_locks kl 
        ON kl.locktype = bl.locktype
        AND kl.database IS NOT DISTINCT FROM bl.database
        AND kl.relation IS NOT DISTINCT FROM bl.relation
        AND kl.page IS NOT DISTINCT FROM bl.page
        AND kl.tuple IS NOT DISTINCT FROM bl.tuple
        AND kl.pid != bl.pid
      JOIN pg_stat_activity blocking ON blocking.pid = kl.pid
      WHERE NOT bl.granted;
    `);
  }

  async getLongRunningQueries() {
    return this.dataSource.query(`
      SELECT
        pid,
        usename,
        query,
        state,
        NOW() - query_start AS duration
      FROM pg_stat_activity
      WHERE state != 'idle'
        AND query_start IS NOT NULL
      ORDER BY duration DESC;
    `);
  }

  async getMostQueriedTables() {
    return this.dataSource.query(`
      SELECT
        schemaname,
        relname as tablename,
        seq_scan as total_escaneos_secuenciales,
        seq_tup_read as filas_leidas_secuencial,
        idx_scan as total_escaneos_indice,
        idx_tup_fetch as filas_leidas_indice,
        n_tup_ins as inserts,
        n_tup_upd as updates,
        n_tup_del as deletes,
        n_live_tup as filas_vivas,
        n_dead_tup as filas_muertas,
        (seq_scan + idx_scan) as total_consultas,
        CASE 
          WHEN (seq_scan + idx_scan) > 0 
          THEN ROUND((idx_scan::numeric / (seq_scan + idx_scan) * 100), 2)
          ELSE 0 
        END as porcentaje_uso_indices
      FROM pg_stat_user_tables
      WHERE schemaname = 'core'
      ORDER BY total_consultas DESC
      LIMIT 10;
    `);
  }

  async getTableSizes() {
    return this.dataSource.query(`
      SELECT
        schemaname,
        relname as tablename,
        pg_size_pretty(pg_total_relation_size(relid)) as total_size_humano,
        pg_total_relation_size(relid) as total_size_bytes,
        pg_size_pretty(pg_relation_size(relid)) as tabla_size_humano,
        pg_size_pretty(pg_indexes_size(relid)) as indices_size_humano,
        pg_indexes_size(relid) as indices_size_bytes,
        n_live_tup as filas_aproximadas
      FROM pg_stat_user_tables
      WHERE schemaname = 'core'
      ORDER BY total_size_bytes DESC;
    `);
  }

  async getIndexInfo() {
    return this.dataSource.query(`
      SELECT
        i.schemaname,
        i.relname as tablename,
        i.indexrelname as indexname,
        pg_get_indexdef(i.indexrelid) as indexdef,
        pg_size_pretty(pg_relation_size(i.indexrelid)) as index_size_humano,
        pg_relation_size(i.indexrelid) as index_size_bytes,
        i.idx_scan as veces_usado,
        i.idx_tup_read as filas_leidas,
        i.idx_tup_fetch as filas_obtenidas
      FROM pg_stat_user_indexes i
      WHERE i.schemaname = 'core'
      ORDER BY i.idx_scan DESC, index_size_bytes DESC;
    `);
  }

  async getTableLockStats() {
    return this.dataSource.query(`
      SELECT
        relation::regclass AS tabla,
        mode,
        COUNT(*) as cantidad_locks,
        COUNT(CASE WHEN granted THEN 1 END) as concedidos,
        COUNT(CASE WHEN NOT granted THEN 1 END) as esperando
      FROM pg_locks
      WHERE locktype = 'relation'
        AND relation::regclass::text LIKE 'core.%'
      GROUP BY relation, mode
      ORDER BY tabla, cantidad_locks DESC;
    `);
  }

  async getTableScanStats() {
    return this.dataSource.query(`
      SELECT
        schemaname,
        relname as tablename,
        seq_scan,
        idx_scan,
        (seq_scan + idx_scan) as total_accesos,
        CASE 
          WHEN (seq_scan + idx_scan) > 0 
          THEN ROUND((seq_scan::numeric / (seq_scan + idx_scan) * 100), 2)
          ELSE 0 
        END as porcentaje_escaneo_secuencial
      FROM pg_stat_user_tables
      WHERE schemaname = 'core'
        AND (seq_scan + idx_scan) > 0
      ORDER BY porcentaje_escaneo_secuencial DESC
      LIMIT 10;
    `);
  }
}
