import type { MigrationInterface, QueryRunner } from 'typeorm';

/** Specific transactional migration; no TypeORM schema synchronization. */
export class AccountDeletion1794100000000 implements MigrationInterface {
  name = 'AccountDeletion1794100000000';
  constructor(private readonly backupRole?: string) {}

  async up(runner: QueryRunner): Promise<void> {
    let backupRole =
      this.backupRole ?? process.env.ACCOUNT_DELETION_BACKUP_ROLE;
    if (!backupRole && process.env.DATABASE_URL_BACKUP) {
      try {
        backupRole = decodeURIComponent(
          new URL(process.env.DATABASE_URL_BACKUP).username,
        );
      } catch {
        throw new Error('ACCOUNT_DELETION_BACKUP_ROLE_REQUIRED');
      }
    }
    if (!backupRole || !/^[a-z_][a-z\d_-]{0,62}$/i.test(backupRole))
      throw new Error('ACCOUNT_DELETION_BACKUP_ROLE_REQUIRED');
    const backups = (await runner.query(
      "SELECT rolname FROM pg_roles WHERE rolname=$1 AND has_table_privilege(oid,'core.users','SELECT') AND NOT has_table_privilege(oid,'core.users','UPDATE')",
      [backupRole],
    )) as { rolname: string }[];
    if (backups.length !== 1)
      throw new Error('ACCOUNT_DELETION_BACKUP_READER_ROLE_REQUIRED');
    const rows = (await runner.query(
      "SELECT to_regclass('core.users')::text AS present",
    )) as { present: string | null }[];
    if (rows[0]?.present !== 'core.users')
      throw new Error('ACCOUNT_DELETION_USERS_SCHEMA_REQUIRED');
    await runner.query(`
      CREATE TABLE core.account_deletion_accounts (
        user_id integer PRIMARY KEY REFERENCES core.users(id_usuario) ON DELETE RESTRICT,
        account_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
        state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','deleting','deleted')),
        identity_email varchar(100),
        confirmed_at timestamptz, completed_at timestamptz
      );
      INSERT INTO core.account_deletion_accounts(user_id) SELECT id_usuario FROM core.users;
      UPDATE core.account_deletion_accounts a SET identity_email=u.email FROM core.users u
        WHERE u.id_usuario=a.user_id AND u.email_verified=1;
      CREATE TABLE core.account_deletion_requests (
        request_id uuid PRIMARY KEY, user_id integer NOT NULL REFERENCES core.account_deletion_accounts(user_id),
        account_id uuid NOT NULL, session_id uuid NOT NULL,
        status text NOT NULL CHECK(status IN ('received','identity_verified','deletion_confirmed','in_progress','completed','requires_attention','error')),
        reason text, email_hash text, code_hash text, code_expires_at timestamptz,
        attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
        authorization_hash text, authorization_expires_at timestamptz,
        receipt_hash text NOT NULL, receipt_expires_at timestamptz NOT NULL,
        requested_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
        retained_categories jsonb NOT NULL DEFAULT '[]',
        notification_status text NOT NULL DEFAULT 'not_required' CHECK(notification_status IN ('pending','sent','not_required','unavailable'))
      );
      CREATE INDEX account_deletion_requests_owner ON core.account_deletion_requests(user_id,requested_at DESC);
      CREATE UNIQUE INDEX account_deletion_one_open ON core.account_deletion_requests(user_id)
        WHERE status IN ('received','identity_verified','deletion_confirmed','in_progress','requires_attention');
      CREATE TABLE core.account_deletion_retention (
        request_id uuid PRIMARY KEY REFERENCES core.account_deletion_requests(request_id),
        basis text NOT NULL CHECK(length(btrim(basis))>0), retain_until timestamptz NOT NULL,
        categories jsonb NOT NULL, identifiers_expired_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT clock_timestamp()
      );
      CREATE TABLE core.account_deletion_notifications (
        request_id uuid PRIMARY KEY REFERENCES core.account_deletion_requests(request_id),
        encrypted_recipient text, attempts integer NOT NULL DEFAULT 0,
        expires_at timestamptz NOT NULL, sent_at timestamptz
      );
      REVOKE ALL ON core.account_deletion_accounts,core.account_deletion_requests,
        core.account_deletion_retention,core.account_deletion_notifications FROM PUBLIC;
      DO $acl$ DECLARE target record; BEGIN
        FOR target IN SELECT rolname FROM pg_roles WHERE rolname<>current_user AND NOT rolsuper LOOP
          EXECUTE format('REVOKE ALL ON core.account_deletion_accounts,core.account_deletion_requests,core.account_deletion_retention,core.account_deletion_notifications FROM %I',target.rolname);
        END LOOP;
      END $acl$;
      CREATE FUNCTION core.invalidate_account_deletion_challenges(owner_id integer) RETURNS void
        LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
        UPDATE core.account_deletion_requests SET status='error',reason='identity_changed',code_hash=NULL,
          authorization_hash=NULL,updated_at=clock_timestamp() WHERE user_id=owner_id AND status IN ('received','identity_verified');
      $fn$;
      REVOKE ALL ON FUNCTION core.invalidate_account_deletion_challenges(integer) FROM PUBLIC;

      CREATE FUNCTION core.account_deletion_identity_immutable() RETURNS trigger LANGUAGE plpgsql
        SET search_path=pg_catalog AS $fn$
      BEGIN
        IF NEW.user_id<>OLD.user_id OR NEW.account_id<>OLD.account_id
          OR (OLD.state='deleted' AND NEW.state<>'deleted') THEN
          RAISE EXCEPTION 'Deleted identity cannot be reused' USING ERRCODE='42501';
        END IF;
        IF OLD.identity_email IS NOT NULL AND NEW.identity_email IS DISTINCT FROM OLD.identity_email
          AND NOT (NEW.identity_email IS NULL AND NEW.state='deleted' AND EXISTS(
            SELECT 1 FROM core.account_deletion_requests r WHERE r.user_id=OLD.user_id
              AND r.request_id::text=current_setting('sportcenter.account_deletion',true)
              AND r.status IN ('in_progress','completed')
          )) THEN RAISE EXCEPTION 'Verified identity is immutable' USING ERRCODE='42501'; END IF;
        RETURN NEW;
      END $fn$;
      REVOKE ALL ON FUNCTION core.account_deletion_identity_immutable() FROM PUBLIC;
      CREATE TRIGGER account_deletion_identity_immutable BEFORE UPDATE ON core.account_deletion_accounts
        FOR EACH ROW EXECUTE FUNCTION core.account_deletion_identity_immutable();

      DO $scope$ BEGIN
        IF to_regprocedure('core.reject_review_moderation_history_change()') IS NOT NULL THEN
          EXECUTE $definition$CREATE OR REPLACE FUNCTION core.reject_review_moderation_history_change() RETURNS trigger
            LANGUAGE plpgsql SET search_path=pg_catalog AS $body$
          BEGIN
            IF TG_OP='UPDATE' AND NEW.motivo='Contenido eliminado por su titular'
              AND (to_jsonb(NEW)-'motivo')=(to_jsonb(OLD)-'motivo') AND EXISTS(
                SELECT 1 FROM core.account_deletion_requests request
                JOIN core.account_deletion_accounts account ON account.user_id=request.user_id
                JOIN core.reviews review ON review.id_usuario=request.user_id
                WHERE request.request_id::text=current_setting('sportcenter.account_deletion',true)
                  AND request.status IN ('in_progress','requires_attention','completed') AND account.state IN ('deleting','deleted')
                  AND review.id_review=OLD.id_review
              ) THEN RETURN NEW; END IF;
            RAISE EXCEPTION 'Review moderation history is append-only' USING ERRCODE='42501';
          END $body$ $definition$;
        END IF;
      END $scope$;

      CREATE FUNCTION core.account_deletion_register_user() RETURNS trigger LANGUAGE plpgsql
        SECURITY DEFINER SET search_path=pg_catalog AS $fn$
      BEGIN INSERT INTO core.account_deletion_accounts(user_id,identity_email) VALUES(NEW.id_usuario,
        CASE WHEN NEW.email_verified=1 THEN NEW.email ELSE NULL END); RETURN NEW; END $fn$;
      REVOKE ALL ON FUNCTION core.account_deletion_register_user() FROM PUBLIC;
      CREATE TRIGGER account_deletion_register_user AFTER INSERT ON core.users FOR EACH ROW
        EXECUTE FUNCTION core.account_deletion_register_user();

      CREATE FUNCTION core.account_deletion_protect_user() RETURNS trigger LANGUAGE plpgsql
        SECURITY DEFINER SET search_path=pg_catalog AS $fn$
      DECLARE lifecycle text; permit text;
      BEGIN
        PERFORM pg_advisory_xact_lock(193589,OLD.id_usuario);
        SELECT state INTO lifecycle FROM core.account_deletion_accounts WHERE user_id=OLD.id_usuario;
        permit := current_setting('sportcenter.account_deletion',true);
        IF lifecycle IS DISTINCT FROM 'active' AND NOT EXISTS(
          SELECT 1 FROM core.account_deletion_requests WHERE user_id=OLD.id_usuario
            AND request_id::text=permit AND status IN ('deletion_confirmed','in_progress','requires_attention','error','completed')
        ) THEN RAISE EXCEPTION 'Account unavailable' USING ERRCODE='42501'; END IF;
        IF TG_OP='UPDATE' AND OLD.email IS DISTINCT FROM NEW.email AND lifecycle='active' THEN
          NEW.email_verified:=0;
          UPDATE core.account_deletion_requests SET status='error',reason='identity_changed',code_hash=NULL,
            authorization_hash=NULL,updated_at=clock_timestamp()
            WHERE user_id=OLD.id_usuario AND status IN ('received','identity_verified');
        END IF;
        IF TG_OP='UPDATE' AND NEW.email_verified=1 AND lifecycle='active' THEN
          UPDATE core.account_deletion_accounts SET identity_email=NEW.email
            WHERE user_id=OLD.id_usuario AND identity_email IS NULL;
        END IF;
        IF TG_OP='DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
      END $fn$;
      REVOKE ALL ON FUNCTION core.account_deletion_protect_user() FROM PUBLIC;
      CREATE TRIGGER account_deletion_protect_user BEFORE UPDATE OR DELETE ON core.users FOR EACH ROW
        EXECUTE FUNCTION core.account_deletion_protect_user();

      CREATE FUNCTION core.account_deletion_protect_owner() RETURNS trigger LANGUAGE plpgsql
        SECURITY DEFINER SET search_path=pg_catalog AS $fn$
      DECLARE owner_id integer; lifecycle text;
      BEGIN
        owner_id:=(to_jsonb(NEW)->>TG_ARGV[0])::integer;
        IF owner_id IS NULL THEN RETURN NEW; END IF;
        PERFORM pg_advisory_xact_lock(193589,owner_id);
        SELECT state INTO lifecycle FROM core.account_deletion_accounts WHERE user_id=owner_id;
        IF lifecycle IS DISTINCT FROM 'active' AND NOT EXISTS(
          SELECT 1 FROM core.account_deletion_requests WHERE user_id=owner_id
            AND request_id::text=current_setting('sportcenter.account_deletion',true)
            AND status IN ('deletion_confirmed','in_progress','requires_attention','error','completed')
        ) THEN RAISE EXCEPTION 'Account unavailable' USING ERRCODE='42501'; END IF;
        RETURN NEW;
      END $fn$;
      REVOKE ALL ON FUNCTION core.account_deletion_protect_owner() FROM PUBLIC;
      DO $block$ DECLARE target record; BEGIN
        FOR target IN SELECT table_schema,table_name FROM information_schema.columns
          WHERE table_schema IN ('core','public') AND column_name='id_usuario' AND table_name<>'users'
        LOOP
          EXECUTE format('CREATE TRIGGER account_deletion_protect_owner BEFORE %s ON %I.%I FOR EACH ROW EXECUTE FUNCTION core.account_deletion_protect_owner(''id_usuario'')',
            CASE WHEN target.table_schema='core' AND target.table_name IN ('user_sessions','carts','direcciones','user_payment_methods','reviews','alexa_codes','alexa_account_links') THEN 'INSERT OR UPDATE' ELSE 'INSERT' END,
            target.table_schema,target.table_name);
        END LOOP;
      END $block$;
      DO $block$ DECLARE target record; BEGIN
        FOR target IN SELECT DISTINCT roles.rolname FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
          CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) acl
          JOIN pg_roles roles ON roles.oid=acl.grantee
          WHERE namespace.nspname='core' AND relation.relname='users' AND acl.grantee<>0 AND acl.privilege_type='UPDATE'
        LOOP
          EXECUTE format('GRANT SELECT(user_id,state) ON core.account_deletion_accounts TO %I',target.rolname);
          EXECUTE format('GRANT EXECUTE ON FUNCTION core.invalidate_account_deletion_challenges(integer) TO %I',target.rolname);
        END LOOP;
      END $block$;
    `);
    await runner.query(
      `GRANT SELECT ON core.account_deletion_accounts,core.account_deletion_requests,core.account_deletion_retention,core.account_deletion_notifications TO "${backupRole}"`,
    );
  }

  async down(runner: QueryRunner): Promise<void> {
    const rows = (await runner.query(
      'SELECT count(*)::text AS count FROM core.account_deletion_requests',
    )) as { count: string }[];
    if (rows[0]?.count !== '0')
      throw new Error('ACCOUNT_DELETION_HISTORY_CANNOT_BE_REVERSED');
    await runner.query(`
      DO $block$ DECLARE target record; BEGIN
        FOR target IN SELECT n.nspname,c.relname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace WHERE t.tgname='account_deletion_protect_owner'
        LOOP EXECUTE format('DROP TRIGGER account_deletion_protect_owner ON %I.%I',target.nspname,target.relname); END LOOP;
      END $block$;
      DROP TRIGGER account_deletion_protect_user ON core.users;
      DROP TRIGGER account_deletion_register_user ON core.users;
      DROP TRIGGER account_deletion_identity_immutable ON core.account_deletion_accounts;
      DROP FUNCTION core.account_deletion_identity_immutable();
      DROP FUNCTION core.invalidate_account_deletion_challenges(integer);
      DO $scope$ BEGIN
        IF to_regprocedure('core.reject_review_moderation_history_change()') IS NOT NULL THEN
          EXECUTE $definition$CREATE OR REPLACE FUNCTION core.reject_review_moderation_history_change() RETURNS trigger
            LANGUAGE plpgsql SET search_path=pg_catalog AS $body$
          BEGIN RAISE EXCEPTION 'Review moderation history is append-only' USING ERRCODE='42501'; END $body$ $definition$;
        END IF;
      END $scope$;
      DROP FUNCTION core.account_deletion_protect_owner();
      DROP FUNCTION core.account_deletion_protect_user();
      DROP FUNCTION core.account_deletion_register_user();
      DROP TABLE core.account_deletion_notifications,core.account_deletion_retention,core.account_deletion_requests,core.account_deletion_accounts;
    `);
  }
}
