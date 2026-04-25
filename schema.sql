-- ============================================================================
-- EDGE Hack 2026 — Supabase Schema (with simple credential auth)
-- Run this entire file in: Supabase Dashboard -> SQL Editor -> New query
-- Safe to re-run: idempotent throughout (IF NOT EXISTS / ON CONFLICT).
-- Re-running also removes the old bundled sample teams if they exist.
-- ============================================================================

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;


-- 1) Judges (fixed roster — five industry experts) ---------------------------
create table if not exists judges (
  slug      text primary key,
  name      text not null,
  org       text not null,
  expertise text
);

insert into judges (slug, name, org, expertise) values
  ('lin-yuan',          'Lin Yuan',     'OKX',        'Cyber Security'),
  ('kamal-mann',        'Kamal Mann',   'Apple',      'Industrial Automation'),
  ('sasi-ingua',        'Sasi Ingua',   'YouTube',    'Video Processing'),
  ('himant',            'Himant',       'Salesforce', 'Enterprise Cloud'),
  ('manish-shah',       'Manish Shah',  'eBay',       'E-commerce')
on conflict (slug) do update set
  name = excluded.name,
  org = excluded.org,
  expertise = excluded.expertise;


-- 2) Teams -------------------------------------------------------------------
create table if not exists teams (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  project_title text not null,
  track         text,
  table_number  text,
  members       text,
  notes         text,
  created_at    timestamptz default now()
);

-- No default teams are inserted. Add teams from the admin console or directly
-- in Supabase; the app reads teams from this table.
delete from teams
where (name, project_title) in (values
  ('SynapseGrid', 'Adaptive AI for distributed power-grid load balancing'),
  ('Chainlight',  'Cross-chain identity attestation without doxxing'),
  ('EchoLens',    'Real-time multilingual captioning for accessibility'),
  ('NovaForge',   'Browser-native LLM fine-tuning with WebGPU'),
  ('PulseRoute',  'Edge-deployed last-mile logistics optimizer'),
  ('VoxelMed',    '3D medical imaging diagnostic assistant for radiologists'),
  ('CipherDesk',  'Zero-knowledge collaborative document editor'),
  ('RetailRift',  'AI-powered inventory anomaly detection for SMB retailers'),
  ('ClipForge',   'Auto-generated short-form video summaries from long-form content'),
  ('SwarmHaul',   'Multi-robot warehouse coordination engine')
);


-- 3) Scores (one row per team x judge — unique constraint enforces this) -----
create table if not exists scores (
  id          uuid primary key default gen_random_uuid(),
  team_id     uuid not null references teams(id) on delete cascade,
  judge_slug  text not null references judges(slug),
  scores      jsonb not null,
  bonuses     jsonb not null,
  feedback    text,
  created_at  timestamptz default now(),
  updated_at  timestamptz default now(),
  unique (team_id, judge_slug)
);


-- 4) Event settings (single row) ---------------------------------------------
create table if not exists event_settings (
  id         int primary key default 1,
  locked     boolean default false,
  event_name text default 'EDGE Hack 2026',
  check (id = 1)
);

insert into event_settings (id, locked, event_name) values (1, false, 'EDGE Hack 2026')
on conflict (id) do nothing;


-- 5) Auto-update updated_at on score updates --------------------------------
create or replace function set_updated_at() returns trigger as $$
begin new.updated_at = now(); return new; end;
$$ language plpgsql;

drop trigger if exists scores_updated_at on scores;
create trigger scores_updated_at before update on scores
  for each row execute function set_updated_at();


-- 6) Credentials table + login RPC (simple username/password auth) ===========
-- Stores hashed passwords. The anon key cannot read this table because no RLS
-- policies are added. Login validation goes through the login() RPC, which runs
-- as SECURITY DEFINER and returns only success/role/judge_slug.

create table if not exists credentials (
  username      text primary key,
  password_hash text not null,
  role          text not null check (role in ('admin', 'judge')),
  judge_slug    text references judges(slug) on delete cascade,
  created_at    timestamptz default now()
);

alter table credentials enable row level security;
-- Intentionally no policies: credentials are invisible to the anon key.

-- Migrate the earlier Himant slug from himant-salesforce to himant.
delete from scores old_score
where old_score.judge_slug = 'himant-salesforce'
  and exists (
    select 1 from scores new_score
    where new_score.team_id = old_score.team_id
      and new_score.judge_slug = 'himant'
  );

update scores set judge_slug = 'himant'
where judge_slug = 'himant-salesforce';

update credentials set judge_slug = 'himant'
where judge_slug = 'himant-salesforce';

delete from judges where slug = 'himant-salesforce';

-- Requested credentials.
-- Admin:
--   username: neeljain
--   password: Beeps@123
-- Judges:
--   username: <judge-slug>
--   password: <judge-slug>@123
insert into credentials (username, password_hash, role, judge_slug) values
  ('neeljain',          extensions.crypt('Beeps@123',             extensions.gen_salt('bf')), 'admin', null),
  ('lin-yuan',          extensions.crypt('lin-yuan@123',          extensions.gen_salt('bf')), 'judge', 'lin-yuan'),
  ('kamal-mann',        extensions.crypt('kamal-mann@123',        extensions.gen_salt('bf')), 'judge', 'kamal-mann'),
  ('sasi-ingua',        extensions.crypt('sasi-ingua@123',        extensions.gen_salt('bf')), 'judge', 'sasi-ingua'),
  ('himant',            extensions.crypt('himant@123',            extensions.gen_salt('bf')), 'judge', 'himant'),
  ('manish-shah',       extensions.crypt('manish-shah@123',       extensions.gen_salt('bf')), 'judge', 'manish-shah')
on conflict (username) do update set
  password_hash = excluded.password_hash,
  role = excluded.role,
  judge_slug = excluded.judge_slug;

-- Remove old demo/legacy credentials from earlier schema drafts.
delete from credentials where username in ('admin', 'himant-salesforce');

-- The login function. Anon-callable, returns one row.
-- App calls: supabase.rpc('login', { p_username, p_password })
create or replace function login(p_username text, p_password text)
returns table(success boolean, role text, judge_slug text)
language plpgsql
security definer
set search_path = public
as $$
declare rec credentials%rowtype;
begin
  select * into rec from credentials where username = lower(p_username);
  if not found then
    return query select false, null::text, null::text;
    return;
  end if;

  if rec.password_hash = extensions.crypt(p_password, rec.password_hash) then
    return query select true, rec.role, rec.judge_slug;
  else
    return query select false, null::text, null::text;
  end if;
end $$;

revoke all on function login(text, text) from public;
grant execute on function login(text, text) to anon;


-- 7) Row Level Security on data tables --------------------------------------
-- The app authenticates client-side using the credentials table + login() RPC,
-- then uses the anon key to read/write data tables. The credentials table is the
-- page-access boundary. The data tables stay anon-permissive for this simple app.

alter table judges          enable row level security;
alter table teams           enable row level security;
alter table scores          enable row level security;
alter table event_settings  enable row level security;

-- Drop pre-existing policies (so this script can be re-run after edits)
do $$
declare r record;
begin
  for r in (
    select schemaname, tablename, policyname from pg_policies
    where schemaname = 'public'
      and tablename in ('judges','teams','scores','event_settings')
  ) loop
    execute format('drop policy if exists %I on %I.%I', r.policyname, r.schemaname, r.tablename);
  end loop;
end $$;

create policy "anon read judges"     on judges          for select using (true);
create policy "anon read teams"      on teams           for select using (true);
create policy "anon insert teams"    on teams           for insert with check (true);
create policy "anon update teams"    on teams           for update using (true);
create policy "anon delete teams"    on teams           for delete using (true);
create policy "anon read scores"     on scores          for select using (true);
create policy "anon insert scores"   on scores          for insert with check (true);
create policy "anon update scores"   on scores          for update using (true);
create policy "anon delete scores"   on scores          for delete using (true);
create policy "anon read settings"   on event_settings  for select using (true);
create policy "anon update settings" on event_settings  for update using (true);


-- 8) Realtime publication ----------------------------------------------------
do $$ begin alter publication supabase_realtime add table judges;         exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table teams;          exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table scores;         exception when duplicate_object then null; end $$;
do $$ begin alter publication supabase_realtime add table event_settings; exception when duplicate_object then null; end $$;


-- ============================================================================
-- Default logins:
--
--   Role   | Username          | Password              | Goes to
--   -------+-------------------+-----------------------+-------------------------------
--   admin  | neeljain          | Beeps@123             | /admin
--   judge  | lin-yuan          | lin-yuan@123          | /judge/lin-yuan
--   judge  | kamal-mann        | kamal-mann@123        | /judge/kamal-mann
--   judge  | sasi-ingua        | sasi-ingua@123        | /judge/sasi-ingua
--   judge  | himant            | himant@123            | /judge/himant
--   judge  | manish-shah       | manish-shah@123       | /judge/manish-shah
-- ============================================================================
